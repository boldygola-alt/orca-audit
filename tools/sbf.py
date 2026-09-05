"""Relocation-aware analysis of a deployed Solana BPF (SOL_SBF v3) ELF.

SBF reloc types:  R_BPF_NONE=0  R_BPF_64_64=1  R_BPF_64_32=2  R_BPF_64_RELATIVE=8  R_BPF_64_32(call)=10
  * type 10 -> imm32 of a `call` instruction, patched to the import stub for dynsym[sym]
  * type 8  -> 64-bit data pointer in .data.rel.ro/.data, value = load-base + addend
This resolves (a) every syscall call-site, (b) the jump/descriptor tables in .data.rel.ro.
"""
import struct, json, re, sys
from collections import defaultdict
from elftools.elf.elffile import ELFFile

OP_LDDW, OP_CALL, OP_EXIT = 0x18, 0x85, 0x95
TYPE_CALL, TYPE_REL = 10, 8


class Sbf:
    def __init__(self, path):
        self.path = path
        self.raw = open(path, "rb").read()
        self.e = ELFFile(open(path, "rb"))
        self.secs = {s.name: s for s in self.e.iter_sections()}
        t = self.secs[".text"]
        self.t_addr, self.t_off, self.t_size = t["sh_addr"], t["sh_offset"], t["sh_size"]
        self.code = self.raw[self.t_off:self.t_off + self.t_size]
        r = self.secs[".rodata"]
        self.r_addr, self.r_off, self.r_size = r["sh_addr"], r["sh_offset"], r["sh_size"]
        self.ro = self.raw[self.r_off:self.r_off + self.r_size]
        for nm in (".data.rel.ro", ".data", ".rodata"):
            s = self.secs.get(nm)
            if s is not None:
                setattr(self, nm.replace(".", "") + "_addr", s["sh_addr"])
                setattr(self, nm.replace(".", "") + "_off", s["sh_offset"])
                setattr(self, nm.replace(".", "") + "_size", s["sh_size"])
        self.n = len(self.code) // 8
        self.op = [0]*self.n; self.dst=[0]*self.n; self.src=[0]*self.n; self.imm=[0]*self.n; self.imm64=[0]*self.n
        for i in range(self.n):
            o, ds, sr, im = struct.unpack_from("<BBHI", self.code, i*8)
            self.op[i]=o; self.dst[i]=ds; self.src[i]=sr; self.imm[i]=im
            if o == OP_LDDW and i+1 < self.n and (self.code[i*8+8] & 0xFF) == 0:
                self.imm64[i] = im | (struct.unpack_from("<I", self.code, i*8+12)[0] << 32)
            else:
                self.imm64[i] = im
        self.addr_of = lambda i: self.t_addr + i*8
        self.i_of = lambda a: (a - self.t_addr)//8
        self._relocs()
        self._funcs()
        self._strs()

    # ---- relocations ----
    def _relocs(self):
        self.dynsyms = list(self.e.get_section_by_name(".dynsym").iter_symbols())
        rel = self.e.get_section_by_name(".rel.dyn")
        raw = self.raw[rel["sh_offset"]:rel["sh_offset"]+rel["sh_size"]]
        self.call_import = {}     # text vaddr of the call insn -> import name
        self.rel_relative = {}    # storage vaddr -> target vaddr (already based)
        for i in range(0, len(raw), 16):
            off, info = struct.unpack_from("<QQ", raw, i)
            sym, rtype = info >> 32, info & 0xFFFFFFFF
            name = self.dynsyms[sym].name if sym < len(self.dynsyms) else "?"
            if rtype == TYPE_CALL:
                self.call_import[off] = name
            elif rtype == TYPE_REL:
                fo = self.fileoff(off)
                if fo is not None:
                    self.rel_relative[off] = struct.unpack_from("<Q", self.raw, fo)[0]
        # imports sorted by stub order: the loader lays out stubs in .text order of first reloc
        self.import_names = sorted(set(self.call_import.values()))

    def sections_list(self):
        return {s.name: (hex(s["sh_addr"]), hex(s["sh_offset"]), hex(s["sh_size"]), s["sh_flags"])
                for s in self.e.iter_sections() if s["sh_size"]}

    def fileoff(self, vaddr):
        for s in self.e.iter_sections():
            if s["sh_addr"] and s["sh_addr"] <= vaddr < s["sh_addr"]+s["sh_size"]:
                return s["sh_offset"] + (vaddr - s["sh_addr"])
        return None

    def read(self, vaddr, n):
        fo = self.fileoff(vaddr)
        return b"" if fo is None else self.raw[fo:fo+n]

    # ---- functions ----
    def _funcs(self):
        starts = set()
        for i in range(self.n):
            if self.op[i] == OP_CALL and self.addr_of(i) not in self.call_import:
                im = self.imm[i] - (1<<32) if self.imm[i] >= 0x80000000 else self.imm[i]
                tgt = self.addr_of(i) + 8 + im*8
                if self.t_addr <= tgt < self.t_addr + self.t_size:
                    starts.add(tgt)
        for s in self.dynsyms:
            if s["st_value"] and s["st_info"]["type"] == "STT_FUNC":
                starts.add(s["st_value"])
        starts.add(self.e.header["e_entry"])
        self.fs = sorted(x for x in starts if self.t_addr <= x < self.t_addr + self.t_size)
        self.func_end = {}; self.func_of = {}
        for k, s in enumerate(self.fs):
            hi = self.fs[k+1] if k+1 < len(self.fs) else self.t_addr + self.t_size
            j = self.i_of(s); end = hi
            while j < self.n and self.addr_of(j) < hi:
                if self.op[j] == OP_EXIT:
                    end = self.addr_of(j)+8; break
                j += 1
            self.func_end[s] = end
            a = s
            while a < end:
                self.func_of[a] = s; a += 8

    def _strs(self):
        self.strtab = {}
        i, n = 0, len(self.ro)
        while i < n:
            if 0x20 <= self.ro[i] < 0x7F:
                j = i
                while j < n and 0x20 <= self.ro[j] < 0x7F:
                    j += 1
                self.strtab[self.r_addr+i] = self.ro[i:j].decode("latin1")
                i = j
            else:
                i += 1

    # ---- per-function facts ----
    def info(self, f, max_str=14):
        j0, j1 = self.i_of(f), self.i_of(self.func_end[f])
        sc = defaultdict(list); calls = set(); strs = []; vals = set(); arith = defaultdict(int)
        for j in range(min(j0, self.n), min(j1, self.n)):
            a, op, im = self.addr_of(j), self.op[j], self.imm[j]
            if op == OP_CALL:
                if a in self.call_import:
                    sc[self.call_import[a]].append(hex(a))
                else:
                    r = im - (1<<32) if im >= 0x80000000 else im
                    calls.add(hex(a+8+r*8))
            elif op == OP_LDDW:
                v = self.imm64[j]; vals.add(v)
                if v in self.strtab:
                    strs.append(self.strtab[v])
            code = (op & 0xF0) >> 4; cls = (op & 0xE0) >> 5
            if cls == 4:
                if code == 0x3: arith["div"] += 1
                elif code == 0x9: arith["mod"] += 1
                elif code == 0xa: arith["mul"] += 1
                elif code == 0x6: arith["sub"] += 1
                elif code == 0x0: arith["add"] += 1
        out = {"addr": hex(f), "end": hex(self.func_end[f]), "size": self.func_end[f]-f,
               "syscalls": {k: v for k, v in sc.items()}, "calls": sorted(calls),
               "arith": dict(arith), "rodata": []}
        seen = set()
        for s in strs:
            s2 = s[:120]
            if s2 in seen or not s2:
                continue
            seen.add(s2); out["rodata"].append(s2)
        out["strings"] = out.pop("rodata")[:max_str]
        out["n_strings"] = len(seen)
        return out

    def funcs_touching_syscall(self, name):
        out = defaultdict(list)
        for a, n in self.call_import.items():
            if n == name:
                f = self.func_of.get(a)
                if f is not None:
                    out[f].append(hex(a))
        return {hex(k): v for k, v in sorted(out.items())}

    def funcs_for_str(self, needle):
        b = needle.encode(); idx = defaultdict(list)
        for i in range(self.n):
            if self.op[i] == OP_LDDW:
                idx[self.imm64[i]].append(i)
        out, pos = set(), 0
        while True:
            k = self.ro.find(b, pos)
            if k < 0:
                break
            for i in idx.get(self.r_addr+k, []):
                f = self.func_of.get(self.addr_of(i))
                if f is not None:
                    out.add(f)
            pos = k+1
        return sorted(hex(x) for x in out)

    # ---- .data.rel.ro pointer graph (dispatch/jump tables) ----
    def relro_pointers(self):
        base = getattr(self, "datarelro_addr", 0)
        if not base:
            return []
        out = []
        for off, tgt in sorted(self.rel_relative.items()):
            if base <= off < base + getattr(self, "datarelro_size", 0):
                out.append((off, tgt))
        return out

    def text_refs_in_relro(self):
        """(relro_addr, text_target) pairs — a jump table"""
        res = []
        for off, tgt in self.relro_pointers():
            if self.t_addr <= tgt < self.t_addr + self.t_size:
                res.append((hex(off), hex(tgt)))
        return res

    def dis(self, start, end, note=""):
        lines = [f"  ;; {note} {hex(start)}-{hex(end)}"]
        try:
            from capstone import Cs, CS_ARCH_BPF, CS_MODE_BPF_EXTENDED, CS_MODE_LITTLE_ENDIAN
            md = Cs(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED | CS_MODE_LITTLE_ENDIAN)
            for x in md.disasm(self.code[self.i_of(start)*8:self.i_of(end)*8], start):
                s = f"  {x.address:#08x}: {x.mnemonic} {x.op_str}".rstrip()
                ia = self.i_of(x.address)
                if x.address in self.call_import:
                    s += f"   ; IMPORT {self.call_import[x.address]}"
                elif self.op[ia] == OP_CALL:
                    im = self.imm[ia]
                    r = im - (1<<32) if im >= 0x80000000 else im
                    s += f"   ; -> {x.address+8+r*8:#x}"
                elif self.op[ia] == OP_LDDW:
                    v = self.imm64[ia]
                    if v in self.strtab:
                        s += f"   ; str {self.strtab[v][:56]!r}"
                    else:
                        s += f"   ; val {v:#x}"
                lines.append(s)
        except Exception as e:
            lines.append(f"   (capstone: {e})")
        return "\n".join(lines)
