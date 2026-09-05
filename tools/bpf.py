"""Minimal Solana BPF analysis harness over the *deployed* ELF (capstone-based).

Not a full decompiler: it provides (a) linear disassembly of .text, (b) function
boundary inference from call targets + prologues, (c) rodata string/constant
extraction with xrefs from `lddw` immediates, (d) CPI/import resolution through
.lesolver/.dynsym relocations, so that handler-level checks (PDA seeds, owner
pins, token-program pins, unchecked math, invoke_signed seeds) can be located
by address and read by hand.
"""
import struct, subprocess, sys, os
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_BPF, CS_MODE_BPF_EXTENDED, CS_MODE_LITTLE_ENDIAN

try:
    import base58
    def b58(b): return base58.b58encode(bytes(b)).decode()
except Exception:
    def b58(b): return bytes(b).hex()


class Elf:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        self._fh = open(path, "rb")
        self.e = ELFFile(self._fh)
        self.sections = {s.name: s for s in self.e.iter_sections()}
        self.text_addr = self.sections[".text"]['sh_addr']
        self.text_off = self.sections[".text"]['sh_offset']
        self.text_size = self.sections[".text"]['sh_size']
        self.text = self.raw[self.text_off:self.text_off + self.text_size]
        r = self.sections[".rodata"]
        self.ro_addr, self.ro_off, self.ro_size = r['sh_addr'], r['sh_offset'], r['sh_size']
        self.ro = self.raw[self.ro_off:self.ro_off + self.ro_size]
        self.entry = self.e.header['e_entry']
        self._disasm()
        self._imports()
        self._funcs()
        self._lddw_xrefs()

    # ---- disassembly -------------------------------------------------
    def _disasm(self):
        md = Cs(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED | CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        self.insns = {}          # addr -> (mnemonic, op_str, raw)
        self.order = []          # addrs in file order
        for ins in md.disasm(self.text, self.text_addr):
            self.insns[ins.address] = (ins.mnemonic, ins.op_str, bytes(ins.bytes))
            self.order.append(ins.address)
        self.md = md

    # ---- imported sol_* syscalls via .dynsym -------------------------
    def _imports(self):
        self.imports = {}   # addr -> name
        sym = self.e.get_section_by_name(".dynsym")
        strtab = self.e.get_section_by_name(".dynstr")
        if sym is None:
            return
        for s in sym.iter_symbols():
            if s['st_info']['type'] == 'STT_FUNC' and s['st_value']:
                self.imports[s['st_value']] = s.name
        # also map relative-reloc targets that look like import thunks
        self.import_by_name = {v: k for k, v in self.imports.items()}

    # ---- function inference -----------------------------------------
    def _funcs(self):
        calls = defaultdict(list)
        for a, (m, ops, _) in self.insns.items():
            if m == "call":
                try:
                    tgt = a + 8 + int(ops, 0) * 8
                except Exception:
                    continue
                calls[tgt].append(a)
        self.callers = calls
        starts = sorted(set(calls.keys()) | {self.entry} | set(self.imports.keys()))
        self.funcs = {}
        for s in starts:
            if s not in self.insns:
                continue
            # body = from start until next start or exit
            nxt = min([x for x in starts if x > s], default=self.text_addr + self.text_size)
            self.funcs[s] = (nxt, sorted(calls.get(s, [])))
        # tail-call chains: instruction 'exit' inside region marks end

    def region(self, start, end=None):
        if end is None:
            end = self.funcs.get(start, (self.text_addr + self.text_size, []))[0]
        out = []
        a = start
        while a < end:
            if a in self.insns:
                m, ops, raw = self.insns[a]
                out.append((a, m, ops, raw))
            a += 8
        return out

    def dis_text(self, start, end=None, note=None):
        lines = []
        for a, m, ops, raw in self.region(start, end):
            ann = ""
            if m == "call":
                try:
                    tgt = a + 8 + int(ops, 0) * 8
                    ann = f"   ; -> {tgt:#x}"
                    if tgt in self.imports:
                        ann += f" {self.imports[tgt]}"
                    if tgt in self.funcs:
                        ann += " (local)"
                except Exception:
                    pass
            # lddw -> rodata pointer
            if m == "lddw":
                ann += self._maybe_rodata(ops)
            lines.append(f"  {a:#08x}: {m:8s} {ops}{ann}")
        if note:
            lines.insert(0, f"  ;; {note}")
        return "\n".join(lines)

    # ---- lddw -> .rodata constants -----------------------------------
    def _lddw_xrefs(self):
        # collect (dst_reg, imm) pairs: 'lddw rX, addr'
        self.lddw = []
        for a, (m, ops, _) in self.insns.items():
            if m == "lddw":
                self.lddw.append((a, ops))
        self.lddw_by_addr = {a: ops for a, (ops) in [(x[0], x[1:]) for x in self.lddw]}

    def _maybe_rodata(self, ops):
        try:
            reg, imm = ops.split(",")
            imm = int(imm.strip().replace("#", ""), 0) & 0xFFFFFFFFFFFFFFFF
            if imm < 2 if False else False:
                return ""
            if self.ro_addr <= imm < self.ro_addr + self.ro_size:
                off = imm - self.ro_addr
                s = cstr(self.ro, off)
                b = self.ro[off:off + 32]
                extra = ""
                if s:
                    extra = f" rodata={s[:80]!r}"
                else:
                    extra = f" rodata[{imm:#x}]"
                if self._looks_like_pubkey(b):
                    extra += f" pubkey={b58(b)}"
                return extra
        except Exception:
            pass
        return ""

    def _looks_like_pubkey(self, b):
        return len(b) == 32 and any(x for x in b) and (b[0] != 0 or True)

    # ---- string search -----------------------------------------------
    def find_str(self, needle, min_len=3):
        """returns list of (rodata_addr, s)"""
        out = []
        needle = needle.encode() if isinstance(needle, str) else needle
        pos = 0
        while True:
            i = self.ro.find(needle, pos)
            if i < 0:
                break
            out.append((self.ro_addr + i, cstr(self.ro, max(0, i - 0))))
            pos = i + 1
        return out

    def strings(self):
        out = []
        i = 0
        n = len(self.ro)
        while i < n:
            if 0x20 <= self.ro[i] < 0x7f:
                j = i
                while j < n and 0x20 <= self.ro[j] < 0x7f:
                    j += 1
                if j - i >= 4:
                    out.append((self.ro_addr + i, self.ro[i:j].decode()))
                i = j
            else:
                i += 1
        return out

    def xref_to(self, target_addr, within=None):
        """instruction addresses whose lddw imm == target_addr (or st_ helper)"""
        hits = []
        for a, ops in self.lddw:
            try:
                imm = int(ops.split(",")[1].strip().replace("#", ""), 0) & 0xFFFFFFFFFFFFFFFF
            except Exception:
                continue
            if imm == target_addr:
                if within is None or within[0] <= a < within[1]:
                    hits.append(a)
        return hits

    def find_pubkey(self, pk_bytes):
        return self.ro.find(pk_bytes)


def cstr(buf, off, maxlen=200):
    out = bytearray()
    i = off
    while i < len(buf) and len(out) < maxlen:
        c = buf[i]
        if c == 0:
            break
        if 0x20 <= c < 0x7f:
            out.append(c)
        else:
            return ""
        i += 1
    return out.decode() if len(out) >= 3 else ""


PUBKEY_LEN = 32
