"""Function attribution for stripped Solana BPF ELFs.

Approach (no symbols available):
  1. decode .text manually (op/dst/src/imm) -> lddw targets and relative calls
  2. function starts = call-graph targets + exported syms
  3. attribute each function to a source module via the .rodata panic/path strings it
     references (the deployed ELF embeds "solana-program/src/instructions/<mod>.rs")
  4. attribute each function to an instruction discriminator via the entry dispatch chain
  5. per function: syscalls used, guard/error strings loaded, pubkey constants loaded
"""
import struct, json, re, sys
from collections import defaultdict
from elftools.elf.elffile import ELFFile

OP_LDDW = 0x18
OP_CALL = 0x85


def b58enc(b):
    D = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(b, "big"); o = ""
    while n:
        n, r = divmod(n, 58); o = D[r] + o
    return "1" * sum(1 for c in b if c == 0 if b[:b.index(c)] == b"") + o if False else ("1" * (len(b) - len(b.lstrip(b"\x00")) if isinstance(b, bytearray) else len(b) - len(bytes(b).lstrip(b"\x00")))) + o


def b58dec(s):
    D = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in s:
        n = n * 58 + D.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


KNOWN = {
    "11111111111111111111111111111111": "system_program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "spl_token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "token_2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "ata_program",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": "orca_whirlpool",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "mpl_token_metadata",
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": "mpl_metadata_legacy",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr": "memo_program",
    "SysvarC1ock11111111111111111111111111111111": "sysvar_clock",
    "Sysvar1nstructions1111111111111111111111111": "sysvar_instructions",
    "SysvarRent111111111111111111111111111111111": "sysvar_rent",
    "So11111111111111111111111111111111111111112": "wsol_mint",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "usdc_mint",
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP": "orca_amm",
    "2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ": "whirlpool_config",
    "BPFLoaderUpgradeab1e11111111111111111111111": "bpf_loader_upgradeable",
    "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uBXJqNViz": "spl_memo_legacy?",
}


class P:
    def __init__(self, path):
        self.path = path
        self.raw = open(path, "rb").read()
        self.e = ELFFile(open(path, "rb"))
        self.secs = {s.name: s for s in self.e.iter_sections()}
        t = self.secs[".text"]
        self.t_addr, self.t_off, self.t_size = t["sh_addr"], t["sh_offset"], t["sh_size"]
        r = self.secs[".rodata"]
        self.r_addr, self.r_off, self.r_size = r["sh_addr"], r["sh_offset"], r["sh_size"]
        self.ro = self.raw[self.r_off:self.r_off + self.r_size]
        d = self.secs.get(".data.rel.ro")
        self.d_addr = d["sh_addr"] if d is not None else 0
        self.d_size = d["sh_size"] if d is not None else 0
        self.d_off = d["sh_offset"] if d is not None else 0
        self.dr = self.raw[self.d_off:self.d_off + self.d_size] if d is not None else b""
        self._relocs()
        self._decode()
        self._funcs()
        self._strs()

    def _relocs(self):
        self.call_import = {}
        symsec = self.e.get_section_by_name(".dynsym")
        self.dynsyms = list(symsec.iter_symbols())
        rel = self.e.get_section_by_name(".rel.dyn")
        raw = self.raw[rel["sh_offset"]:rel["sh_offset"] + rel["sh_size"]]
        self.import_stubs = {}
        for i in range(0, len(raw), 16):
            off, info = struct.unpack_from("<QQ", raw, i)
            sym, rtype = info >> 32, info & 0xFFFFFFFF
            name = self.dynsyms[sym].name if sym < len(self.dynsyms) else "?"
            if rtype == 1:
                self.call_import[off] = name

    def _decode(self):
        code = self.code = self.raw[self.t_off:self.t_off + self.t_size]
        self.n = len(code) // 8
        self.op = [0] * self.n
        self.dst = [0] * self.n
        self.src = [0] * self.n
        self.imm = [0] * self.n
        self.imm64 = [0] * self.n
        for i in range(self.n):
            o, ds, sr, im = struct.unpack_from("<BBHI", code, i * 8)
            self.op[i], self.dst[i], self.src[i], self.imm[i] = o, ds, sr, im
            if o == OP_LDDW and i + 1 < self.n:
                hi = struct.unpack_from("<I", code, i * 8 + 12)[0]
                if (code[i * 8 + 8] & 0xFF) == 0:
                    self.imm64[i] = im | (hi << 32)
                else:
                    self.imm64[i] = im
            else:
                self.imm64[i] = im
        self.addr_of = lambda i: self.t_addr + i * 8
        self.i_of = lambda a: (a - self.t_addr) // 8

    def _funcs(self):
        starts = set()
        for i in range(self.n):
            if self.op[i] == OP_CALL and self.addr_of(i) not in self.call_import:
                im = self.imm[i]
                if im >= 0x80000000:
                    im -= 0x100000000
                tgt = self.addr_of(i) + 8 + im * 8
                if self.t_addr <= tgt < self.t_addr + self.t_size:
                    starts.add(tgt)
        for s in self.dynsyms:
            if s["st_value"] and s["st_info"]["type"] == "STT_FUNC":
                starts.add(s["st_value"])
        starts.add(self.e.header["e_entry"])
        self.fs = sorted(s for s in starts if self.t_addr <= s < self.t_addr + self.t_size)
        self.func_of = {}
        self.func_end = {}
        for k, s in enumerate(self.fs):
            hi = self.fs[k + 1] if k + 1 < len(fs := self.fs) else self.t_addr + self.t_size
            j = self.i_of(s)
            end = hi
            while j < self.n and self.addr_of(j) < hi:
                if self.op[j] == 0x95:      # exit
                    end = self.addr_of(j) + 8
                    break
                j += 1
            self.func_end[s] = end
            a = s
            while a < end:
                self.func_of[a] = s
                a += 8

    def _strs(self):
        self.strtab = {}
        i, n = 0, len(self.ro)
        while i < n:
            if 0x20 <= self.ro[i] < 0x7F:
                j = i
                while j < n and 0x20 <= self.ro[j] < 0x7F:
                    j += 1
                self.strtab[self.r_addr + i] = self.ro[i:j].decode("latin1")
                i = j
            else:
                i += 1

    # ---- string occurrence lookup (substring) -----------------------
    def find_sub(self, needle):
        b = needle.encode()
        out, pos = [], 0
        while True:
            k = self.ro.find(b, pos)
            if k < 0:
                return out
            out.append(self.r_addr + k)
            pos = k + 1

    def lddw_index(self):
        idx = defaultdict(list)
        for i in range(self.n):
            if self.op[i] == OP_LDDW:
                idx[self.imm64[i]].append(i)
        return idx

    def funcs_for_str(self, needle, idx=None):
        idx = idx or self.lddw_index()
        out = set()
        for va in self.find_sub(needle):
            for i in idx.get(va, []):
                f = self.func_of.get(self.addr_of(i))
                if f is not None:
                    out.add(f)
        return sorted(out)

    def funcs_for_subtree(self, needle, idx=None, depth=2):
        """funcs referencing the string + their transitive callers"""
        base = set(self.funcs_for_str(needle, idx))
        callers = defaultdict(set)
        for i in range(self.n):
            if self.op[i] == OP_CALL and self.addr_of(i) not in self.call_import:
                im = self.imm[i]
                if im >= 0x80000000:
                    im -= 0x100000000
                tgt = self.addr_of(i) + 8 + im * 8
                c = self.func_of.get(self.addr_of(i))
                if c is not None:
                    callers[tgt].add(c)
        cur = set(base)
        for _ in range(depth):
            nxt = set(cur)
            for f in list(cur):
                nxt |= callers.get(f, set())
            cur = nxt
        return sorted(cur)

    def info(self, f):
        end = self.func_end[f]
        j0, j1 = self.i_of(f), self.i_of(end)
        strs, calls, sc, arith, lddw_vals = [], [], defaultdict(list), defaultdict(int), set()
        for j in range(min(j0, self.n), min(j1, self.n)):
            a, op, im = self.addr_of(j), self.op[j], self.imm[j]
            if op == OP_CALL:
                if a in self.call_import:
                    sc[self.call_import[a]].append(hex(a))
                else:
                    r = im if im < 0x80000000 else im - 0x100000000
                    calls.append(hex(a + 8 + r * 8))
            elif op == OP_LDDW:
                v = self.imm64[j]
                lddw_vals.add(v)
                if v in self.strtab:
                    strs.append(self.strtab[v][:160])
            # arithmetic
            cls = (op & 0xE0) >> 5
            code = (op & 0xF0) >> 4
            if op & 0x07 == 0x05 and cls == 4:        # ALU64 imm  (op = 0x07|code<<4)
                if code == 0x3: arith["div64_imm"] += 1
                elif code == 0x9: arith["mod64_imm"] += 1
                elif code == 0xa: arith["mul64_imm"] += 1
                elif code == 0x2: arith["lsh64_imm"] += 1
            elif op & 0x07 == 0x07 and cls == 4:      # ALU64 reg
                if code == 0x3: arith["div64_reg"] += 1
                elif code == 0x9: arith["mod64_reg"] += 1
                elif code == 0xa: arith["mul64_reg"] += 1
        # pubkey constants
        pks = {}
        for b58, label in KNOWN.items():
            bb = b58dec(b58)
            for v in lddw_vals:
                if self.r_addr <= v < self.r_addr + self.r_size:
                    if self.ro[v - self.r_addr:v - self.r_addr + 32] == bb:
                        pks[label] = {"addr": hex(v), "b58": b58}
        return {"addr": hex(f), "end": hex(end), "size": end - f,
                "syscalls": dict(sc), "calls": sorted(set(calls)),
                "strings": sorted(set(s for s in strs if s)), "pubkeys": pks}

    def panic_modules(self):
        mods = {}
        for addr, s in self.strtab.items():
            for m in re.finditer(r"solana-program/src/[A-Za-z0-9_/\.]+\.rs|src/[A-Za-z0-9_/\.]+\.rs", s):
                mods.setdefault(m.group(0), []).append(hex(addr))
        return mods
