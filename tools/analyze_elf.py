"""Sink-first static analysis of a deployed Solana BPF ELF (no capstone op_str reliance).

Facts produced (machine readable, used by the Wavebreak / Busybox reviews):
  * instruction dispatch map  : discriminator byte -> handler function address
  * per-function syscall import attribution (sol_invoke_signed_c, sol_secp256k1_recover,
    sol_try_find_program_address, sol_get_processed_sibling_instruction, sol_memcmp_, ...)
  * per-function .rodata string references (handler names, error text, module paths)
  * .rodata 32-byte pubkey constants + which functions load them (program pinning)
  * arithmetic scan: div/mod by reg (checked vs. unwrap), unchecked add pattern hints
"""
import struct, json, sys, re
from collections import defaultdict
from elftools.elf.elffile import ELFFile

BS58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58enc(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = BS58[r] + out
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + out


def b58dec(s):
    n = 0
    for c in s:
        n = n * 58 + BS58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


KNOWN = {
    "11111111111111111111111111111111": "system_program",
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA": "spl_token",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb": "token_2022",
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL": "associated_token_program",
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc": "orca_whirlpool",
    "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P": "mpl_token_metadata",
    "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s": "mpl_metadata_legacy",
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr": "memo_program",
    "SysvarC1ock11111111111111111111111111111111": "sysvar_clock",
    "Sysvar1nstructions1111111111111111111111111": "sysvar_instructions",
    "SysvarRent111111111111111111111111111111111": "sysvar_rent",
    "KeccakSecp256k11111111111111111111111111111": "secp256k1_precompile",
    "So11111111111111111111111111111111111111112": "wsol_mint",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v": "usdc_mint",
    "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP": "orca_amm",
    "2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ": "whirlpool_config",
    "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF": "wavebreak_self",
    "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j": "busybox_self",
    "BPFLoaderUpgradeab11e1111111111111111111111": "bpf_loader_upgradeable",
    "BPFLoaderUpgradeab1e11111111111111111111111": "bpf_loader_upgradeable",
}

# BPF opcodes
OP_LDDW = 0x18
OP_CALL = 0x85
OP_EXIT = 0x95
OP_JEQ_IMM = 0x55
OP_JGT_IMM = 0x2d
OP_JGE_IMM = 0x35
OP_JNE_IMM = 0x95 ^ 0xC0  # placeholder
OP_JEQ_REG = 0x15
OP_JGT_REG = 0x25
OP_JGE_REG = 0x35
OP_ADD64_IMM = 0x07
OP_ADD64_REG = 0x0f
OP_SUB64_IMM = 0x17
OP_MUL64_IMM = 0xa7
OP_DIV64_IMM = 0x3c ^ 0  # handled below
OP_LDXDW = 0x79
OP_STXDW = 0x7b
OP_STDW = 0x7a
OP_MOV64_IMM = 0xb7
OP_ALU_DIV = 0x30
OP_ALU_MOD = 0x90


class Analyzer:
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
        d = self.secs.get(".data.rel.ro")
        if d is not None:
            self.d_addr, self.d_off, self.d_size = d["sh_addr"], d["sh_offset"], d["sh_size"]
            self.dr = self.raw[self.d_off:self.d_off + self.d_size]
        else:
            self.d_addr = self.d_off = self.d_size = 0
            self.dr = b""
        self._relocs()
        self._decode()
        self._funcs()
        self._strings()

    # ------------------------------------------------------------------
    def _relocs(self):
        symsec = self.e.get_section_by_name(".dynsym")
        self.dynsyms = list(symsec.iter_symbols())
        rel = self.e.get_section_by_name(".rel.dyn")
        raw = self.raw[rel["sh_offset"]:rel["sh_offset"] + rel["sh_size"]]
        self.call_import = {}      # text vaddr (call insn) -> import name
        self.data_relocs = []      # (storage vaddr, sym, addend)
        for i in range(0, len(raw), 16):
            off, info = struct.unpack_from("<QQ", raw, i)
            sym, rtype = info >> 32, info & 0xFFFFFFFF
            name = self.dynsyms[sym].name if sym < len(self.dynsyms) else "?"
            if rtype == 1:
                self.call_import[off] = name
            elif rtype == 2:
                addend = struct.unpack_from("<Q", self.raw, self._fileoff(off))[0] if self._fileoff(off) else 0
                self.data_relocs.append((off, name, addend))

    def _fileoff(self, vaddr):
        for s in self.e.iter_sections():
            if s["sh_addr"] and s["sh_addr"] <= vaddr < s["sh_addr"] + s["sh_size"]:
                return s["sh_offset"] + (vaddr - s["sh_addr"])
        return None

    def read_vaddr(self, vaddr, n=32):
        fo = self._fileoff(vaddr)
        return b"" if fo is None else self.raw[fo:fo + n]

    # ------------------------------------------------------------------
    def _decode(self):
        """linear decode of .text into a list of dicts (raw, so no capstone dependency)"""
        code = self.code
        base = self.t_addr
        self.n = len(code) // 8
        self.insn = []
        for i in range(self.n):
            off = i * 8
            w0 = struct.unpack_from("<BBHI", code, off)
            op, dst, src, imm = w0
            raw8 = code[off:off + 8]
            item = {"i": i, "addr": base + off, "op": op, "dst": dst, "src": src, "imm": imm, "raw": raw8}
            if op == OP_LDDW:
                if i + 1 < self.n:
                    hi = struct.unpack_from("<I", code, off + 12)[0]
                    item["imm64"] = imm | (hi << 32)
            self.insn.append(item)
        # disassembly strings via capstone if available
        try:
            from capstone import Cs, CS_ARCH_BPF, CS_MODE_BPF_EXTENDED, CS_MODE_LITTLE_ENDIAN
            md = Cs(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED | CS_MODE_LITTLE_ENDIAN)
            self.asm = {}
            for x in md.disasm(code, base):
                self.asm[x.address] = f"{x.mnemonic} {x.op_str}".strip()
        except Exception:
            self.asm = {}

    def _funcs(self):
        starts = set()
        for x in self.insn:
            if (x["op"] & 0xFF) == OP_CALL and x["addr"] not in self.call_import:
                tgt = x["addr"] + 8 + x["imm"] * 8
                if self.t_addr <= tgt < self.t_addr + self.t_size:
                    starts.add(tgt)
        for s in self.dynsyms:
            if s["st_value"] and s["st_info"]["type"] == "STT_FUNC":
                starts.add(s["st_value"])
        starts.add(self.e.header["e_entry"])
        # function bodies also begin right after exit? use call graph only
        self.func_starts = sorted(s for s in starts if self.t_addr <= s < self.t_addr + self.t_size)
        fs = self.func_starts
        self.func_end = {}
        for i, s in enumerate(fs):
            # find first 'exit' at depth 0 (r0-based heuristic: first exit after start)
            end = fs[i + 1] if i + 1 < len(fs) else self.t_addr + self.t_size
            j = (s - self.t_addr) // 8
            depth = 0
            while j < self.n and self.t_addr + j * 8 < end:
                op = self.insn[j]["op"]
                if op == OP_EXIT and depth == 0:
                    end = self.t_addr + j * 8 + 8
                    break
                j += 1
            self.func_end[s] = end
        self._index = {a: (a, j // 8) for j, a in enumerate(fs)}
        # map addr -> func (linear sweep)
        self.func_of = {}
        for fi, s in enumerate(fs):
            e = self.func_end[s]
            a = s
            while a < e:
                self.func_of[a] = s
                a += 8

    def _strings(self):
        self.strtab = {}
        i, n = 0, len(self.ro)
        while i < n:
            c = self.ro[i]
            if 0x20 <= c < 0x7F:
                j = i
                while j < n and 0x20 <= self.ro[j] < 0x7F:
                    j += 1
                self.strtab[self.r_addr + i] = self.ro[i:j].decode("ascii", "replace")
                i = j
            else:
                i += 1

    # ------------------------------------------------------------------
    def func_info(self, f):
        end = self.func_end[f]
        out = {"start": f, "end": end, "size": end - f, "syscalls": defaultdict(list),
               "rodata": [], "calls": [], "arith": defaultdict(int)}
        j0 = (f - self.t_addr) // 8
        j1 = max(j0, (end - self.t_addr) // 8)
        for j in range(j0, j1):
            x = self.insn[j]
            a, op = x["addr"], x["op"]
            if op == OP_CALL:
                if a in self.call_import:
                    out["syscalls"][self.call_import[a]].append(hex(a))
                else:
                    tgt = a + 8 + x["imm"] * 8
                    out["calls"].append(hex(tgt))
            elif op == OP_LDDW:
                v = x.get("imm64", 0)
                if self.r_addr <= v < self.r_addr + self.r_size:
                    s = self.strtab.get(v)
                    out["rodata"].append((hex(v), (s[:100] if s else "")))
                elif self.d_addr <= v < self.d_addr + self.d_size:
                    out["rodata"].append((hex(v), "<data.rel.ro ptr>"))
            elif op in (0x34, 0x3c, 0x94, 0x9c):     # div/mod imm (32/64)
                out["arith"]["div_mod_imm"] += 1
            elif op in (0x30, 0x38):                   # div reg (32/64)
                out["arith"]["div_reg"] += 1
            elif op in (0x90, 0x98):                   # mod reg
                out["arith"]["mod_reg"] += 1
            elif op in (0xa4, 0xac):                    # mul32/64 imm
                out["arith"]["mul_imm"] += 1
            elif op in (0x24, 0x2c):                    # lsh imm
                out["arith"]["lsh_imm"] += 1
        out["syscalls"] = {k: v for k, v in out["syscalls"].items()}
        # dedup rodata refs keeping first
        seen, ro = set(), []
        for a, s in out["rodata"]:
            if a in seen:
                continue
            seen.add(a)
            ro.append({"addr": a, "str": s})
        out["rodata"] = ro
        out["calls"] = sorted(set(out["calls"]))
        return out

    def all_funcs(self):
        return {hex(f): self.func_info(f) for f in self.func_starts}

    # ---- dispatcher discovery: entry -> compare chain on data[0] ----
    def dispatch_map(self, max_disc=70):
        """
        Walk the entry function: find ldxw/ldxb of the instruction data, followed by
        jeq/jne immediates -> (discriminator -> branch target -> lddw of handler fn ptr or direct call).
        Returns raw evidence: list of {disc, branch_addr} plus each branch's first call target.
        """
        ent = self.e.header["e_entry"]
        end = self.func_end[ent]
        j0 = (ent - self.t_addr) // 8
        j1 = (end - self.t_addr) // 8
        hits = []
        for j in range(j0, j1):
            x = self.insn[j]
            op, imm = x["op"], x["imm"]
            if op in (0x55, 0x95, 0x2d, 0x35) and 0 <= imm <= max_disc:   # jeq/jne/jgt/jge imm
                tgt = x["addr"] + 8 + (imm if op in (0x55, 0x95) else 0) * 8
                hits.append({"addr": hex(x["addr"]), "op": hex(op), "imm": imm, "ins": self.asm.get(x["addr"], "")})
        return hits

    def pubkey_constants(self):
        res = {}
        for b58, label in KNOWN.items():
            try:
                b = b58dec(b58)
            except Exception:
                continue
            if len(b) != 32:
                continue
            pos, hits = 0, []
            while True:
                i = self.ro.find(b, pos)
                if i < 0:
                    break
                hits.append(self.r_addr + i)
                pos = i + 1
            # also search whole file (data.rel.ro etc.)
            if hits:
                res.setdefault(label, {"b58": b58, "addrs": [hex(h) for h in hits]})
        return res

    def funcs_referencing(self, addr_hex):
        addr = int(addr_hex, 16)
        return sorted({hex(self.func_of[a]) for a, x in [(i["addr"], i) for i in self.insn]
                       if x["op"] == OP_LDDW and x.get("imm64") == addr and a in self.func_of})


def report(path, out_path):
    a = Analyzer(path)
    data = {
        "elf": path,
        "text": {"addr": hex(a.t_addr), "size": hex(a.t_size)},
        "n_funcs": len(a.func_starts),
        "imports": sorted(set(a.call_import.values())),
        "pubkey_constants": a.pubkey_constants(),
        "funcs": a.all_funcs(),
    }
    json.dump(data, open(out_path, "w"), indent=1)
    return a, data


if __name__ == "__main__":
    a, d = report(sys.argv[1], sys.argv[2])
    print("funcs", d["n_funcs"], "imports", d["imports"])
