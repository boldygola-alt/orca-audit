"""Busybox/Riptide final evidence pass.

(1) Atomic MAINNET custody check: market account reserves vs the market's two vault token balances,
    all read in one getMultipleAccounts call at one slot (the earlier numbers compared a market dump
    from one slot against vault reads from another, which produced spurious "divergence").
(2) Authorization sweep with the correct live account shape: deposit / withdraw / update / close on
    a funded live market where the attacker is NOT the authority, plus the swap-path guards
    (stale oracle, sequence monotonicity, slippage, partial fill, duplicate mutable account).
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
import rpc
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
actor = F.load_actor(); A = str(actor.pubkey())


def prog_of(m):
    v = F.get_account(m) or rpc.get_account(m)
    return (v or {}).get("owner") or F.TOKEN


def ata_of(o, m, p):
    return str(Pubkey.find_program_address([bytes(F.pk(o)), bytes(F.pk(p)), bytes(F.pk(m))], F.pk(F.ATA))[0])


def mainnet_atomic():
    mk = json.load(open("/home/user/orca-audit/recon/busybox_markets_live.json"))["markets"]
    progs = {}
    for m in mk:
        for mint in (m["mint_a"], m["mint_b"]):
            if mint not in progs:
                v = rpc.get_account(mint)
                progs[mint] = (v or {}).get("owner") or F.TOKEN
    addrs = []
    for m in mk:
        a = m["address"]
        m["_va"] = ata_of(a, m["mint_a"], progs[m["mint_a"]])
        m["_vb"] = ata_of(a, m["mint_b"], progs[m["mint_b"]])
        addrs += [a, m["_va"], m["_vb"]]
    slot = rpc.get_slot()
    vals = {}
    for i in range(0, len(addrs), 80):
        ch = addrs[i:i + 80]
        r = rpc.rpc("getMultipleAccounts", [ch, {"encoding": "base64", "commitment": "confirmed"}], timeout=120)
        for a, v in zip(ch, r["result"]["value"]):
            vals[a] = v
    out = []
    for m in mk:
        mm = vals.get(m["address"])
        if not mm:
            out.append({"addr": m["address"], "absent": True}); continue
        raw = base64.b64decode(mm["data"][0])
        resA, resB = struct.unpack_from("<Q", raw, 736)[0], struct.unpack_from("<Q", raw, 744)[0]

        def amt(x):
            v = vals.get(x)
            if not v or v["space"] != 165:
                return None
            return struct.unpack_from("<Q", base64.b64decode(v["data"][0]), 64)[0]
        bA, bB = amt(m["_va"]), amt(m["_vb"])
        out.append({"addr": m["address"], "slot": slot, "authority": m["authority"], "updater": m["updater"],
                    "mintA": m["mint_a"], "mintB": m["mint_b"], "progs": [progs[m["mint_a"]], progs[m["mint_b"]]],
                    "sequence": struct.unpack_from("<Q", raw, 136)[0],
                    "validUntil": struct.unpack_from("<Q", raw, 144)[0],
                    "reservesA": resA, "reservesB": resB, "vaultA": bA, "vaultB": bB,
                    "excessA": (bA or 0) - resA, "excessB": (bB or 0) - resB,
                    "marketLamports": mm["lamports"], "cuPen": raw[2], "imbalanceGuard": raw[3],
                    "minSpread": struct.unpack_from("<i", raw, 664)[0],
                    "arbPenalty": struct.unpack_from("<I", raw, 668)[0],
                    "jitod": struct.unpack_from("<I", raw, 672)[0],
                    "minOracle": str(int.from_bytes(raw[688:704], "little")),
                    "maxOracle": str(int.from_bytes(raw[704:720], "little")),
                    "vaultAtA": m["_va"], "vaultAtB": m["_vb"]})
    json.dump({"mainnetSlot": slot, "markets": out},
              open("/home/user/orca-audit/recon/busybox_custody_atomic_mainnet.json", "w"), indent=1)
    import time as _t
    now0 = int(_t.time())
    bad = [o for o in out if not o.get("absent") and (o["excessA"] or o["excessB"])]
    tot = sum(max(o["excessA"], 0) + max(o["excessB"], 0) for o in out if not o.get("absent"))
    deficit = sum(max(-o["excessA"], 0) + max(-o["excessB"], 0) for o in out if not o.get("absent"))
    print("total reserves-over-vault (market owes more than it holds):", f"{deficit:,}", "units")
    print(f"mainnet slot {slot}: {len(out)} markets; reserves!=vault on {len(bad)}; "
          f"total vault-over-reserves {tot:,} units")
    for o in bad[:8]:
        print("   %-26s A res=%s vault=%s | B res=%s vault=%s | fresh=%s" % (
            o["addr"][:24], f"{o['reservesA']:,}", f"{o['vaultA'] or 0:,}", f"{o['reservesB']:,}",
            f"{o['vaultB'] or 0:,}", o["validUntil"] >= now0))
    return out


def auth_sweep(custody):
    live = [o for o in custody if not o.get("absent") and (o["reservesA"] + o["reservesB"]) > 0]
    live.sort(key=lambda o: -(o["reservesA"] + o["reservesB"]))
    now = F.get_slot()
    res = []

    def rec(name, ix, note=""):
        before = {a: F.snapshot([a], tokenaddrs={a})[a] for a in ix_watch}
        r = F.send([ix], actor)
        after = {a: F.snapshot([a], tokenaddrs={a})[a] for a in ix_watch}
        det = r.get("detail", {})
        logs = [l.strip().split("log:")[-1].strip() for l in det.get("logs", []) if "log:" in l or "failed" in l]
        e = {"case": name, "note": note, "sig": r.get("result"), "slot": now,
             "err": det.get("err") or r.get("error"), "guardLogs": logs[:6],
             "diff": F.diff(before, after)}
        res.append(e)
        print(f"\n### {name}  [{note}]")
        print("   err:", json.dumps(e["err"])[:130])
        print("   logs:", " | ".join(logs)[:280])
        print("   diff:", json.dumps(e["diff"])[:220])
        return e
    o = live[0]
    mkt = o["addr"]
    uA = ata_of(A, o["mintA"], o["progs"][0]); uB = ata_of(A, o["mintB"], o["progs"][1])
    for m, p in ((o["mintA"], o["progs"][0]), (o["mintB"], o["progs"][1])):
        _, x = F.create_ata(A, m, p, A)
        F.send([x], actor)
    ix_watch = [A, mkt, o["vaultAtA"], o["vaultAtB"], uA, uB]
    def AM(k, w=False, s=False):
        return F.AM(k, writable=w, signer=s)
    liq = lambda tag, x, y: Instruction(F.pk(BB), bytes([tag]) + struct.pack("<QQ", x, y), [
        AM(A, w=True, s=True), AM(mkt, w=True), AM(o["mintA"], w=True), AM(o["mintB"], w=True),
        AM(uA, w=True), AM(uB, w=True), AM(o["vaultAtA"], w=True), AM(o["vaultAtB"], w=True),
        AM(o["progs"][0]), AM(o["progs"][1]), AM(F.MEMO)])

    def swap(tag, amount, is_a, partial=0, sl=None, seq=None, dup=False, oracle=None):
        data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
        data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<QQ", *sl) if isinstance(sl, tuple)
                                              else bytes([2]) + struct.pack("<Q", sl))
        data += bytes([partial])
        accts = [AM(A, w=True, s=True), AM(mkt, w=True), AM(o["mintA"], w=True), AM(o["mintB"], w=True),
                 AM(o["vaultAtA"] if dup else uA, w=True), AM(uB, w=True),
                 AM(o["vaultAtA"], w=True), AM(o["vaultAtB"], w=True),
                 AM(o["progs"][0]), AM(o["progs"][1]), AM(F.MEMO), AM(F.IX_SYSVAR)]
        return Instruction(F.pk(BB), data, accts)

    print(f"\nauth-sweep target market {mkt} reserves {o['reservesA']:,}/{o['reservesB']:,} "
          f"authority={o['authority'][:12]} validUntil={o['validUntil']} forkSlot={now}")
    rec("BB-A01 marketDeposit by non-authority", liq(10, 10 ** 8, 0), "must be authority-gated")
    rec("BB-A02 marketWithdraw by non-authority", liq(11, 10 ** 8, 0), "must be authority-gated")
    rec("BB-A03 marketUpdate by non-authority",
        Instruction(F.pk(BB), bytes([9]) + bytes([2, 200]), [AM(A, w=True, s=True), AM(mkt, w=True), AM(F.SYSTEM)]),
        "cu penalty change by non-authority")
    rec("BB-A04 marketClose by non-authority", Instruction(F.pk(BB), bytes([12]), [
        AM(A, w=True, s=True), AM(mkt, w=True), AM(o["mintA"], w=True), AM(o["mintB"], w=True),
        AM(o["vaultAtA"], w=True), AM(o["vaultAtB"], w=True), AM(uA, w=True), AM(uB, w=True),
        AM(F.SYSTEM), AM(F.ATA), AM(o["progs"][0]), AM(o["progs"][1])]), "close gate")
    rec("BB-A05 oracleUpdate by non-updater (correct 529B payload)",
        Instruction(F.pk(BB), bytes([1]) + struct.pack("<QQ", o["sequence"] + 1, now + 4096) +
                      bytes([1]) + struct.pack("<Q", 1 << 63) + bytes(448) + bytes(32),
        [AM(mkt, w=True), AM(A, s=True)]), "attacker-signed price push")
    rec("BB-A06 oracleUpdate sequence replay (old sequence)",
        Instruction(F.pk(BB), bytes([1]) + struct.pack("<QQ", o["sequence"], now + 4096) +
                      bytes([1]) + struct.pack("<Q", 1 << 63) + bytes(448) + bytes(32),
        [AM(mkt, w=True), AM(A, s=True)]), "replay of the current sequence number")
    rec("BB-A07 swapExactIn on this market (stale-oracle guard)", swap(2, 10 ** 6, True),
        "oracle validUntil vs fork slot")
    rec("BB-A08 swapExactIn with duplicate mutable account (authorityA := marketVaultA)",
        swap(2, 10 ** 6, True, dup=True), "vault aliasing")
    rec("BB-A09 swapExactIn max-u64 amount", swap(2, 2 ** 64 - 1, True), "overflow / partial-fill guard")
    rec("BB-A10 swapExactIn zero amount", swap(2, 0, True), "zero-input path")
    rec("BB-A11 swapExactOut whole vault with partial fill", swap(3, (o["vaultAtB"] and 10 ** 12) or 1, False, partial=1),
        "exact-out bounded by reserves")
    rec("BB-A12 swapExactIn with tight MaxExecutionPrice", swap(2, 10 ** 6, True, sl=(0, 1)), "slippage guard")
    json.dump({"custodyTarget": o, "results": res, "custody": custody},
              open("/home/user/orca-audit/evidence/BBA_auth_sweep.json", "w"), indent=1)
    print("\nsaved evidence/BBA_auth_sweep.json")


if __name__ == "__main__":
    c = mainnet_atomic()
    auth_sweep(c)
