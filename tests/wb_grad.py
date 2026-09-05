"""Wavebreak graduation / escrow payout-path tests on live curves.

The prior run could only test graduation on curves configured for Whirlpool graduation, where the
run failed with 6015 "incorrect graduation instruction" - i.e. it never reached the payout
authorization decision. Seven live curves have a **Manual** graduation method configured, so this
run exercises `graduateManual` (disc 33) and `graduateWhirlpool` (disc 32) against them and records
which guard fires FIRST (authority check before or after state check), plus any balance movement.
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


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def read_ata(a):
    return snap(a)


def read_acct(a):
    return snap(a)


def snap(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    out = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
           "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        out["amount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 2048 and len(raw) >= 216:
        out["quote_amount"] = struct.unpack_from("<Q", raw, 208)[0]
        out["base_amount"] = struct.unpack_from("<Q", raw, 216)[0]
    return out


LBL = {0: "None", 1: "Whirlpool", 2: "Manual"}


def manual_curves():
    out = []
    for c in CURVES.values():
        meths = [(LBL.get(m["label"], m["label"]), m["graduated"], m["destination"], m["split_bps"],
                  m["fee_tier_index"], m["unlocked"]) for m in c["graduation_methods"]]
        if any(m[0] == "Manual" and not m[1] for m in meths):
            out.append(c)
    return out


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RESULTS = []


def run(name, ixs, watch, note=""):
    before = {a: snap(a) for a in watch}
    sb = F.get_slot()
    r = F.send(ixs, actor)
    after = {a: snap(a) for a in watch}
    det = r.get("detail", {})
    rec = {"case": name, "note": note, "curve": Tglob, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"),
           "logs": [l.strip() for l in det.get("logs", [])], "before": before, "after": after,
           "lamportsDelta": {a: (after.get(a) or {}).get("lamports", 0) - (before.get(a) or {}).get("lamports", 0)
                             for a in watch},
           "tokenDelta": {a: (after.get(a) or {}).get("amount", 0) - (before.get(a) or {}).get("amount", 0)
                          for a in watch if (after.get(a) or {}).get("space") == 165},
           "curveQuoteDelta": {a: (after.get(a) or {}).get("quote_amount", 0) - (before.get(a) or {}).get("quote_amount", 0)
                               for a in watch if (after.get(a) or {}).get("space") == 2048}}
    RESULTS.append(rec)
    print(f"\n### {name}   {note}")
    print("   err:", json.dumps(rec["err"])[:150])
    print("   logs:", " | ".join(l.split('log:')[-1].strip() for l in rec["logs"] if 'log:' in l or 'failed' in l)[:280])
    nzd = {k: v for k, v in rec["tokenDelta"].items() if v}
    nzl = {k: v for k, v in rec["lamportsDelta"].items() if v}
    print("   token deltas:", json.dumps(nzd)[:200])
    print("   lamport deltas:", json.dumps(nzl)[:200])
    print("   curve quote delta:", json.dumps({k: v for k, v in rec["curveQuoteDelta"].items() if v})[:160])
    return rec


Tglob = None


def main():
    global Tglob
    ms = manual_curves()
    print(f"live curves with an un-graduated Manual method: {len(ms)}")
    for c in sorted(ms, key=lambda x: -x["quote_amount"]):
        print(f"   {c['address']:44s} quote={c['quote_amount']:>14,} target={c['graduation_target']:>14,} "
              f"creator={c['creator'][:10]} base={c['base_mint'][:14]} quoteMint={c['quote_mint'][:12]}")
    for c in sorted(ms, key=lambda x: -x["quote_amount"])[:3]:
        Tglob = c["address"]
        BASE = c["base_mint"]
        QM = c["quote_mint"]
        VAULT = ata_of(Tglob, QM)
        dest_base = ata_of(A, BASE)
        _, ix1 = F.create_ata(A, BASE, F.TOKEN, A)
        _, ix2 = F.create_ata(A, QM, F.TOKEN if QM in (WSOL, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v") else F.TOKEN22, A)
        F.send([ix1, ix2], actor)
        dest_quote = ata_of(A, QM)
        watch = [A, ATA_WSOL, Tglob, VAULT, dest_base, dest_quote]
        # graduateManual [signer*, destination, bondingCurve, quoteMint, quoteVault, signerQuoteAta,
        #                 destinationQuoteAta, baseMint, destinationBaseAta, system, ata,
        #                 quoteTokenProgram, baseTokenProgram]
        qprog = F.TOKEN if QM in (WSOL, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v") else F.TOKEN22
        g_manual = Instruction(F.pk(WB), bytes([33]), [
            M(A, w=True, s=True), M(A), M(Tglob, w=True), M(QM), M(VAULT, w=True),
            M(ATA_WSOL, w=True), M(dest_quote, w=True), M(BASE, w=True), M(dest_base, w=True),
            M(F.SYSTEM), M(F.ATA), M(qprog), M(F.TOKEN)])
        run(f"WB-G01 graduateManual (attacker signer, attacker destination) {Tglob[:10]}",
            [g_manual], watch, "does a non-creator signer reach the escrow payout?")
        g_whirl = Instruction(F.pk(WB), bytes([32]), [
            M(A, w=True, s=True), M(A, w=True), M(Tglob, w=True), M(QM), M(VAULT, w=True),
            M(ATA_WSOL, w=True), M(dest_quote, w=True), M(BASE, w=True), M(dest_base, w=True),
            M(dest_quote, w=True), M("2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ"), M(BASE, w=True),
            M(Tglob), M(Tglob), M(Tglob), M(Tglob), M(Tglob), M(Tglob), M(dest_quote), M(dest_base),
            M(Tglob), M(Tglob), M(Tglob), M(Tglob), M(Tglob), M(Tglob), M(Tglob),
            M(F.SYSTEM), M(F.ATA), M(qprog), M(F.TOKEN), M(F.TOKEN22), M(F.MEMO),
            M("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"), M(F.RENT_SYSVAR)])
        run(f"WB-G02 graduateWhirlpool (wrong instruction for a Manual curve)", [g_whirl], watch,
            "expect 6015 incorrect graduation instruction")
        # tokenRefund on an expired curve (state gate), with attacker holding nothing
        rix = Instruction(F.pk(WB), bytes([12]), [
            M(A, w=True, s=True), M(Tglob, w=True), M(QM), M(VAULT, w=True), M(dest_quote, w=True),
            M(BASE, w=True), M(dest_base, w=True), M(F.SYSTEM), M(F.TOKEN), M(qprog), M(F.ATA)])
        run(f"WB-G03 tokenRefund on this curve", [rix], watch, "refund path state gate")
        # bondingCurveClose (disc 51) with attacker as the claimed authority
        cix = Instruction(F.pk(WB), bytes([51]), [
            M(A, w=True, s=True), M(c["creator"]), M("8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor"),
            M(Tglob, w=True), M(QM), M(VAULT, w=True), M(dest_quote, w=True), M(BASE, w=True),
            M("5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"), M(qprog), M(F.TOKEN),
            M(F.SYSTEM), M(F.ATA)])
        run(f"WB-G04 bondingCurveClose with attacker as authority", [cix], watch, "privilege gate")
        # collectFees by attacker (fee custody claim)
        fci = Instruction(F.pk(WB), bytes([49]), [
            M(A, w=True, s=True), M("8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor"),
            M(dest_quote, w=True), M(Tglob, w=True), M(BASE, w=True), M(QM), M(VAULT, w=True),
            M("5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"), M(F.SYSTEM), M(F.ATA), M(qprog)])
        run(f"WB-G05 bondingCurveCollectFees by attacker", [fci], watch,
            "fee custody claim gate")
    json.dump({"results": RESULTS}, open("/home/user/orca-audit/evidence/WBG_graduation.json", "w"), indent=1)
    print("\nsaved evidence/WBG_graduation.json")


if __name__ == "__main__":
    main()
