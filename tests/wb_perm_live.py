"""Wavebreak permission replay/subject-binding tests using REAL live permission data only.

Method (mandate Workstream B+C3): take the exact `PermissionConsumeTopLevel` instruction bytes
(message + secp256k1 signature) from a recent successful mainnet transaction, then on the fork
(a) replay it verbatim with the attacker as the consumer signer, and
(b) replay the same message with the permission subject set to the attacker while keeping the
    original signature (must fail signature verification), and
(c) attempt PermissionRefund before safeToCloseSlot and after, checking destination binding.
No signature is forged and no permission account is fabricated.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
import fixtures
from solders.instruction import Instruction

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
PCFG = "8Sz6ihaNiWVNQM2MRArqrZa8RpGxr7SzRYSSr5cgeDDi"
actor = F.load_actor(); A = str(actor.pubkey())


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RESULTS = []


def run(name, ixs, watch, note=""):
    before = {a: F.snapshot([a], tokenaddrs={a})[a] for a in watch}
    sb = F.get_slot()
    r = F.send(ixs, actor)
    after = {a: F.snapshot([a], tokenaddrs={a})[a] for a in watch}
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "stateDiff": F.diff(before, after),
           "before": before, "after": after}
    RESULTS.append(rec)
    print(f"\n### {name}  [{note}]")
    print("   slot", sb, "->", rec["forkSlotAfter"], " sig:", (rec["sig"] or "")[:30])
    print("   err:", json.dumps(rec["err"])[:170])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:340])
    print("   diff:", json.dumps(rec["stateDiff"])[:300])
    return rec


def parse_msg(msg):
    o = 1
    nonce = struct.unpack_from("<Q", msg, o)[0]; o += 8
    cp = F.b58(msg[o:o + 32]); o += 32
    signer = msg[o:o + 33]; o += 33
    subject = F.b58(msg[o:o + 32]); o += 32
    vu = struct.unpack_from("<Q", msg, o)[0]; o += 8
    pt = msg[o]; o += 1
    n = struct.unpack_from("<I", msg, o)[0]; o += 4
    discs = []
    for _ in range(n):
        ln = struct.unpack_from("<I", msg, o)[0]; o += 4
        discs.append(bytes(msg[o:o + ln])); o += ln
    return {"nonce": nonce, "consumerProgram": cp, "signer": signer, "subject": subject,
            "validUntil": vu, "permissionType": pt, "discs": discs, "lenConsumed": o}


def build_msg(p):
    out = bytearray(b"\x00")
    out += struct.pack("<Q", p["nonce"])
    out += bytes(F.pk(p["consumerProgram"]))
    out += bytes(p["signer"])
    out += bytes(F.pk(p["subject"]))
    out += struct.pack("<Q", p["validUntil"])
    out += bytes([p["permissionType"]])
    out += struct.pack("<I", len(p["discs"]))
    for d in p["discs"]:
        out += struct.pack("<I", len(d)) + bytes(d)
    return bytes(out)


def consumed_pda(sig64):
    from solders.pubkey import Pubkey
    for b in range(255, -1, -1):
        try:
            return str(Pubkey.create_program_address(
                [b"consumed_permission", sig64[0:32], sig64[32:64], bytes([b])], F.pk(WB)))
        except Exception:
            continue
    return None


def main():
    forms = json.load(open("/home/user/orca-audit/recon/wb_ix_forms.json"))["forms"]
    f0 = forms.get("0")
    if not f0:
        print("no tag-0 fixture"); return
    ix = f0["ix"]
    data = bytes.fromhex(ix["data_hex"])
    accs = [a["pubkey"] if isinstance(a, dict) else a for a in ix["accounts"]]
    print("fixture consume: sig", f0["sig"][:30], "slot", f0["slot"], "accounts", accs)
    msg = data[1:]
    p = parse_msg(msg)
    tail = msg[p["lenConsumed"]:]
    sig64, rec_id = tail[:64], tail[64] if len(tail) == 65 else 0
    print(f"  message: nonce={p['nonce']} consumerProgram={p['consumerProgram']} "
          f"subject={p['subject']} validUntil(slot)={p['validUntil']} type={p['permissionType']} "
          f"discs={[d.hex() for d in p['discs']]} signer={p['signer'].hex()} recId={rec_id}")
    fork_slot = F.get_slot()
    print(f"  fork slot {fork_slot}  -> permission valid window: "
          f"{'EXPIRED at fork tip' if p['validUntil'] < fork_slot else 'STILL VALID at fork tip'}")
    consumed = accs[2]
    exists = F.get_account(consumed)
    print("  consumed-permission account at fork:", "EXISTS" if exists else "ABSENT", exists and exists["lamports"])
    # RP1 verbatim replay, attacker as the consumer signer
    rp1 = Instruction(F.pk(WB), data, [M(A, w=True, s=True), M(accs[1]), M(consumed, w=True),
                                      M(F.SYSTEM), M(F.IX_SYSVAR)])
    run("WB-RP1 verbatim replay of a live consume (attacker signs as consumer)",
        [rp1], [A, consumed, accs[1]], "must fail: account already exists / consumer-subject binding")
    # RP2 attacker substituted as subject, original signature kept
    p2 = dict(p); p2["subject"] = A
    rp2 = Instruction(F.pk(WB), bytes([0]) + build_msg(p2) + tail,
                      [M(A, w=True, s=True), M(accs[1]), M(consumed_pda(sig64) or consumed, w=True),
                       M(F.SYSTEM), M(F.IX_SYSVAR)])
    run("WB-RP2 subject replaced by the attacker, original signature kept",
        [rp2], [A, consumed_pda(sig64) or consumed], "secp256k1 recovery must not match the allowed signer set")
    # RP3 attacker claims its own pubkey as the signer (still the original signature)
    p3 = dict(p); p3["subject"] = A; p3["signer"] = bytes(33)
    from solders.pubkey import Pubkey
    mine = F.get_account(A)
    rp3 = Instruction(F.pk(WB), bytes([0]) + build_msg(p3) + tail,
                      [M(A, w=True, s=True), M(accs[1]), M(consumed_pda(sig64), w=True),
                       M(F.SYSTEM), M(F.IX_SYSVAR)])
    run("WB-RP3 signer field zeroed, original signature kept", [rp3], [A], "must fail signature verification")
    # RP4 refund of the (now closed) consumed permission, and of a live one before/after safeToCloseSlot
    live = json.load(open("/home/user/orca-audit/recon/wb_consumed_permissions.json"))["accounts"]
    closable = [x for x in live if x["safe_to_close_slot"] <= F.get_slot()]
    notclosable = [x for x in live if x["safe_to_close_slot"] > F.get_slot()]
    print(f"  live consumed-permissions: {len(live)} closable-now={len(closable)} not-yet={len(notclosable)}")
    if closable:
        t = closable[0]["address"]
        run("WB-RP4 refund live consumed-permission (past safeToCloseSlot) -> attacker wallet",
            [Instruction(F.pk(WB), bytes([6]), [M(t, w=True), M(A, w=True)])], [A, t],
            f"stored refundDestination={closable[0]['refund_destination']}")
        run("WB-RP5 refund live consumed-permission -> attacker WSOL ATA",
            [Instruction(F.pk(WB), bytes([6]), [M(t, w=True), M("HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh", w=True)])],
            [A, t], "rent-lamport redirect attempt")
        dup = [Instruction(F.pk(WB), bytes([6]), [M(t, w=True), M(A, w=True)]),
               Instruction(F.pk(WB), bytes([6]), [M(t, w=True), M(A, w=True)])]
        run("WB-RP6 same refund twice in one tx", dup, [A, t], "double refund / close-after-close")
    # RP7 PermissionRevoke by the attacker (disc 5) on the live consumed pda
    if closable:
        t = closable[0]["address"]
        run("WB-RP7 permissionRevoke by attacker on a live consumed-permission",
            [Instruction(F.pk(WB), bytes([5]) + msg + tail,
                         [M(A, w=True, s=True), M(accs[1]), M(t, w=True), M(F.SYSTEM)])], [A, t],
            "funder binding: only the original funder may revoke")
        # RP8 config update attempts with the exact live account shape (privilege gate)
        for tag, nm in ((3, "permissionConfigUpdate"), (4, "permissionConfigClose")):
            run(f"WB-RP8 {nm} by attacker",
                [Instruction(F.pk(WB), bytes([tag]) + (bytes([0]) + bytes(33) if tag == 3 else b""),
                             [M(A, w=True, s=True), M(PCFG, w=True),
                              M("5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4")])], [A, PCFG],
                "privilege gate on the shared permission config")
    json.dump({"fixture": {"sig": f0["sig"], "slot": f0["slot"], "accounts": accs,
                           "message": p if isinstance(p, dict) else None,
                           "parsed": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in p.items() if k != "discs"},
                           "discs": [d.hex() for d in p["discs"]],
                           "signature_hex": sig64.hex(), "recoveryId": rec_id,
                           "consumedExistsAtFork": bool(exists)},
               "forkSlot": fork_slot, "results": RESULTS},
              open("/home/user/orca-audit/evidence/WBRP_permission.json", "w"), indent=1, default=str)
    print("\nsaved evidence/WBRP_permission.json")


if __name__ == "__main__":
    main()
