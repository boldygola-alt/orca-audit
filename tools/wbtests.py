"""Workstream C: Wavebreak fork test runner.

Fixtures are recovered live transaction forms (see recon/wb_ix_forms.json + recon/wb_curves.json)
and replayed against the state-preserving local fork with attacker substitutions.

Attacker funding is fixture funding on the fork only (documented in the evidence files):
native SOL via the fork airdrop, WSOL/base balances via Surfpool's setTokenAccount cheatcode.
Artificial funding is never treated as exploit evidence; it only lets a test reach the
program's own guards instead of failing early on an empty account.
"""
import sys, os, json, struct, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WSOL_MINT = F.WSOL
ATA = F.ATA
TOKEN = F.TOKEN
TOKEN22 = F.TOKEN22
SYSTEM = F.SYSTEM
PCFG = "8Sz6ihaNiWVNQM2MRArqrZa8RpGxr7SzRYSSr5cgeDDi"
ACFG = "5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"
MINTCFG = "DeVsaMequ6CxfhyJgV3EPdt5imnAWW6kSLZ7sdptDjFA"

actor = F.load_actor()
A = str(actor.pubkey())
LOG = []


def b58(b):
    from base58 import b58encode
    return b58encode(bytes(b)).decode()


def ata_of(owner, mint, prog=TOKEN):
    from solders.pubkey import Pubkey
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(ATA))[0])


def create_ata_ix(mint, prog=TOKEN):
    return F.create_ata(A, mint, prog, A)[1]


def sync_wsol_ix():
    return F.wsol_sync_instruction(A)[1]


def ix(tag, metas, data=b""):
    return Instruction(F.pk(WB), bytes([tag]) + data, metas)


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


def record(name, ixs, watch, before=None, note=""):
    before = before if before is not None else F.snapshot(watch, tokenaddrs=set(watch))
    r = F.send(ixs, actor)
    after = F.snapshot(watch, tokenaddrs=set(watch))
    d = F.diff(before, after)
    det = r.get("detail", {})
    err = det.get("err") or (r.get("error") or {}).get("message")
    logs = det.get("logs", [])
    rec = {"case": name, "note": note, "forkSlotAfter": F.get_slot(), "sig": r.get("result"),
           "txErr": err, "sendError": r.get("error"),
           "logsTail": [l.strip() for l in logs][-6:], "stateDiff": d,
           "actorLamports": after.get(A, {}).get("lamports"),
           "actorWsol": (after.get(ata_of(A, WSOL_MINT)) or {}).get("token", {}).get("amount"),
           "watchedAfter": {k: {"lamports": v.get("lamports"),
                               "tokenAmount": (v.get("token") or {}).get("amount"),
                               "dataHash": (v.get("dataHash") or "")[:12],
                               "absent": v.get("absent")} for k, v in after.items()}}
    LOG.append(rec)
    print(f"\n### {name}  ({note})")
    print("    err:", json.dumps(err)[:200])
    print("    logs:", " | ".join(rec["logsTail"])[:330])
    print("    diff:", json.dumps(d)[:300])
    return rec


# ---------------- codecs (borsh subset) ----------------
def enc_u64(v):
    return struct.pack("<Q", v)


def enc_msg(nonce, consumer_program, signer33, subject, valid_until, ptype, ixs_disc):
    out = b"\x00"                                  # PermissionMessage::V1
    out += enc_u64(nonce)
    out += bytes(F.pk(consumer_program))
    out += bytes(signer33)
    out += bytes(F.pk(subject))
    out += enc_u64(valid_until)
    out += bytes([ptype])
    out += struct.pack("<I", len(ixs_disc))
    for d in ixs_disc:
        out += struct.pack("<I", len(d)) + bytes(d)
    return out


def parse_msg(raw):
    o = 1
    nonce = struct.unpack_from("<Q", raw, o)[0]; o += 8
    cp = b58(raw[o:o + 32]); o += 32
    signer = raw[o:o + 33]; o += 33
    subj = b58(raw[o:o + 32]); o += 32
    vu = struct.unpack_from("<Q", raw, o)[0]; o += 8
    pt = raw[o]; o += 1
    n = struct.unpack_from("<I", raw, o)[0]; o += 4
    discs = []
    for _ in range(n):
        ln = struct.unpack_from("<I", raw, o)[0]; o += 4
        discs.append(raw[o:o + ln].hex()); o += ln
    return {"nonce": nonce, "consumerProgram": cp, "signer": signer.hex(), "subject": subj,
            "validUntil": vu, "permissionType": pt, "instructionDiscriminators": discs, "consumed": o}
