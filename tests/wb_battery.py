"""Wavebreak fork test battery (Workstream C1/C2/C3/C4/C5), executed as state-preserving
transactions on the local mainnet fork.

Every case records: fork slot, tx signature, per-instruction error, program log tail, and a
before/after diff of every account it touches (lamports, data hash, token amount, mint supply).
Attacker = fresh session keypair. Any artificial token funding is done via Surfpool cheatcodes,
is recorded in evidence, and is never treated as exploit evidence.
"""
import sys, os, json, struct, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey
from base58 import b58decode, b58encode

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
PCFG = "8Sz6ihaNiWVNQM2MRArqrZa8RpGxr7SzRYSSr5cgeDDi"        # permission_config (consumer=wavebreak)
ACFG = "5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"        # authority_config
MCFG = "DeVsaMequ6CxfhyJgV3EPdt5imnAWW6kSLZ7sdptDjFA"        # mint_config(WSOL, disc 40)
IXSYS = "Sysvar1nstructions1111111111111111111111111"
ALLOWED_SIGNER = bytes.fromhex("0359c54abfca3ce4aa40f74eec17c50f22de42c1002e871fcd98d36f6f186b2b29")
WSOL = F.WSOL
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

actor = F.load_actor()
A = str(actor.pubkey())
ATA_WSOL = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"   # created+funded earlier (fork fixture)

CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def curve_addr(base_mint):
    return str(Pubkey.find_program_address([b"bonding_curve", bytes(F.pk(base_mint))], F.pk(WB))[0])


def pda(seeds):
    for b in range(255, -1, -1):
        try:
            return str(Pubkey.create_program_address(list(seeds) + [bytes([b])], F.pk(WB))), b
        except Exception:
            continue
    raise RuntimeError("no viable bump seed")


def consumed_pda(sig64):
    return pda([b"consumed_permission", sig64[0:32], sig64[32:64]])[0]


def enc_msg(nonce, consumer_program, signer33, subject, valid_until, ptype, discs):
    o = bytearray(b"\x00")
    o += struct.pack("<Q", nonce)
    o += bytes(F.pk(consumer_program))
    o += bytes(signer33)
    o += bytes(F.pk(subject))
    o += struct.pack("<Q", valid_until)
    o += bytes([ptype])
    o += struct.pack("<I", len(discs))
    for d in discs:
        o += struct.pack("<I", len(d)) + bytes(d)
    return bytes(o)


def enc_sig(rec_id, sig64):
    return bytes([rec_id]) + bytes(sig64)


RESULTS = []


def snapshot(addrs):
    return F.snapshot(addrs, tokenaddrs=set(addrs) - {WB}, mints=set(addrs))


def run(name, ixs, watch, note="", expect=None):
    before = snapshot(watch)
    slot_before = F.get_slot()
    r = F.send(ixs, actor)
    after = snapshot(watch)
    slot_after = F.get_slot()
    d = F.diff(before, after)
    det = r.get("detail", {})
    err = det.get("err") or (r.get("error") or {}).get("message")
    rec = {"case": name, "note": note, "expect": expect, "forkSlotBefore": slot_before,
           "forkSlotAfter": slot_after, "sig": r.get("result"), "txErr": err,
           "sendError": r.get("error"),
           "logs": [l.strip() for l in det.get("logs", [])],
           "stateDiff": d,
           "before": {k: {"lamports": v.get("lamports"), "hash": (v.get("dataHash") or "")[:16],
                          "token": (v.get("token") or {}).get("amount"),
                          "supply": (v.get("mint") or {}).get("supply"), "absent": v.get("absent")}
                      for k, v in before.items()},
           "after": {k: {"lamports": v.get("lamports"), "hash": (v.get("dataHash") or "")[:16],
                         "token": (v.get("token") or {}).get("amount"),
                         "supply": (v.get("mint") or {}).get("supply"), "absent": v.get("absent")}
                     for k, v in after.items()}}
    RESULTS.append(rec)
    print(f"\n### {name}   {note}")
    print("   slot:", slot_before, "->", slot_after, " sig:", (rec["sig"] or "")[:36])
    print("   err :", json.dumps(err)[:160])
    keylogs = [l for l in rec["logs"] if "log:" in l or "failed" in l]
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in keylogs)[:300])
    print("   diff:", json.dumps(d)[:220])
    return rec


def ix(tag, metas, data=b""):
    return Instruction(F.pk(WB), bytes([tag]) + data, metas)


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


# =============================== permission layer ===============================
now_ts = int(time.time())
nonce = 1755000000 + (now_ts % 100000)


def consume_ix(consumer, msg, sig, consumed_addr):
    return ix(0, [M(consumer, w=True, s=True), M(PCFG), M(consumed_addr, w=True), M(F.SYSTEM), M(IXSYS)],
              msg + sig)


# P1: attacker signs with its own secp key, claims its own (non-allowed) signer
def make_msg(**kw):
    return enc_msg(kw.get("nonce", nonce), kw.get("consumer", WB), kw.get("signer", ALLOWED_SIGNER),
                   kw.get("subject", A), kw.get("valid_until", now_ts + 3600),
                   kw.get("ptype", 0), kw.get("discs", [[8]]))


bad_sig = bytes(64)
c_pda = consumed_pda(bad_sig)
run("WB-P01 consume: zero signature", [consume_ix(A, make_msg(), enc_sig(0, bad_sig), c_pda)],
    [A, ATA_WSOL, c_pda, PCFG], "attacker-generated message, all-zero signature",
    expect="rejected: signature/pubkey binding")

# P2: claimed signer = the real allowed signer, signature = attacker's own key
sig2 = bytes(range(1, 65))
c_pda2 = consumed_pda(sig2)
run("WB-P02 consume: claim allowed signer, attacker signature",
    [consume_ix(A, make_msg(), enc_sig(0, sig2), c_pda2)], [A, c_pda2, PCFG],
    "tests pubkey-recovery binding", expect="rejected: Permission signature is invalid")

# P3: expired permission, otherwise identical
c_pda3 = consumed_pda(bytes(64))
run("WB-P03 consume: expired permission",
    [consume_ix(A, make_msg(valid_until=now_ts - 60), enc_sig(0, bytes(64)), c_pda3)],
    [A, c_pda3, PCFG], "validUntil in the past", expect="rejected: Permission has expired")

# P4: wrong consumerProgram binding (busybox program as consumer) while calling wavebreak top-level
run("WB-P04 consume: consumerProgram = busybox",
    [consume_ix(A, make_msg(consumer="riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"),
                enc_sig(0, bytes(64)), consumed_pda(bytes(64)))],
    [A, PCFG], "cross-program permission reuse", expect="rejected")

# P5: instructionDiscriminators that do not include the trade instruction
c5 = consumed_pda(bytes([7]) * 64)
run("WB-P05 consume: discs=[99] (no trade ix)",
    [consume_ix(A, make_msg(discs=[[99]]), enc_sig(0, bytes([7]) * 64), c5)], [A, c5, PCFG],
    "permission not bound to the trade instruction", expect="rejected")

# P6: permissionType mismatch (type 255)
c6 = consumed_pda(bytes([9]) * 64)
run("WB-P06 consume: unknown permissionType",
    [consume_ix(A, make_msg(ptype=255), enc_sig(0, bytes([9]) * 64), c6)], [A, c6, PCFG],
    "bitmap/permissionType binding", expect="rejected")

# P7: subject = a victim, consumer = attacker (permission theft across wallets)
victim = "9gmP91zD3DP5NGJzuZqKAXqY4PpQq3pBQqJ3MhJcE1oq"
c7 = consumed_pda(bytes([11]) * 64)
run("WB-P07 consume: subject != consumer",
    [consume_ix(A, make_msg(subject=victim), enc_sig(0, bytes([11]) * 64), c7)], [A, c7, PCFG],
    "attacker consumes a permission issued for another wallet", expect="rejected: subject binding")

# P8: PermissionConsumeCpi invoked as a top-level instruction
run("WB-P08 consumeCpi as top-level",
    [ix(1, [M(A, w=True, s=True), M("2jXkJm9w6vZ1u5W4aPm3DQ6iW6oDk7rRnK9tQ3pY2vB5"),
            M(PCFG), M(consumed_pda(bytes([13]) * 64), w=True), M(F.SYSTEM)],
        make_msg() + enc_sig(0, bytes([13]) * 64))],
    [A, PCFG, consumed_pda(bytes([13]) * 64)], "tag 1 (CPI variant) called directly",
    expect="rejected: must be called via CPI")

# P9: two identical consumes in one transaction (duplicate)
c9 = consumed_pda(bytes([15]) * 64)
run("WB-P09 duplicate consume in one tx",
    [consume_ix(A, make_msg(), enc_sig(0, bytes([15]) * 64), c9),
     consume_ix(A, make_msg(), enc_sig(0, bytes([15]) * 64), c9)],
    [A, c9, PCFG], "same permission consumed twice in one tx", expect="rejected: duplicate/already-consumed")

# P10: valid-shaped consume followed by a buy that uses it
buy_curve = "AsE5V1Rc5syaHnmgqUrnTkf2abn3TSXPZAikvSRNnKqR"
bc = CURVES.get(buy_curve)
print("\n(buy curve fixture present:", bool(bc), (bc or {}).get("base_mint"), ")")
if bc:
    base = bc["base_mint"]
    vault = ata_of(buy_curve, WSOL)
    base_ata = ata_of(A, base)
    c10 = consumed_pda(bytes([17]) * 64)
    buy = ix(8, [M(A, w=True, s=True), M(buy_curve, w=True), M(base, w=True), M(base_ata, w=True),
                 M(WSOL), M(vault, w=True), M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA),
                 M(F.TOKEN), M(F.TOKEN)],
             struct.pack("<QB", 100_000_000, 1) + b"\x00")
    run("WB-P10 consume(attacker-signed) then buy", [consume_ix(A, make_msg(), enc_sig(0, bytes([17]) * 64), c10), buy],
        [A, ATA_WSOL, base_ata, buy_curve, vault, c10], "permissionless trade via self-signed permission",
        expect="rejected before any transfer")
    # C1 baseline: buy with NO consume
    run("WB-C01 buy with no consume ix", [buy], [A, ATA_WSOL, base_ata, buy_curve, vault],
        "live curve, funded attacker WSOL, no permission", expect="6018 missing permission consume")
    # C1 boundary cases
    for nm, amt, partial, thr in (("zero amount", 0, 0, 0), ("max u64", 2**64 - 1, 0, 0),
                                  ("partial-fill allowed", 100_000_000, 1, 0),
                                  ("tight threshold", 100_000_000, 0, 1)):
        d = bytearray(struct.pack("<QB", amt & (2**64 - 1), partial))
        if thr:
            d += b"\x01" + struct.pack("<QQ", 1, 2**64 - 1)
        else:
            d += b"\x00"
        ixb = ix(8, [M(A, w=True, s=True), M(buy_curve, w=True), M(base, w=True), M(base_ata, w=True),
                     M(WSOL), M(vault, w=True), M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA),
                     M(F.TOKEN), M(F.TOKEN)], bytes(d))
        run(f"WB-C01b buy {nm}", [ixb], [A, ATA_WSOL, base_ata, buy_curve, vault], nm,
            expect="rejected/denied deterministically")
    # C5 substitutions
    run("WB-C05a buy: quoteTokenProgram = Token-2022",
        [ix(8, [M(A, w=True, s=True), M(buy_curve, w=True), M(base, w=True), M(base_ata, w=True),
                M(WSOL), M(vault, w=True), M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA),
                M(F.TOKEN), M(F.TOKEN22)], struct.pack("<QB", 100_000_000, 1) + b"\x00")],
        [A, ATA_WSOL, base_ata, buy_curve, vault], "wrong quote token program", expect="rejected")
    other_vault = ata_of("11111111111111111111111111111111", WSOL)
    run("WB-C05b buy: vault = attacker-owned ATA",
        [ix(8, [M(A, w=True, s=True), M(buy_curve, w=True), M(base, w=True), M(base_ata, w=True),
                M(WSOL), M(ATA_WSOL, w=True), M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA),
                M(F.TOKEN), M(F.TOKEN)], struct.pack("<QB", 100_000_000, 1) + b"\x00")],
        [A, ATA_WSOL, base_ata, buy_curve], "quoteVault replaced by the buyer's own ATA", expect="rejected")
    run("WB-C05c buy: duplicate mutable account (buyer == vault)",
        [ix(8, [M(A, w=True, s=True), M(buy_curve, w=True), M(base, w=True), M(base_ata, w=True),
                M(WSOL), M(A, w=True), M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA),
                M(F.TOKEN), M(F.TOKEN)], struct.pack("<QB", 100_000_000, 1) + b"\x00")],
        [A, ATA_WSOL, base_ata, buy_curve], "same account twice / vault is a signer account", expect="rejected")
    run("WB-C05d buy: baseMint = other curve's mint",
        [ix(8, [M(A, w=True, s=True), M(buy_curve, w=True), M(USDC, w=True), M(base_ata, w=True),
                M(WSOL), M(vault, w=True), M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA),
                M(F.TOKEN), M(F.TOKEN)], struct.pack("<QB", 100_000_000, 1) + b"\x00")],
        [A, ATA_WSOL, base_ata, buy_curve, vault], "mint substitution", expect="rejected")
    # C2: two buys in one tx (sequence carry-over)
    run("WB-C02 buy+buy in one tx", [buy, buy], [A, ATA_WSOL, base_ata, buy_curve, vault],
        "same instruction twice against the same curve", expect="no state carry-over profit")
json.dump({"forkSlotEnd": F.get_slot(), "results": RESULTS}, open("/home/user/orca-audit/evidence/WBC_perm_trade.json","w"), indent=1)
print("\n==== saved evidence/WBC_perm_trade.json with", len(RESULTS), "cases")
