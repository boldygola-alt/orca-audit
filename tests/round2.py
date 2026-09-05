"""Round 2: (a) Wavebreak graduateWhirlpool authorization test with all accounts derived from live
state; (b) live-permission consume replay/subject-binding with the real on-chain message+signature;
(c) Busybox swap tests using the markets' ACTUAL vault token accounts (read from chain, not derived).
"""
import sys, json, struct, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
import rpc
from solders.instruction import Instruction
from solders.pubkey import Pubkey
from base58 import b58decode, b58encode

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
WSOL, USDC = F.WSOL, F.USDC
WHIRL = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"
WCFG = "2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ"
actor = F.load_actor(); A = str(actor.pubkey())
ATA_WSOL = ata_wsol = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}


def pk(s):
    return Pubkey.from_string(s)


def pda(seeds, program):
    for b in range(255, -1, -1):
        try:
            return str(Pubkey.create_program_address(list(seeds) + [bytes([b])], pk(program))), b
        except Exception:
            continue
    return None, None


def ata_of(owner, mint, prog):
    return str(Pubkey.find_program_address([bytes(pk(owner)), bytes(pk(prog)), bytes(pk(mint))],
                                           pk(F.ATA))[0])


def prog_of(mint):
    v = F.get_account(mint) or rpc.get_account(mint)
    return (v or {}).get("owner") or F.TOKEN


def snap(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    o = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
         "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        o["tokenAmount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 82 and len(raw) >= 44:
        o["supply"] = struct.unpack_from("<Q", raw, 36)[0]
    if v["space"] == 2048 and len(raw) >= 224:
        o["quoteAmount"] = struct.unpack_from("<Q", raw, 208)[0]
        o["baseAmount"] = struct.unpack_from("<Q", raw, 216)[0]
    return o


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
    d = {}
    for a in watch:
        b, af = before.get(a) or {}, after.get(a) or {}
        e = {}
        if (b.get("lamports") or 0) != (af.get("lamports") or 0):
            e["lamports"] = (af.get("lamports") or 0) - (b.get("lamports") or 0)
        if b.get("tokenAmount") is not None and b.get("tokenAmount") != af.get("tokenAmount"):
            e["tokenAmount"] = (af.get("tokenAmount") or 0) - (b["tokenAmount"] or 0)
        if b.get("supply") is not None and b.get("supply") != af.get("supply"):
            e["supply"] = (af.get("supply") or 0) - (b["supply"] or 0)
        for f in ("quoteAmount", "baseAmount"):
            if b.get(f) is not None and b.get(f) != af.get(f):
                e[f] = (af.get(f) or 0) - (b[f] or 0)
        if e:
            d[a] = e
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "deltas": d, "attackerTokenDeltas": {}}
    for a in watch:
        if (after.get(a) or {}).get("space") == 165 and (after.get(a) or {}).get("owner") in (F.TOKEN, F.TOKEN22):
            o = snap(a)
    RESULTS.append(rec)
    print(f"\n### {name}   [{note}]")
    print("   slot", sb, "->", rec["forkSlotAfter"], " err:", json.dumps(rec["err"])[:150])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l or "invoke" in l)[:400])
    print("   deltas:", json.dumps(d)[:600])
    return rec


# ============ (b) live permission replay: exact message+signature from a real tx ============
def permission_replay():
    forms = json.load(open("/home/user/orca-audit/recon/wb_ix_forms.json"))
    f0 = forms["forms"].get("0")
    if not f0:
        print("no tag-0 live form"); return
    data = bytes.fromhex(f0["ix"]["data_hex"])
    keys = [k["pubkey"] if isinstance(k, dict) else k for k in f0["keys"]]
    accs = f0["ix"]["accounts"]
    print("\nlive consume form: slot", f0["slot"], "sig", f0["sig"][:28], "accounts", accs)
    msg = data[1:]
    # parse out the fields we need to mutate
    o = 1
    nonce = struct.unpack_from("<Q", msg, o)[0]; o += 8
    consumer_program = b58encode(msg[o:o+32]).decode(); o += 32
    signer = msg[o:o+33]; o += 33
    subject = b58encode(msg[o:o+32]).decode(); o += 32
    valid_until = struct.unpack_from("<Q", msg, o)[0]; o += 8
    ptype = msg[o]; o += 1
    n = struct.unpack_from("<I", msg, o)[0]; o += 4
    discs = []
    for _ in range(n):
        ln = struct.unpack_from("<I", msg, o)[0]; o += 4
        discs.append(msg[o:o+ln].hex()); o += ln
    tail = msg[o:]
    sig = tail[:-1] if len(tail) == 65 else tail
    rec_id = tail[-1] if len(tail) == 65 else 0
    print(f"   parsed: nonce={nonce} consumerProgram={consumer_program} subject={subject} "
          f"validUntil={valid_until} type={ptype} discs={discs} signer={signer.hex()[:20]}.. "
          f"tailLen={len(tail)}")
    consumed = accs[2]
    exists = F.get_account(consumed) is not None
    print(f"   consumed-permission {consumed} exists at fork: {exists}")
    # RP1: exact replay (same message, same signature) with the ATTACKER as the consumer signer
    rp = Instruction(F.pk(WB), data, [M(A, w=True, s=True), M(accs[1]), M(consumed, w=True),
                                     M(F.SYSTEM), M(F.IX_SYSVAR)])
    run("WB-RP1 exact replay of a live consume (attacker as consumer)", [rp],
        [A, consumed, accs[1]], "public permission data; expired permission (validUntil slot "
                                f"{valid_until} vs now {F.get_slot()})")
    # RP2: replay with the ORIGINAL consumer account listed but the attacker paying? (needs their sig)
    #     -> not possible; instead mutate the subject to the attacker, keep the original signature
    mutated = bytearray()
    mutated += struct.pack("<Q", nonce)
    mutated += bytes(pk(consumer_program))
    mutated += bytes(signer)
    mutated += bytes(pk(A))
    mutated += struct.pack("<Q", valid_until)
    mutated += bytes([ptype])
    mutated += struct.pack("<I", n)
    for dd in discs:
        b = bytes.fromhex(dd)
        mutated += struct.pack("<I", len(b)) + b
    mutated = bytes(mutated)
    rp2 = Instruction(F.pk(WB), bytes([0]) + mutated + tail, [M(A, w=True, s=True), M(accs[1]),
                  M(consumed, w=True), M(F.SYSTEM), M(F.IX_SYSVAR)])
    run("WB-RP2 subject swapped to the attacker, original signature kept", [rp2],
        [A, consumed, accs[1]], "signature must not verify for a mutated message")
    json.dump({"parsed": {"nonce": nonce, "consumerProgram": consumer_program, "subject": subject,
                          "validUntil": valid_until, "permissionType": ptype, "discs": discs,
                          "signer": signer.hex(), "consumedPda": consumed,
                          "consumedExistsAtFork": exists},
               "results": RESULTS[-2:]}, open("/home/user/orca-audit/evidence/WBRP_live_permission_replay.json", "w"), indent=1)


# ============ (a) graduateWhirlpool authorization on a live Whirlpool-method curve ============
def graduate_whirlpool_test():
    now = int(time.time())
    cands = [c for c in CURVES.values()
             if c["quote_mint"] == WSOL and not any(m["graduated"] for m in c["graduation_methods"])
             and any(m["label"] == 1 for m in c["graduation_methods"]) and c["quote_amount"] > 10 ** 9]
    cands.sort(key=lambda c: -c["quote_amount"])
    c = cands[0]
    T, BASE = c["address"], c["base_mint"]
    meth = [m for m in c["graduation_methods"] if m["label"] == 1][0]
    creator, dest = c["creator"], meth["destination"]
    print(f"\ngraduateWhirlpool target curve {T} quote={c['quote_amount']:,} feeTierIndex={meth['fee_tier_index']}")
    # whirlpool pool PDA for (base, WSOL) at the fee tier's tick spacing
    cfg = F.get_account(WCFG)
    raw = base64.b64decode(cfg["data"][0]) if cfg else b""
    tiers = []
    i = 4
    while i + 4 <= min(len(raw), 4 + 4 * 40):
        fee_tier, ts = struct.unpack_from("<Hh", raw, i); i += 4
        tiers.append((fee_tier, ts))
    print("   config fee tiers:", tiers[:12])
    ts = tiers[meth["fee_tier_index"]][1] if meth["fee_tier_index"] < len(tiers) else 64
    for order in ((BASE, WSOL), (WSOL, BASE)):
        pool, _ = pda([b"whirlpool", bytes(pk(WCFG)), bytes(pk(order[0])), bytes(pk(order[1])),
                       struct.pack("<H", ts)], WHIRL)
        if pool and F.get_account(pool):
            print("   existing pool:", pool, "order", order); break
    else:
        pool, _ = pda([b"whirlpool", bytes(pk(WCFG)), bytes(pk(BASE)), bytes(pk(WSOL)),
                       struct.pack("<H", ts)], WHIRL)
        print("   no pool exists; derived (would be created by the CPI):", pool)
    oracle, _ = pda([b"oracle", bytes(pk(pool))], WHIRL)
    pos_mint, _ = pda([b"position", bytes(pk(pool)), b"\x00"], WHIRL)
    position, _ = pda([b"position", bytes(pk(pos_mint))], WHIRL)
    lower, _ = pda([b"tick_array", bytes(pk(pool)), struct.pack("<I", 2**32 - 8192 // 64)], WHIRL)
    lock_cfg, _ = pda([b"lock_config", bytes(pk(pos_mint))], WHIRL)
    badge_q, _ = pda([b"token_badge", bytes(pk(WSOL)), bytes(pk(pool))], WHIRL)
    badge_b, _ = pda([b"token_badge", bytes(pk(BASE)), bytes(pk(pool))], WHIRL)
    vault_q, vault_b = ata_of(pool, WSOL, F.TOKEN), ata_of(pool, BASE, prog_of(BASE))
    lp_auth = dest
    pta_q, pta_b = ata_of(lp_auth, WSOL, F.TOKEN), ata_of(lp_auth, BASE, prog_of(BASE))
    curve_vault = ata_of(T, WSOL, F.TOKEN)
    att_base = ata_of(A, BASE, prog_of(BASE))
    escrow, _ = pda([b"lp_escrow", bytes(pk(lp_auth))], WB)
    ixs = [Instruction(F.pk(WB), bytes([32]), [
        M(A, w=True, s=True), M(lp_auth, w=True), M(T, w=True), M(WSOL), M(curve_vault, w=True),
        M(ATA_WSOL, w=True), M(pta_q, w=True), M(BASE, w=True), M(vault_b, w=True), M(pta_b, w=True),
        M(vault_q, w=True), M(WCFG), M(BASE), M(pool), M(oracle), M(position), M(pos_mint),
        M(ata_of(escrow, pos_mint, F.TOKEN22), w=True), M(ata_of(lp_auth, pos_mint, F.TOKEN22), w=True),
        M(lower), M(pool), M(badge_q), M(badge_b), M(escrow, w=True), M("3axbTs2z5GBy6usVbNVoqEgZMng3vZvMnAoX29BFfwhr", w=True),
        M(lock_cfg, w=True), M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(prog_of(BASE)), M(F.TOKEN22), M(F.MEMO),
        M(WHIRL), M(F.RENT_SYSVAR)])]
    watch = [A, ATA_WSOL, T, curve_vault, pool, position, pos_mint, escrow, BASE, vault_q, vault_b, pta_q, pta_b]
    run("WB-GW1 graduateWhirlpool: attacker signer on a live Whirlpool-method curve", ixs, watch,
        "is graduation gated by authority/privilege, or reachable by anyone?")


# ============ (c) busybox swaps with the markets' real vault accounts ============
def busybox_swaps():
    mk = json.load(open("/home/user/orca-audit/recon/busybox_markets_live.json"))["markets"]
    now = F.get_slot()
    withres = [m for m in mk if (m.get("reserves_a") or 0) + (m.get("reserves_b") or 0) > 0]
    withres.sort(key=lambda m: -(m["reserves_a"] + m["reserves_b"]))
    out = []
    for m in withres:
        a = m["address"]
        r = rpc.rpc("getTokenAccountsByOwner", [a, {"encoding": "jsonParsed"}, {"commitment": "confirmed"}])
        toks = {}
        for it in (r.get("result") or {}).get("value", []):
            info = it["account"]["data"]["parsed"]["info"]
            toks.setdefault(info["mint"], []).append({"ata": it["pubkey"],
                                                      "amount": int(info["tokenAmount"]["amount"]),
                                                      "owner": it["account"]["owner"]})
        if not toks:
            for mint in (m["mint_a"], m["mint_b"]):
                pr = prog_of(mint)
                a_ = ata_of(a, mint, pr)
                sv = snap(a_)
                if sv:
                    toks[mint] = [{"ata": a_, "amount": sv.get("tokenAmount", 0), "owner": pr}]
        m["_vaults"] = {k: v[0]["ata"] for k, v in toks.items()}
        m["_balances"] = {k: v[0]["amount"] for k, v in toks.items()}
        m["stale"] = m["valid_until"] < now
        out.append(m)
        print(f"  {a[:20]:22s} stale={m['stale']} resA={m['reserves_a']:>15,}/{m['_balances'].get(m['mint_a'],0):>15,}"
              f" resB={m['reserves_b']:>15,}/{m['_balances'].get(m['mint_b'],0):>15,}")
    json.dump(out, open("/home/user/orca-audit/recon/busybox_market_vaults.json", "w"), indent=1)
    div = [m for m in out if m["_balances"].get(m["mint_a"], 0) != m["reserves_a"]
           or m["_balances"].get(m["mint_b"], 0) != m["reserves_b"]]
    print(f"markets whose vault balances differ from stored reserves: {len(div)} of {len(out)}")
    for m in div[:6]:
        print("   ", m["address"], {k: (m["reserves_a"], m["reserves_b"], m["_balances"]) for k in [m["address"]]}[""])
    # pick a stale market where the attacker can hold both mints
    ok = [m for m in out if m["_vaults"].get(m["mint_a"]) and m["_vaults"].get(m["mint_b"])]
    print("markets with both vaults present:", len(ok))
    tgt = max(ok or out, key=lambda m: (m["valid_until"] < now, m["reserves_a"] + m["reserves_b"]))
    A_ = tgt
    mkt = A_["address"]
    mA, mB = A_["mint_a"], A_["mint_b"]
    pa, pb = prog_of(mA), prog_of(mB)
    mv_a, mv_b = A_["_vaults"].get(mA), A_["_vaults"].get(mB)
    print(f"\nswap target {mkt} mintA={mA[:12]}({pa[:8]}) mintB={mB[:12]}({pb[:8]}) vaultA={mv_a} vaultB={mv_b} stale={A_['stale']}")
    u_a, u_b = ata_of(A, mA, pa), ata_of(A, mB, pb)
    for mint, prog in ((mA, pa), (mB, pb)):
        _, x = F.create_ata(A, mint, prog, A)
        F.send([x], actor)
    watch = [A, mkt, mv_a, mv_b, u_a, u_b, mA, mB]
    def swapix(tag, amount, is_a, partial=0, sl=None, a_src=None, b_dst=None):
        data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
        data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<QQ", *sl))
        data += bytes([partial])
        return Instruction(F.pk(BB), data, [
            M(A, w=True, s=True), M(mkt, w=True), M(mA, w=True), M(mB, w=True),
            M(a_src or u_a, w=True), M(b_dst or u_b, w=True), M(mv_a, w=True), M(mv_b, w=True),
            M(pa), M(pb), M(F.MEMO), M(F.IX_SYSVAR)])
    run("BB-S01 swapExactIn 1 unit of mintA on a STALE-oracle market", [swapix(2, 1, True)], watch,
        "does the swap reject an expired stored oracle?")
    run("BB-S02 swapExactIn with slippage threshold tuple", [swapix(2, 10 ** 6, True, sl=(0, 2**64 - 1))],
        watch, "MaxExecutionPrice variant")
    run("BB-S03 swapExactIn allow_partial_fill=1", [swapix(2, 10 ** 12, True, partial=1)], watch,
        "partial fill against a stale market")
    run("BB-S04 swapExactOut tiny", [swapix(3, 1, False)], watch, "exact-out")
    print("\nNOTE: attacker holds zero balance in both mints on the fork; if the failure is a token")
    print("      'insufficient funds' AFTER the pricing stage, the expiry guard did not reject it.")


if __name__ == "__main__":
    permission_replay()
    graduate_whirlpool_test()
    busybox_swaps()
    json.dump({"results": RESULTS}, open("/home/user/orca-audit/evidence/ROUND2.json", "w"), indent=1)
    print("\nsaved evidence/ROUND2.json")
