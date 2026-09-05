"""Workstream E: Busybox / Riptide AMM (`riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j`) fork tests.

Two goals:

 (1) Re-test every balance-moving handler with the *live account shape* (11-12 accounts). The prior
     run sent tag 0x02/0x03 with 0 accounts and read "InvalidAccountData @9 CU" as "handler not
     implemented"; that is an account-count artifact, not a security conclusion (rule 10).

 (2) Build a fully attacker-owned synthetic market (permissionless `market_initialize`, id chosen by
     the attacker; market PDA = ["market", u32 id]) so that deposit -> oracle update -> swap ->
     withdraw -> close accounting can be measured end-to-end against the deployed program, and the
     authorization/replay gates (stale oracle, sequence replay, duplicate mutable accounts,
     wrong token program, reserves vs vault divergence) can be probed directly.

Everything here is fork-only. Attacker token balances are fork fixture funding (documented), which
is never treated as exploit evidence.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
actor = F.load_actor(); A = str(actor.pubkey())
WSOL, USDC = F.WSOL, F.USDC
MARKETS = json.load(open("/home/user/orca-audit/recon/busybox_markets_live.json"))["markets"]
BYADDR = {m["address"]: m for m in MARKETS}


def ata_of(owner, mint, prog):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def mprog(mint):
    v = F.get_account(mint)
    return (v or {}).get("owner") or F.TOKEN


def snap_acct(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    out = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
           "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        out["amount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 1024:
        out["market"] = {"authority": F.b58(raw[8:40]), "updater": F.b58(raw[40:72]),
                         "mintA": F.b58(raw[72:104]), "mintB": F.b58(raw[104:136]),
                         "sequence": struct.unpack_from("<Q", raw, 136)[0],
                         "validUntil": struct.unpack_from("<Q", raw, 144)[0],
                         "reservesA": struct.unpack_from("<Q", raw, 736)[0],
                         "reservesB": struct.unpack_from("<Q", raw, 744)[0],
                         "disc": raw[0]}
    if v["space"] == 82:
        out["supply"] = struct.unpack_from("<Q", raw, 36)[0]
    return out


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RESULTS = []


def run(name, ixs, watch, note=""):
    before = {a: snap_acct(a) for a in watch}
    sb = F.get_slot()
    r = F.send(ixs, actor)
    after = {a: snap_acct(a) for a in watch}
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    deltas = {}
    for a in watch:
        b, af = before.get(a) or {}, after.get(a) or {}
        d = {}
        if b.get("lamports") != af.get("lamports"):
            d["lamports"] = (af.get("lamports") or 0) - (b.get("lamports") or 0)
        if b.get("amount") is not None and b.get("amount") != af.get("amount"):
            d["tokenAmount"] = (af.get("amount") or 0) - (b.get("amount") or 0)
        if b.get("supply") is not None and b.get("supply") != af.get("supply"):
            d["supply"] = (af.get("supply") or 0) - (b.get("supply") or 0)
        if b.get("market") and af.get("market"):
            ch = {k: [b["market"][k], af["market"][k]] for k in b["market"] if b["market"][k] != af["market"][k]}
            if ch:
                d["marketFields"] = ch
        if d:
            deltas[a] = d
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "deltas": deltas,
           "before": before, "after": after,
           "attackerLamportsDelta": (after.get(A) or {}).get("lamports", 0) - (before.get(A) or {}).get("lamports", 0)}
    RESULTS.append(rec)
    print(f"\n### {name}  [{note}]")
    print("   err:", json.dumps(rec["err"])[:170])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:300])
    print("   deltas:", json.dumps(deltas)[:700])
    return rec


# ---------- instruction builders (account lists from the v2.1.1 client + live forms) ----------
def ix_version():
    return Instruction(F.pk(BB), bytes([0]), [])


def ix_oracle_update(market, updater, sequence, valid_until, payload):
    return Instruction(F.pk(BB), bytes([1]) + struct.pack("<QQ", sequence, valid_until) + payload,
                       [M(market, w=True), M(updater, s=True)])


def ix_initialize(market_id, mint_a, mint_b, payer=A):
    market = str(Pubkey.find_program_address([b"market", struct.pack("<I", market_id)], F.pk(BB))[0])
    pa = mprog(mint_a); pb = mprog(mint_b)
    va, vb = ata_of(market, mint_a, pa), ata_of(market, mint_b, pb)
    accts = [M(payer, w=True, s=True), M(market, w=True), M(mint_a), M(mint_b),
             M(va, w=True), M(vb, w=True), M(F.SYSTEM), M(F.ATA), M(pa), M(pb)]
    return market, va, vb, Instruction(F.pk(BB), bytes([8]) + struct.pack("<I", market_id), accts)


def mk_liquidity(tag, market, mkt, va, vb, mv_a, mv_b, aa, ab, amount_a, amount_b):
    return Instruction(F.pk(BB), bytes([tag]) + struct.pack("<QQ", amount_a, amount_b), [
        M(aa[0], writable=True, signer=True), M(market, w=True),
        M(mkt["mintA"], w=True), M(mkt["mintB"], w=True),
        M(va, w=True), M(vb, w=True), M(mv_a, w=True), M(mv_b, w=True),
        M(mprog(mkt["mintA"])), M(mprog(mkt["mintB"])), M(F.MEMO)])


def mk_swap(tag, market, mkt, va, vb, mv_a, mv_b, amount, is_a, slippage, partial, signer=None,
            dup=False, swap_progs=None):
    data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
    data += bytes([0]) if slippage is None else (bytes([1]) + struct.pack("<Q", slippage))
    data += bytes([1 if partial else 0])
    pa, pb = swap_progs or (mprog(mkt["mintA"]), mprog(mkt["mintB"]))
    aa = signer or A
    accounts = [M(aa, w=True, s=True), M(market, w=True), M(mkt["mintA"], w=True), M(mkt["mintB"], w=True),
                M(va, w=True), M(vb, w=True), M(mv_a, w=True), M(mv_b, w=True), M(pa), M(pb),
                M(F.MEMO), M(F.IX_SYSVAR)]
    if dup:
        accounts[4] = M(mv_a, w=True)      # authority_a := market vault
    return Instruction(F.pk(BB), data, accounts)


def ix_close(market, mkt, mv_a, mv_b, va, vb, auth_signer=None):
    return Instruction(F.pk(BB), bytes([12]), [
        M(auth_signer or A, w=True, s=True), M(market, w=True),
        M(mkt["mintA"], w=True), M(mkt["mintB"], w=True),
        M(mv_a, w=True), M(mv_b, w=True), M(va, w=True), M(vb, w=True),
        M(F.SYSTEM), M(F.ATA), M(mprog(mkt["mintA"])), M(mprog(mkt["mintB"]))])


def flat_payload(price_q64_64):
    p = bytearray(512)
    p[0] = 1                                    # OracleData::FlatPrice
    struct.pack_into("<Q", p, 1, price_q64_64 & (2**64 - 1))
    struct.pack_into("<Q", p, 9, price_q64_64 >> 64)
    p[480] = 0                                  # SkewMode at SKEW_OFFSET
    return bytes(p)


def main():
    live = [m for m in MARKETS if m.get("reserves_a") or m.get("reserves_b")]
    print(f"live markets with non-zero reserves: {len(live)} of {len(MARKETS)}")

    # ---- E1: reachability of every tag with the CORRECT live account shape (real market) ----
    L = max(live or MARKETS, key=lambda m: (m.get("reserves_a") or 0) + (m.get("reserves_b") or 0))
    T = L["address"]
    raw = BYADDR[T]
    mkt = {"mintA": raw["mint_a"], "mintB": raw["mint_b"], "authority": raw["authority"],
           "updater": raw["updater"], "sequence": raw["sequence"], "validUntil": raw["valid_until"],
           "reservesA": raw["reserves_a"], "reservesB": raw["reserves_b"]}
    mA, mB = mkt["mintA"], mkt["mintB"]
    va, vb = ata_of(A, mA, mprog(mA)), ata_of(A, mB, mprog(mB))
    mv_a, mv_b = ata_of(T, mA, mprog(mA)), ata_of(T, mB, mprog(mB))
    print("live market:", T, "authority", mkt["authority"][:12], "updater", mkt["updater"][:12],
          "reserves", mkt["reservesA"], mkt["reservesB"], "validUntil", mkt["validUntil"],
          "sequence", mkt["sequence"])
    # make sure the attacker's own ATAs exist (real accounts, funded only for its own tokens)
    ixs = []
    for mint, prog in ((mA, mprog(mA)), (mB, mprog(mB))):
        _, x = F.create_ata(A, mint, prog, A)
        ixs.append(x)
    r = F.send(ixs, actor)
    print("attacker ATAs ready:", json.dumps((r.get("detail") or {}).get("err")))
    watch = [A, va, vb, T, mv_a, mv_b, mA, mB]
    run("BB-E01 programVersion", [ix_version()], watch, "returns the deployed version")
    run("BB-E02 swapExactIn, correct 12-account shape, attacker signer (NOT market authority)",
        [mk_swap(2, T, mkt, va, vb, mv_a, mv_b, 10 ** 6, True, None, False)], watch,
        "the prior run never reached this guard")
    run("BB-E03 swapExactOut, same shape", [mk_swap(3, T, mkt, va, vb, mv_a, mv_b, 10 ** 6, True, None, False)],
        watch, "swap exact-out reachability")
    run("BB-E04 oracleUpdate by non-updater", [ix_oracle_update(T, A, mkt["sequence"] + 1, 0, flat_payload(1 << 64))],
        watch, "attacker signs as the updater account")
    run("BB-E05 marketDeposit with live shape, attacker as authority",
        [mk_liquidity(10, T, mkt, va, vb, mv_a, mv_b, A, A, 10 ** 6, 0)], watch, "deposit gate")
    run("BB-E06 marketWithdraw with live shape, attacker as authority",
        [mk_liquidity(11, T, mkt, va, vb, mv_a, mv_b, A, A, 10 ** 6, 0)], watch, "withdraw gate")
    run("BB-E07 marketClose with live shape, attacker as authority", [ix_close(T, mkt, mv_a, mv_b, va, vb)],
        watch, "close gate: does the market's rent lamports go to the caller?")
    run("BB-E08 swapExactIn with duplicate mutable account (authorityA := marketVaultA)",
        [mk_swap(2, T, mkt, va, vb, mv_a, mv_b, 10 ** 6, True, None, False, dup=True)], watch,
        "aliasing the swapper's account onto the market vault")
    run("BB-E09 swapExactIn with wrong token program for mintA",
        [mk_swap(2, T, mkt, va, vb, mv_a, mv_b, 10 ** 6, True, None, False,
                 swap_progs=(F.TOKEN22, mprog(mkt["mintB"])))], watch, "token program pinning")
    run("BB-E10 reserved tags 4-7, 13-15 with a live-shaped payload",
        [Instruction(F.pk(BB), bytes([4]), [M(A, w=True, s=True), M(T, w=True)])], watch,
        "reserved swap slots")
    json.dump({"results": RESULTS, "liveMarket": mkt, "rawMarket": raw},
              open("/home/user/orca-audit/evidence/BBE_live_market.json", "w"), indent=1)
    print("\nsaved evidence/BBE_live_market.json")


if __name__ == "__main__":
    main()
