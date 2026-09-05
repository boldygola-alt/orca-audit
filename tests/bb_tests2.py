"""Busybox/Riptide v2.1.1: swap-path guard tests (oracle expiry, aliasing, empty oracle) and a
fully attacker-owned synthetic market lifecycle.

Context: the deployed riptK81h ELF (sha256 32a8a8f75662cfdc...) is "Riptide AMM Program" v2.1.1 and
its SwapExactIn/SwapExactOut handlers ARE implemented and reachable with the correct 12-account
shape - the prior run's "not implemented (InvalidAccountData @9 CU)" conclusion came from sending the
tag with zero accounts, which is an account-count artifact (mandate rule 10). Swaps take only the
*trader's* signature, so they are permissionless against live market reserves; therefore the oracle
expiry gate, the sequence gate and account aliasing are the security-critical checks under test.
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
BY = {m["address"]: m for m in MARKETS}


def ata_of(owner, mint, prog):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def mprog(mint):
    v = F.get_account(mint)
    return (v or {}).get("owner") or F.TOKEN


def snap(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    out = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
           "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        out["tokenAmount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 82:
        out["supply"] = struct.unpack_from("<Q", raw, 36)[0]
        out["mintAuthority"] = F.b58(raw[46:78]) if raw[45] else None
    if v["space"] == 1024:
        out["market"] = {"disc": raw[0], "authority": F.b58(raw[8:40]), "updater": F.b58(raw[40:72]),
                         "mintA": F.b58(raw[72:104]), "mintB": F.b58(raw[104:136]),
                         "sequence": struct.unpack_from("<Q", raw, 136)[0],
                         "validUntil": struct.unpack_from("<Q", raw, 144)[0],
                         "reservesA": struct.unpack_from("<Q", raw, 736)[0],
                         "reservesB": struct.unpack_from("<Q", raw, 744)[0],
                         "oracleNonzero": sum(1 for b in raw[152:664] if b)}
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
    d = {}
    for a in watch:
        b, af = before.get(a) or {}, after.get(a) or {}
        e = {}
        if b.get("lamports") != af.get("lamports"):
            e["lamports"] = (af.get("lamports") or 0) - (b.get("lamports") or 0)
        if b.get("tokenAmount") is not None and b.get("tokenAmount") != af.get("tokenAmount"):
            e["tokenAmount"] = (af.get("tokenAmount") or 0) - (b.get("tokenAmount") or 0)
        if b.get("supply") is not None and b.get("supply") != af.get("supply"):
            e["supply"] = (af.get("supply") or 0) - (b.get("supply") or 0)
        if b.get("market") and af.get("market"):
            ch = {k: [b["market"][k], af["market"][k]] for k in b["market"] if b["market"][k] != af["market"][k]}
            if ch:
                e["market"] = ch
        if e:
            d[a] = e
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "deltas": d, "before": before, "after": after,
           "attackerTokenDeltas": {a: (after.get(a) or {}).get("tokenAmount", 0) - (before.get(a) or {}).get("tokenAmount", 0)
                                   for a in watch if (after.get(a) or {}).get("space") == 165
                                   and (a == ata_of(A, WSOL, F.TOKEN) or a == ata_of(A, USDC, F.TOKEN))}}
    RESULTS.append(rec)
    print(f"\n### {name}   [{note}]")
    print("   slot", rec["forkSlotBefore"], "->", rec["forkSlotAfter"], " err:", json.dumps(rec["err"])[:150])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:300])
    print("   deltas:", json.dumps(d)[:520])
    return rec


def swap(tag, mkt_addr, amount, is_a, slippage=None, partial=False, src=None, dst=None,
         vault_a=None, vault_b=None, prog_a=None, prog_b=None, dup_src_into_vault=False):
    m = BY[mkt_addr]
    mA, mB = m["mint_a"], m["mint_b"]
    pa, pb = prog_a or mprog(mA), prog_b or mprog(mB)
    a_va, a_vb = src or ata_of(A, mA, pa), dst or ata_of(A, mB, pb)
    mv_a, mv_b = vault_a or ata_of(mkt_addr, mA, pa), vault_b or ata_of(mkt_addr, mB, pb)
    if dup_src_into_vault:
        a_va = mv_a
    data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
    data += bytes([0]) if slippage is None else (bytes([1]) + struct.pack("<Q", *slippage) if isinstance(slippage, tuple) else bytes([2]) + struct.pack("<Q", slippage))
    data += bytes([1 if partial else 0])
    return Instruction(F.pk(BB), data, [
        M(A, w=True, s=True), M(mkt_addr, w=True), M(mA, w=True), M(mB, w=True),
        M(a_va, w=True), M(a_vb, w=True), M(mv_a, w=True), M(mv_b, w=True),
        M(pa), M(pb), M(F.MEMO), M(F.IX_SYSVAR)])


def fund_ata(addr, raw_len, amount, prog):
    """fork-only fixture funding of the ATTACKER's own token account (documented; not exploit proof)"""
    v = F.get_account(addr)
    if not v:
        return {"skipped": "ata absent"}
    raw = bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q", raw, 64, amount)
    return F.rpc.rpc("surfnet_setAccount", [addr, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                                   "owner": prog, "executable": False}], url=F.FORK)


def main():
    now = F.get_slot()
    print("fork slot:", now)
    stale = [m for m in MARKETS if (m.get("reserves_a") or 0) + (m.get("reserves_b") or 0) > 0
             and m["valid_until"] < now]
    fresh = [m for m in MARKETS if (m.get("reserves_a") or 0) + (m.get("reserves_b") or 0) > 0
             and m["valid_until"] >= now]
    print(f"markets with reserves: stale {len(stale)} / fresh {len(fresh)}")

    # --- WSOL funding so the swap tests reach the program's guards, not an empty account ---
    u_wsol = ata_of(A, WSOL, F.TOKEN)
    u_usdc = ata_of(A, USDC, F.TOKEN)
    for mint, prog in ((WSOL, F.TOKEN), (USDC, F.TOKEN)):
        _, x = F.create_ata(A, mint, prog, A)
        F.send([x], actor)
    print("fund wsol:", json.dumps(fund_ata(u_wsol, 165, 100_000_000_000, F.TOKEN))[:80])
    print("fund usdc:", json.dumps(fund_ata(u_usdc, 165, 100_000_000, F.TOKEN))[:80])

    # ============ staleness gate on a live, funded market with a stale oracle ============
    S = max(stale, key=lambda m: m["reserves_a"] + m["reserves_b"])
    st = S["address"]
    print(f"\nSTALE target {st} validUntil={S['valid_until']} (< {now}) resA={S['reserves_a']:,} resB={S['reserves_b']:,}")
    watch = [A, u_wsol, u_usdc, st, ata_of(st, S["mint_a"], mprog(S["mint_a"])),
             ata_of(st, S["mint_b"], mprog(S["mint_b"])), S["mint_a"], S["mint_b"]]
    run("BB-F01 swapExactIn on a market whose stored oracle has EXPIRED",
        [swap(2, st, 1_000_000_000, S["mint_a"] == WSOL)], watch,
        "expiry guard: does the program still price the swap off the stale stored oracle?")
    run("BB-F02 swapExactOut on the same stale market",
        [swap(3, st, 1_000_000, S["mint_a"] == WSOL)], watch, "exact-out variant")
    # fresh-oracle contrast
    if fresh:
        Fm = fresh[0]["address"]
        mm = fresh[0]
        wf = [A, u_wsol, u_usdc, Fm, ata_of(Fm, mm["mint_a"], mprog(mm["mint_a"])),
              ata_of(Fm, mm["mint_b"], mprog(mm["mint_b"])), mm["mint_a"], mm["mint_b"]]
        run("BB-F03 swapExactIn on a market with a FRESH oracle (contrast)",
            [swap(2, Fm, 1_000_000, mm["mint_a"] == WSOL)], wf,
            "same code path, non-expired oracle")
    # aliasing: swapper's input account := the market vault itself
    run("BB-F04 swapExactIn with authorityA aliased onto the market vault",
        [swap(2, st, 1_000_000, True, dup_src_into_vault=True)], watch,
        "duplicate/aliased mutable account")
    # empty-oracle market (never updated, reserves zero)
    empty = [m for m in MARKETS if m.get("sequence") == 0 and m.get("valid_until") == 0]
    if empty:
        e0 = empty[0]["address"]
        mm = empty[0]
        run("BB-F05 swapExactIn on a never-initialized (empty oracle) market",
            [swap(2, e0, 1_000_000, True)], [A, u_wsol, u_usdc, e0], "OracleData::Empty path")
    # wrong mint order (swap claims token A is actually token B)
    run("BB-F06 swapExactIn with is_token_a flag inconsistent with the funded account",
        [swap(2, st, 1_000_000, not (S["mint_a"] == WSOL))], watch, "flag/mint mismatch")
    # token program substitution for mintB
    run("BB-F07 swapExactIn with mintB token program replaced by Token-2022",
        [swap(2, st, 1_000_000, True, prog_b=F.TOKEN22)], watch, "pinning")

    # ============ attacker-owned synthetic market: full lifecycle accounting ============
    mid = 0x4f434101
    market = str(Pubkey.find_program_address([b"market", struct.pack("<I", mid)], F.pk(BB))[0])
    va, vb = ata_of(market, WSOL, F.TOKEN), ata_of(market, USDC, F.TOKEN)
    init = Instruction(F.pk(BB), bytes([8]) + struct.pack("<I", mid), [
        M(A, w=True, s=True), M(market, w=True), M(WSOL), M(USDC), M(va, w=True), M(vb, w=True),
        M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(F.TOKEN)])
    print("\nsynthetic market pda:", market)
    run("BB-F08 marketInitialize by the attacker (permissionless create)", [init], [A, market, va, vb],
        "does the program let any wallet create a market it controls?")
    mv_snap = snap(market)
    if mv_snap and mv_snap.get("market"):
        print("   created market state:", json.dumps(mv_snap["market"]))
        watch2 = [A, u_wsol, u_usdc, market, va, vb, WSOL, USDC]

        def liq(tag, aa, ab):
            return Instruction(F.pk(BB), bytes([tag]) + struct.pack("<QQ", aa, ab), [
                M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
                M(u_wsol, w=True), M(u_usdc, w=True), M(va, w=True), M(vb, w=True),
                M(F.TOKEN), M(F.TOKEN), M(F.MEMO)])

        run("BB-F09 deposit 50 WSOL + 50 USDC into the attacker's own market",
            [liq(10, 50_000_000_000, 50_000_000)], watch2, "legitimate funded deposit (self-owned market)")
        run("BB-F10 oracleUpdate by the attacker (attacker is the market's updater)",
            [Instruction(F.pk(BB), bytes([1]) + struct.pack("<QQ", 1, F.get_slot() + 1000) +
                         bytes([1]) + struct.pack("<Q", 1 << 64) + bytes(448) + bytes(32),
             [M(market, w=True), M(A, s=True)])], watch2,
            "flat price 1.0 (Q64.64 1<<64) for WSOL/USDC units")
        run("BB-F11 swapExactIn 1 WSOL against the synthetic market",
            [swap(2, market, 1_000_000_000, True)], watch2, "measured payout vs the posted price")
        run("BB-F12 swapExactOut 1 USDC", [swap(3, market, 1_000_000, False)], watch2, "exact-out accounting")
        run("BB-F13 withdraw more than reserves (reserve/vault divergence probe)",
            [liq(11, 10 ** 15, 10 ** 15)], watch2, "must be bounded by reserves")
        run("BB-F14 close with non-zero reserves (state gate)", [Instruction(F.pk(BB), bytes([12]), [
            M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
            M(va, w=True), M(vb, w=True), M(u_wsol, w=True), M(u_usdc, w=True),
            M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(F.TOKEN)])], watch2,
            "close gate: reserves must be zero; where do the market lamports go?")
        run("BB-F15 withdraw all, then close (legit lifecycle)",
            [liq(11, snap(market)["market"]["reservesA"], snap(market)["market"]["reservesB"])], watch2,
            "does the withdraw pay out exactly the reserves?")
        mkt_after = snap(market)
        print("   market after withdraw:", json.dumps(mkt_after.get("market")))
        if mkt_after and mkt_after.get("market"):
            ra, rb = mkt_after["market"]["reservesA"], mkt_after["market"]["reservesB"]
            run("BB-F16 close now that reserves are zero", [Instruction(F.pk(BB), bytes([12]), [
                M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
                M(va, w=True), M(vb, w=True), M(u_wsol, w=True), M(u_usdc, w=True),
                M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(F.TOKEN)])], watch2,
                "close transfers the market PDA lamports to the authority")
        # divergence: does the program trust stored reserves over the vault balance?
        va_now = snap(va)
        print("   vault A balance vs reserves:", json.dumps({"vaultA": (va_now or {}).get("tokenAmount"),
                                                             "market": (mkt_after or {}).get("market")}))
    json.dump({"forkSlotEnd": F.get_slot(), "results": RESULTS,
               "fundingNote": "attacker's own WSOL/USDC test balances set by fork cheatcode; "
                              "no protocol-owned balance was fabricated",
               "marketClassification": {"stale": [m["address"] for m in stale],
                                        "fresh": [m["address"] for m in fresh]}},
              open("/home/user/orca-audit/evidence/BBF_swap_guards.json", "w"), indent=1)
    print("\nsaved evidence/BBF_swap_guards.json")


if __name__ == "__main__":
    main()
