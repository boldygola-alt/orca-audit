"""WS6 - Busybox/Riptide stale-oracle, frozen-price and penalty sweep (fork-only).

For every funded live market we execute real swaps in both directions against the market's
own stored price, then value both legs with an independent external reference (Jupiter price
API, keyed to a mainnet slot) and report the attacker's net USD PnL.  Sizes are swept so a
guard-limited arbitrage cannot hide behind a too-small probe.

Attacker input balances are created with the fork's own fixture funding (surfnet_setAccount on
the attacker's OWN token accounts) so pricing/penalty code is reached; no protocol balance,
vault, oracle payload or authority state is fabricated.  The funding itself is never treated
as evidence - only the measured exchange rate / net delta is.
"""
import base64, json, os, struct, subprocess, sys, time

sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
import rpc
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
OUT = "/home/user/orca-audit/evidence/BBS2_stale_sweep.json"
actor = F.load_actor()
A = str(actor.pubkey())
RESULTS = []
FUNDING = []


# ---------------------------------------------------------------- market state
def fetch_markets():
    r = rpc.rpc("getProgramAccounts", [BB, {"encoding": "base64", "commitment": "confirmed",
                                            "filters": [{"dataSize": 1024}], "dataSlice": {"offset": 0, "length": 1024}}],
                timeout=120)
    slot = rpc.get_slot()
    ms = []
    for it in r.get("result") or []:
        raw = base64.b64decode(it["account"]["data"][0])
        if raw[0] != 2:
            continue
        m = dict(addr=it["pubkey"], lamports=it["account"]["lamports"], cu_pen=raw[2], imb=raw[3],
                 id=struct.unpack_from("<I", raw, 4)[0],
                 authority=str(Pubkey.from_bytes(raw[8:40])), updater=str(Pubkey.from_bytes(raw[40:72])),
                 mint_a=str(Pubkey.from_bytes(raw[72:104])), mint_b=str(Pubkey.from_bytes(raw[104:136])),
                 seq=struct.unpack_from("<Q", raw, 136)[0], valid_until=struct.unpack_from("<Q", raw, 144)[0],
                 oracle=raw[152:664], min_spread=struct.unpack_from("<i", raw, 664)[0],
                 arb_pen=struct.unpack_from("<I", raw, 668)[0], jit=struct.unpack_from("<I", raw, 672)[0],
                 minO=int.from_bytes(raw[688:704], "little"), maxO=int.from_bytes(raw[704:720], "little"),
                 skew_min=struct.unpack_from("<i", raw, 720)[0], skew_max=struct.unpack_from("<i", raw, 724)[0],
                 maxA=struct.unpack_from("<I", raw, 728)[0], maxB=struct.unpack_from("<I", raw, 732)[0],
                 resA=struct.unpack_from("<Q", raw, 736)[0], resB=struct.unpack_from("<Q", raw, 744)[0])
        m["variant"] = raw[152]
        m["stale_by"] = slot - m["valid_until"]
        m["oracle_hex"] = m.pop("oracle").hex()
        ms.append(m)
    return slot, ms


_MEMI = {}


def _acc(mint):
    if mint not in _MEMI:
        v = None
        for ep in rpc.MAINNET_ENDPOINTS:
            r = rpc.rpc("getAccountInfo", [mint, {"encoding": "base64"}], url=ep, timeout=12)
            if isinstance(r, dict) and "result" in r:
                v = r["result"]["value"]
                break
        _MEMI[mint] = v
    return _MEMI[mint]


def prog_of(mint):
    return (_acc(mint) or {}).get("owner") or F.TOKEN


def dec_of(mint):
    v = _acc(mint)
    return base64.b64decode(v["data"][0])[44] if v else 6


def ata_of(owner, mint, prog):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def token_bal(addr):
    v = F.get_account(addr)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    if len(raw) < 72:
        return None
    return struct.unpack_from("<Q", raw, 64)[0]


# ---------------------------------------------------------------- external prices
def jup_prices(mints):
    prices, slot_ref = {}, None
    ms = sorted(mints)
    for i in range(0, len(ms), 2):
        batch = ms[i:i + 4]
        try:
            import urllib.request
            u = "https://lite-api.jup.ag/price/v3?ids=" + ",".join(batch)
            req = urllib.request.Request(u, headers={"user-agent": "curl/8.5.0", "accept": "application/json"})
            d = json.loads(urllib.request.urlopen(req, timeout=25).read())
            for k, v in d.items():
                if isinstance(v, dict) and v.get("usdPrice"):
                    prices[k] = v["usdPrice"]
                    slot_ref = v.get("blockId", slot_ref)
        except Exception as e:
            print("  price batch err", type(e).__name__, str(e)[:60])
        time.sleep(1.6)
    return prices, slot_ref


# ---------------------------------------------------------------- fixture funding
def fund(ata, amount, owner_prog):
    v = F.get_account(ata)
    raw = bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q", raw, 64, amount)
    r = rpc.rpc("surfnet_setAccount", [ata, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                             "owner": owner_prog, "executable": False}], url=F.FORK)
    FUNDING.append({"ata": ata, "amount": amount, "owner": owner_prog, "why":
                    "fork-only fixture funding of the attacker's OWN account so the swap path is "
                    "reached; not protocol state, not exploit evidence", "result": "error" not in r})
    return "error" not in r


def swap_ix(mkt, m, amount, is_a, partial=0, sl=None, tag=2):
    pa, pb = m["prog_a"], m["prog_b"]
    data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
    data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<Q", sl[0]) if isinstance(sl, tuple)
                                          else bytes([2]) + struct.pack("<Q", sl))
    data += bytes([partial])
    return Instruction(F.pk(BB), data, [
        F.AM(A, True, True), F.AM(m["addr"], True),
        F.AM(m["mint_a"], True), F.AM(m["mint_b"], True),
        F.AM(m["u_a"], True), F.AM(m["u_b"], True),
        F.AM(m["mv_a"], True), F.AM(m["mv_b"], True),
        F.AM(pa), F.AM(pb), F.AM(F.MEMO), F.AM(F.IX_SYSVAR)])


def run(name, ixs, watch, note="", extra=None):
    before = {a: token_bal(a) for a in watch}
    mb = None
    for a in watch:
        v = F.get_account(a)
        if v and v["space"] == 1024:
            raw = base64.b64decode(v["data"][0])
            mb = dict(resA=struct.unpack_from("<Q", raw, 736)[0], resB=struct.unpack_from("<Q", raw, 744)[0],
                      seq=struct.unpack_from("<Q", raw, 136)[0], vu=struct.unpack_from("<Q", raw, 144)[0])
    sb = F.get_slot()
    r = F.send(ixs, actor, tries=25)
    after = {a: token_bal(a) for a in watch}
    ma = None
    for a in watch:
        v = F.get_account(a)
        if v and v["space"] == 1024:
            raw = base64.b64decode(v["data"][0])
            ma = dict(resA=struct.unpack_from("<Q", raw, 736)[0], resB=struct.unpack_from("<Q", raw, 744)[0],
                      seq=struct.unpack_from("<Q", raw, 136)[0], vu=struct.unpack_from("<Q", raw, 144)[0])
    det = r.get("detail", {}) or {}
    logs = [l.strip() for l in (det.get("logs") or [])]
    deltas = {a: ((after.get(a) or 0) - (before.get(a) or 0)) for a in watch
              if after.get(a) is not None and before.get(a) is not None and after[a] != before[a]}
    rec = dict(case=name, note=note, forkSlotBefore=sb, forkSlotAfter=F.get_slot(), sig=r.get("result"),
               err=det.get("err") or r.get("error"), instructionError=(det.get("meta") or {}).get("err"),
               logs=[l for l in logs if "log:" in l or "failed" in l or "consumed" in l][-14:],
               tokenDeltas=deltas, marketBefore=mb, marketAfter=ma, before=before, after=after)
    if extra:
        rec.update(extra)
    RESULTS.append(rec)
    print(f"\n### {name}")
    print("   err:", json.dumps(rec["err"])[:150], "| sig:", (rec["sig"] or "-")[:24])
    print("   deltas:", json.dumps(deltas)[:300])
    if mb and ma:
        print("   market:", {k: (mb[k], ma[k]) for k in mb if mb[k] != ma[k]})
    print("   tail:", " | ".join(rec["logs"][-3:])[:220])
    return rec


def ensure_atas(markets):
    seen = set()
    for m in markets:
        for mn, at, pg in ((m["mint_a"], m["u_a"], m["prog_a"]), (m["mint_b"], m["u_b"], m["prog_b"])):
            if (mn, pg) in seen:
                continue
            seen.add((mn, pg))
            if F.get_account(at) is not None:
                continue
            _, ixx = F.create_ata(A, mn, pg, A)
            F.send([ixx], actor, tries=20)
            print("  created ata", mn[:10], at[:10], flush=True)


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    slot, ms = fetch_markets()
    print("mainnet slot", slot, "markets", len(ms), flush=True)
    funded = [m for m in ms if m["resA"] > 0 and m["resB"] > 0]
    print("funded markets:", len(funded), flush=True)
    mints = set()
    for m in funded:
        mints |= {m["mint_a"], m["mint_b"]}
    prices, pref = jup_prices(mints)
    print("external price reference (jupiter) at slot", pref, "priced mints:", len(prices), "/", len(mints))
    mints_all = set()
    for m in ms:
        mints_all |= {m["mint_a"], m["mint_b"]}
    for mn in sorted(mints_all):
        _acc(mn)
        print("  mint", mn[:10], prog_of(mn)[:12], "dec", dec_of(mn), flush=True)
    for m in ms:
        m["prog_a"], m["prog_b"] = prog_of(m["mint_a"]), prog_of(m["mint_b"])
        m["mv_a"], m["mv_b"] = ata_of(m["addr"], m["mint_a"], m["prog_a"]), ata_of(m["addr"], m["mint_b"], m["prog_b"])
        m["u_a"], m["u_b"] = ata_of(A, m["mint_a"], m["prog_a"]), ata_of(A, m["mint_b"], m["prog_b"])
    # ensure our ATAs exist on the fork (only for the markets we will actually trade)
    ensure_atas(funded)
    json.dump({"prices": prices, "jupSlot": pref}, open("/home/user/orca-audit/recon/s4_bb_prices.json", "w"), indent=1)

    def usd(mint, amt):
        p = prices.get(mint)
        if p is None:
            return None
        return amt / (10 ** m_dec[mint]) * p

    m_dec = {mn: dec_of(mn) for mn in mints}

    # ---- A) stale/expired oracle gate: markets whose stored validUntil is already in the past
    expired = [m for m in ms if m["stale_by"] > 0]
    print("\n=== expired markets (validUntil in the past):", [(m['addr'][:10], m['variant'], m['stale_by'], m['resA'], m['resB']) for m in expired])
    ensure_atas([m for m in expired if m["resA"] > 0 and m["resB"] > 0])
    for m in expired:
        if m["resA"] <= 0 or m["resB"] <= 0:
            continue
        give = max(1, m["resB"] // 1000)
        fund(m["u_b"], (token_bal(m["u_b"]) or 0) + give, m["prog_b"])
        # lamport balance of the actor is tracked separately (not a token account)
        run(f"BB-S01 swap on EXPIRED-oracle market {m['addr'][:10]} (var{m['variant']}, expired by {m['stale_by']} slots)",
            [swap_ix(m["addr"], m, give, False)], [A, m["addr"], m["u_a"], m["u_b"], m["mv_a"], m["mv_b"]],
            "does the swap path enforce check_oracle_validity (current_slot > valid_until)?",
            extra={"market": m})

    # ---- B) every funded market, both directions, several sizes
    for m in funded:
        if only and only not in m["addr"]:
            continue
        tagbase = f"BB-SW {m['addr'][:10]} var{m['variant']} resA={m['resA']:,}/resB={m['resB']:,} staleBy={m['stale_by']:,}"
        recs = []
        for is_a, frac in [(True, 0.01), (True, 0.05), (True, 0.25), (False, 0.01), (False, 0.05), (False, 0.25)]:
            give_res = m["resA"] if is_a else m["resB"]
            take_res = m["resB"] if is_a else m["resA"]
            give = max(1, int(give_res * frac))
            at, prog = (m["u_a"], m["prog_a"]) if is_a else (m["u_b"], m["prog_b"])
            have = token_bal(at) or 0
            if have < give:
                fund(at, give - have + 1, prog)
            r = run(f"{tagbase} | exact-in {'A' if is_a else 'B'} {frac*100:g}% ({give:,})",
                    [swap_ix(m["addr"], m, give, is_a)], [A, m["addr"], m["u_a"], m["u_b"], m["mv_a"], m["mv_b"]],
                    "realized exchange rate vs external reference price", extra={"market_addr": m["addr"]})
            din = -(r["tokenDeltas"].get(at, 0))
            outat = m["u_b"] if is_a else m["u_a"]
            dout = r["tokenDeltas"].get(outat, 0)
            v_in = usd(m["mint_a"] if is_a else m["mint_b"], din) if din > 0 else None
            v_out = usd(m["mint_b"] if is_a else m["mint_a"], dout) if dout > 0 else None
            pnl = None if (v_in is None or v_out is None) else v_out - v_in
            r["measured"] = dict(amount_in=din, amount_out=dout, usd_in=v_in, usd_out=v_out, net_usd=pnl,
                                 rate_out_per_in=(dout / din if din else None),
                                 reserve_rate=(m["resB"] / m["resA"]) if m["resA"] else None)
            recs.append(r)
            if r["err"]:
                break
        # ---- C) composed round trip in ONE tx (state carry-over inside the tx)
        last_ok = [r for r in recs if not r["err"]]
        if last_ok:
            g = max(1, m["resA"] // 200)
            fund(m["u_a"], (token_bal(m["u_a"]) or 0) + g, m["prog_a"])
            run(f"{tagbase} | ROUND TRIP A->B->A in one tx (exact-in {g:,} then exact-out {g:,} A)",
                [swap_ix(m["addr"], m, g, True), swap_ix(m["addr"], m, g, True, partial=1, tag=3)],
                [A, m["addr"], m["u_a"], m["u_b"], m["mv_a"], m["mv_b"]],
                "second leg is exact-out for the same token A amount: measures the round-trip cost and any carry-over edge",
                extra={"market_addr": m["addr"]})
    # ---- D) controlled expiry-gate test on live state: identical instruction, before and after
    #         the market's own validUntil passes the fork slot.  No oracle is written, no key is
    #         borrowed: we simply wait for the fork clock to overtake the stored expiry.
    # Pick the funded market whose own validUntil the fork clock overtakes soonest: the only
    # way to cross a real oracle expiry without editing state, balances or keys.
    tgt, best = None, None
    now = F.get_slot()
    for m in funded:
        if m["variant"] not in (3, 4) or m["resA"] < 10 ** 9 or m["resB"] < 10 ** 9:
            continue
        d = m["valid_until"] - now
        if 0 < d < 6000 and (best is None or d < best):
            tgt, best = m, d
    if tgt:
        give = max(1, tgt["resA"] // 200)
        fund(tgt["u_a"], (token_bal(tgt["u_a"]) or 0) + give, tgt["prog_a"])
        ctrl = run(f"BB-EXP control: swap on {tgt['addr'][:10]} while slot <= validUntil ({tgt['valid_until']})",
                   [swap_ix(tgt["addr"], tgt, give, True)],
                   [A, tgt["addr"], tgt["u_a"], tgt["u_b"], tgt["mv_a"], tgt["mv_b"]],
                   "identical instruction used again after the fork slot passes validUntil",
                   extra={"market_addr": tgt["addr"]})
        fs = F.get_slot()
        print(f"\n  fork slot {fs}; market {tgt['addr'][:10]} validUntil {tgt['valid_until']} "
              f"-> crossing in ~{best} slots (~{int(best*0.4)}s); mainnet scan slot {slot}", flush=True)
        json.dump({"mainnetSlotAtScan": slot, "externalPriceSlot": pref, "prices": prices,
                   "cases": RESULTS, "funding": FUNDING,
                   "note": "partial dump: written before the controlled expiry-gate wait"},
                  open(OUT, "w"), indent=1)
        waited = 0
        while F.get_slot() <= tgt["valid_until"] and waited < 3000:
            time.sleep(15); waited += 15
        print(f"  fork slot now {F.get_slot()} (waited {waited}s)", flush=True)
        fund(tgt["u_a"], (token_bal(tgt["u_a"]) or 0) + give, tgt["prog_a"])
        after = run(f"BB-EXP after: same swap on {tgt['addr'][:10]} at slot > validUntil ({tgt['valid_until']})",
                    [swap_ix(tgt["addr"], tgt, give, True)],
                    [A, tgt["addr"], tgt["u_a"], tgt["u_b"], tgt["mv_a"], tgt["mv_b"]],
                    "oracle-expiry guard enforcement test (controlled by the fork clock, not by state edits)",
                    extra={"market_addr": tgt["addr"], "controlSig": ctrl.get("sig")})
        verdict = ("expiry gate ENFORCED (identical instruction rejected once slot > validUntil)"
                   if ctrl.get("err") is None and after.get("err")
                   else ("expiry gate NOT enforced" if after.get("err") is None else "inconclusive (both failed)"))
        RESULTS.append({"case": "BB-EXP meta", "forkSlotBefore": fs, "forkSlotAfter": F.get_slot(),
                        "validUntil": tgt["valid_until"], "controlErr": ctrl.get("err"),
                        "afterExpiryErr": after.get("err"),
                        "slotsPastValidUntilAtProbe": after.get("forkSlotAfter", F.get_slot()) - tgt["valid_until"],
                        "market": tgt["addr"], "controlSig": ctrl.get("sig"),
                        "afterSig": after.get("sig"), "verdict": verdict})
    summary = []
    for r in RESULTS:
        mm = r.get("measured")
        if mm:
            summary.append((r["case"][:70], mm.get("net_usd"), mm.get("amount_in"), mm.get("amount_out")))
    print("\n=== SUMMARY (net_usd, in, out)")
    for s in summary:
        print("   ", s)
    json.dump({"mainnetSlotAtScan": slot, "externalPriceSlot": pref, "prices": prices,
               "funding": FUNDING, "results": RESULTS}, open(OUT, "w"), indent=1)
    print("\nwrote", OUT)


if __name__ == "__main__":
    main()
