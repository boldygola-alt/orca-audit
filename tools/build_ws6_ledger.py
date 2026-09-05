"""Build the WS6 ledger entries into reports/TESTS_MACHINE_READABLE.json  (offline: reads
only persisted artifacts, so it stays reproducible after the fork has been shut down).

Each executed fork transaction of the WS6 pass becomes one ledger entry carrying the fields
the engagement requires: id, program, handler, fixture description, fork slots, the exact
account list, execution method, result, error stage, before/after state, attacker delta
(per-leg + net USD against the same-slot external reference), vault delta, mint-supply
delta, and an executed/denied flag.  Account roles are re-derived deterministically from the
recorded market mint bindings (ATA seeds), which reproduces the addresses that were actually
used (verified against the fork copies earlier in the pass, e.g. ata(actor, XsP7xzNPvE...) =
EG1b9ALRx1AV5JGkAJ9em6kHh1kg9u9vNYDSE2ndJSpu).  Counts are recomputed from the entries so the
prose reports cannot drift from the ledger again.
"""
import base64, collections, datetime, json, os, re, struct, sys

ROOT = "/home/user/orca-audit"
sys.path.insert(0, f"{ROOT}/tools")
from solders.pubkey import Pubkey
from solders.keypair import Keypair

A = str(Keypair.from_bytes(bytes(json.load(open(f"{ROOT}/keys/actor_session2.json")))).pubkey())
ATA = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
T4, T22 = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
MEMO, IXSYS = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "Sysvar1nstructions1111111111111111111111111"

# market id -> mint bindings (verified consistent with the fork copies this pass)
_bb = json.load(open(f"{ROOT}/recon/busybox_markets_live.json"))
_bb = _bb if isinstance(_bb, list) else _bb.get("markets")
MKT = {m["address"][:10]: dict(addr=m["address"], mint_a=m["mint_a"], mint_b=m["mint_b"],
                              authority=m["authority"], updater=m["updater"]) for m in _bb}
# mint10 -> (token program, decimals) from the sweep's own account reads
DEC, PRG = {}, {}
for fn in ("s4_sweep2.log", "s4_sweep.log"):
    p = f"{ROOT}/{fn}"
    if not os.path.exists(p):
        continue
    for m in re.finditer(r"mint (\S{10}) (\S{12}) dec (\d+)", open(p).read()):
        DEC[m.group(1)] = int(m.group(3))
        PRG[m.group(1)] = T22 if m.group(2).startswith("Tokenz") else T4


def mintfull(key10, which):
    return MKT[key10][which]


def prog_of(mint):
    return PRG.get(mint[:10], T4)


def dec_of(mint):
    return DEC.get(mint[:10], 6)


def ata(owner, mint):
    return str(Pubkey.find_program_address([bytes(Pubkey.from_string(owner)), bytes(Pubkey.from_string(prog_of(mint))),
                                            bytes(Pubkey.from_string(mint))], Pubkey.from_string(ATA))[0])


def accounts_for(key10):
    m = MKT[key10]
    pa, pb = prog_of(m["mint_a"]), prog_of(m["mint_b"])
    return [
        {"index": 0, "addr": A, "role": "swapper (fresh non-privileged actor keypair)", "writable": True, "signer": True},
        {"index": 1, "addr": m["addr"], "role": 'market PDA ["market", u32le(market_id)]', "writable": True},
        {"index": 2, "addr": m["mint_a"], "role": "mintA"},
        {"index": 3, "addr": m["mint_b"], "role": "mintB"},
        {"index": 4, "addr": ata(A, m["mint_a"]), "role": "swapper token account A", "writable": True},
        {"index": 5, "addr": ata(A, m["mint_b"]), "role": "swapper token account B", "writable": True},
        {"index": 6, "addr": ata(m["addr"], m["mint_a"]), "role": "market vault A (ATA owned by the market PDA)",
         "writable": True},
        {"index": 7, "addr": ata(m["addr"], m["mint_b"]), "role": "market vault B", "writable": True},
        {"index": 8, "addr": pa, "role": "token program for mintA"},
        {"index": 9, "addr": pb, "role": "token program for mintB"},
        {"index": 10, "addr": MEMO, "role": "memo program"},
        {"index": 11, "addr": IXSYS, "role": "instructions sysvar"},
    ]


def err_stage(err, logs, expired):
    s = json.dumps(err or "")
    tail = " ".join(logs[-3:])
    if err is None:
        return "none - handler completed and market/vault state was written"
    if "Oracle data is invalid" in tail:
        return ("oracle step: market.validUntil vs Clock.slot, or an OracleData variant that yields no "
                "liquidity" + (" [executed with slot > stored validUntil]" if expired else ""))
    if "ArithmeticOverflow" in s:
        return "quote math after the oracle step was passed (book-walk overflow)"
    if '"Custom":1}' in s.replace(" ", ""):
        return "quote / penalty math (custom error 1)"
    if "6099" in s:
        return "slippage / max-execution-price guard (custom 6099)"
    if "IllegalOwner" in s:
        return "account-owner assertion before any transfer"
    if "Insufficient" in s or "Insufficient" in tail:
        return "token transfer - actor balance"
    return "unclassified: " + (tail[:120] or s[:120])


def value_legs(key10, deltas, prices):
    m = MKT[key10]
    mine_by = {ata(A, m["mint_a"]): m["mint_a"], ata(A, m["mint_b"]): m["mint_b"]}
    vault_by = {ata(m["addr"], m["mint_a"]): m["mint_a"], ata(m["addr"], m["mint_b"]): m["mint_b"]}
    mine, vault, net, priced = [], [], 0.0, True
    for acct, d in (deltas or {}).items():
        mint = mine_by.get(acct) or vault_by.get(acct)
        if mint is None:
            continue
        dec = dec_of(mint)
        p = prices.get(mint)
        usd = (d / 10 ** dec * p) if p is not None else None
        rec = {"account": acct, "mint": mint, "decimals": dec, "amount": d,
               "referencePriceUsd": p, "usd": round(usd, 4) if usd is not None else None}
        if acct in mine_by:
            mine.append(rec)
            if usd is not None:
                net += usd
            else:
                priced = False
        else:
            vault.append(rec)
    return mine, vault, round(net, 4), priced


def build():
    led = json.load(open(f"{ROOT}/reports/TESTS_MACHINE_READABLE.json"))
    before = len(led["tests"])
    led["tests"] = [e for e in led["tests"] if not re.match(r"BBS[23]-", e.get("id", ""))]
    kept = len(led["tests"])
    print(f"rebuild: dropped {before - kept} prior WS6 entries, keeping {kept}")
    prior = kept
    entries, seq = [], 0
    for fname, runlabel, role in (("evidence/BBS2_stale_sweep.json", "run2", "authoritative"),
                                  ("evidence/BBS2_stale_sweep_parsed.json", "run1", "superseded")):
        path = f"{ROOT}/{fname}"
        if not os.path.exists(path):
            continue
        d = json.load(open(path))
        prices = d.get("prices") or json.load(open(f"{ROOT}/recon/s4_bb_prices.json"))["prices"]
        for c in d["cases"]:
            mm = (re.match(r"BB-SW (\w{10}).*?\| (.*)$", c["case"])
                  or re.match(r"BB-S01 swap on EXPIRED-oracle market (\w{10}) (.*)$", c["case"])
                  or re.match(r"BB-EXP (control|after): swap on (\w{10}) (.*)$", c["case"]))
            if not mm:
                print("   skipped (unparsed case name):", c["case"][:70])
                continue
            seq += 1
            key10, what = mm.group(1), " | ".join(mm.groups()[1:])
            if key10 not in MKT:
                continue
            mb, ma = c.get("marketBefore") or {}, c.get("marketAfter") or {}
            mine, vault, net, priced = value_legs(key10, c.get("tokenDeltas"), prices)
            ok = c.get("err") is None
            expired = bool(mb.get("vu")) and (c.get("forkSlotAfter") or 0) > mb["vu"]
            entries.append({
                "id": f"BBS2-{runlabel}-{seq:03d}",
                "program": "busybox/riptide",
                "handler": "SwapExactIn x2 in one transaction" if "ROUND TRIP" in what else "SwapExactIn (tag 2)",
                "case": f"{key10} | {what}",
                "note": ("permissionless swap against the market's own stored oracle, executed on the fork copy "
                         f"of live mainnet state; role of this run: {role}"),
                "fixture": {"kind": "live mainnet market state as copied by the Surfpool fork at scan slot "
                                    f"{d.get('mainnetSlotAtScan')}; no historical-transaction replay; actor "
                                    "balances exist only because of fork-cheatcode funding of the actor's OWN "
                                    "accounts (documented in evidence/funding_s4_sol.json, never counted as gain)",
                            "externalPriceReference": {"source": "Jupiter price/v3", "slot": d.get("externalPriceSlot"),
                                                       "pricedMints": len(prices)},
                            "replayOf": None},
                "accounts": accounts_for(key10),
                "executionMethod": "fork transaction on Surfpool 1.5.0 mainnet fork (state-preserving, not simulate)",
                "forkSlotBefore": c.get("forkSlotBefore"), "forkSlotAfter": c.get("forkSlotAfter"),
                "txSignature": c.get("sig"), "instructionError": c.get("err"),
                "errorStage": err_stage(c.get("err"), c.get("logs", []), expired),
                "logsTail": " | ".join(c.get("logs", [])[-3:])[:300],
                "beforeAfterState": {"marketFields": {"before": mb, "after": ma},
                                     "tokenBalancesBefore": c.get("before"), "tokenBalancesAfter": c.get("after")},
                "attackerDeltaUsd": (net if (priced and ok and len(mine) >= 2 and role == "authoritative") else None),
                "attackerDeltaUsdRaw": net if priced else None,
                "attackerDeltaUsdNote": (None if (priced and ok and len(mine) >= 2 and role == "authoritative")
                                          else ("denied case: nothing changed hands, so no delta is asserted" if not ok
                                                else "not asserted: superseded run, its only available external "
                                                     "reference came from the authoritative run's slot - the "
                                                     "cross-slot artifact corrected in FINAL_DISPOSITION 3.8"
                                                     if role != "authoritative"
                                                     else "fewer than two actor legs changed hands")),
                "evidence": fname,
                "attackerLegs": mine, "vaultDelta": vault,
                "marketReserveDelta": {"A": ma.get("resA", 0) - mb.get("resA", 0),
                                       "B": ma.get("resB", 0) - mb.get("resB", 0)} if ma else None,
                "executedAfterStoredExpiry": expired,
                "attackerDeltaLamports": None,
                "attackerDeltaLamportsNote": "this harness captured token balances, not lamport deltas; the actor "
                                              "paid only the transaction fee (5,000 lamports per tx) out of "
                                              "fork-only fixture SOL",
                "mintSupplyDelta": None,
                "mintSupplyNote": "SwapExactIn has no mint/burn path; supply untouched by construction, not measured",
                "flag": ("executed-success" if ok else "executed-denied") + ("" if role == "authoritative" else " (superseded)"),
                "guard": (f"accepted at the market's own price; actor net versus the same-slot external reference "
                          f"= {net} USD") if ok else "rejected before any custody moved",
                "status": "NO CONFIRMED PERMISSIONLESS PROFIT PATH",
            })

    dpath = f"{ROOT}/evidence/BBS3_expiry_diff.json"
    if os.path.exists(dpath):
        dd = json.load(open(dpath))
        for i, c in enumerate(dd["cases"], 1):
            entries.append({
                "id": f"BBS3-diff-{i:02d}",
                "program": "busybox/riptide",
                "handler": "SwapExactIn (tag 2)",
                "case": c["case"],
                "note": ("fork-only differential control: exactly one u64 (the market's own oracle validUntil) "
                          "rewritten on the fork copy and then restored, to attribute the rejection to that field "
                          "instead of to the payload. Not a permissionless path: that field is only writable "
                          "through the per-market updater's OracleUpdate. Recorded as a control, never as "
                          "exploit evidence."),
                "fixture": {"kind": "live mainnet market state on the fork + single-field surfnet_setAccount control",
                            "replayOf": None, "verdict": dd.get("verdict")},
                "accounts": None,
                "executionMethod": "fork transaction + surfnet_setAccount single-field control (documented)",
                "forkSlotBefore": c.get("forkSlotBefore"), "forkSlotAfter": c.get("forkSlotAfter"),
                "txSignature": c.get("sig"), "instructionError": c.get("err"),
                "errorStage": err_stage(c.get("err"), c.get("logs", []), c.get("expired")),
                "logsTail": " | ".join(c.get("logs", [])[-3:])[:300],
                "beforeAfterState": {"marketFields": {"before": c.get("marketBefore"), "after": c.get("marketAfter")},
                                     "tokenBalancesBefore": c.get("before"), "tokenBalancesAfter": c.get("after")},
                "attackerDeltaUsd": None, "attackerDeltaLamports": None, "mintSupplyDelta": None,
                "evidence": "evidence/BBS3_expiry_diff.json",
                "flag": "executed-denied (state-edit control)" if c.get("err") else "executed-success (state-edit control)",
                "guard": dd.get("verdict"),
                "status": "NO CONFIRMED PERMISSIONLESS PROFIT PATH",
            })

    led["tests"].extend(entries)
    st = collections.Counter(x["status"] for x in led["tests"])
    fl = collections.Counter((x.get("flag") or "").split(" (")[0] for x in led["tests"])
    prog = collections.Counter(x["program"] for x in led["tests"])
    nets = [e["attackerDeltaUsd"] for e in entries if isinstance(e.get("attackerDeltaUsd"), (int, float))]
    pos = [n for n in nets if n > 0]
    per = collections.defaultdict(list)
    for e in entries:
        if isinstance(e.get("attackerDeltaUsd"), (int, float)):
            per[e["case"].split(" | ")[0]].append(e["attackerDeltaUsd"])
    led["statusCounts"] = dict(st)
    led["counts"] = {
        "entries": len(led["tests"]), "entriesBeforeThisPass": prior, "addedThisPass": len(entries),
        "withTransactionSignature": sum(1 for x in led["tests"] if x.get("txSignature")),
        "withoutTransactionSignature": sum(1 for x in led["tests"] if not x.get("txSignature")),
        "byProgram": dict(prog), "byFlag": dict(fl),
        "ws6": {"executedSwapProbes": len([e for e in entries if e["id"].startswith("BBS2")]),
                "valuedAgainstExternalReference": len(nets), "netPositiveCases": len(pos),
                "maxNetPositiveUsd": max(nets) if nets else 0, "minNetUsd": min(nets) if nets else 0,
                "perMarketNetRangeUsd": {k: [min(v), max(v)] for k, v in sorted(per.items())},
                "stateEditControls": len([e for e in entries if e["id"].startswith("BBS3")])},
        "reconciliation": (
            "Earlier documents disagreed: the ledger held 177 entries while its statusCounts block still read "
            "178 clear + 8 INCOMPLETE, and FINAL_DISPOSITION quoted 177 executed. The 8 INCOMPLETE paths were "
            "never entries in tests[] - they live in openItems. statusCounts is now recomputed from the entries "
            "themselves, unresolved paths are carried only in openItems, and the WS6 re-run of the same probe "
            "set is present but flagged '(superseded)' so dispositions are counted once while executions are "
            "counted as they happened."),
    }
    led["generated"] = datetime.date.today().isoformat()
    led["schemaNote"] = ("Entries from the WS6 pass (BBS2-*, BBS3-*) carry the full field set the engagement "
                         "requires (fixture, exact account list, execution method, error stage, before/after "
                         "state, attacker/vault/mint-supply deltas, flag). Older entries carry the subset their "
                         "harnesses recorded; a null means not captured, never zero.")
    json.dump(led, open(f"{ROOT}/reports/TESTS_MACHINE_READABLE.json", "w"), indent=1)
    summary = {"priorEntries": prior, "added": len(entries), "total": len(led["tests"]),
               "statusCounts": dict(st), "byFlag": dict(fl), "byProgram": dict(prog),
               "valued": len(nets), "netPositive": len(pos), "maxPositiveUsd": max(nets) if nets else 0,
               "minNetUsd": min(nets) if nets else 0, "perMarketNetRangeUsd": {k: [min(v), max(v)]
                                                                              for k, v in sorted(per.items())},
               "sumPositivesUsd": round(sum(pos), 2)}
    json.dump(summary, open(f"{ROOT}/recon/s4_ws6_summary.json", "w"), indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    build()
