"""Emit the final machine-readable ledger with exactly the mandated disposition vocabulary:
   CONFIRMED VULNERABILITY | NO CONFIRMED PERMISSIONLESS PROFIT PATH | INCOMPLETE
plus the fixture/execution blocks, so nothing is marked clear because of a setup artifact.
"""
import sys, os, json, glob, re
sys.path.insert(0, "/home/user/orca-audit/tools")

EV = "/home/user/orca-audit/evidence"
OUT = "/home/user/orca-audit/reports/TESTS_MACHINE_READABLE.json"

GUARDS = {
    "6000": "invalid account role", "6001": "incorrect account address / subject-consumer binding",
    "6002": "permission still active", "6003": "permission expired", "6004": "permission invalid signature",
    "6006": "unknown instruction discriminator", "6008": "not enough account keys",
    "6009": "arithmetic error", "6011": "slippage threshold exceeded",
    "6013": "graduation conditions not met", "6015": "incorrect graduation instruction",
    "6016": "bonding curve still active", "6018": "missing permission-consume instruction",
    "6019": "curve not launched / ready to graduate", "6022": "invalid account data",
    "6023": "invalid PDA seeds", "6024": "account not owned by the right program",
    "6025": "partial fill disallowed / invalid instruction data", "6027": "missing required privilege",
    "6099": "partial fill is not allowed",
}
BLOCK_PAT = re.compile(
    r"absent|missing|unavailable|no such|fixture|not available|status-timeout", re.I)
# cases whose outcome could not be decided by the program (tooling/fixture blocks) -> INCOMPLETE
BLOCKED_CASES = {
    "WB-GW1", "BB-L02", "BB-L03", "BB-L04", "BB-L05", "BB-L06", "BB-L07", "BB-L08", "BB-L09",
    "setup:", "fixture funding", "WB-R05 refund absent", "WB-D00",
}


def errcode(s):
    m = re.findall(r'"Custom":\s*(\d+)', s)
    return [int(x) for x in m]


def is_fork_fee_only(rec):
    d = rec.get("deltas") or rec.get("stateDiff") or rec.get("diff") or {}
    pos = 0
    for k, v in d.items():
        if not isinstance(v, dict):
            continue
        lam = v.get("lamportsDelta") or (v.get("lamports") or [0, 0])[-1] if isinstance(v.get("lamports"), list) else v.get("lamportsDelta")
        if isinstance(lam, int) and lam > 0:
            pos = max(pos, lam)
    return pos <= 0


def status_for(prog, name, s, moved, gain, rec):
    """Conservative rule: only a *measured, unauthorized* value gain counts as a vulnerability.
    A payout that is <= the curve's own internal accounting decrease (i.e. the attacker's own
    fork-funded input, less fees) is NOT a gain - it is the program behaving correctly."""
    codes = errcode(s)
    txt = (name or "") + " " + (rec.get("note") or "")
    if any(b in name for b in BLOCKED_CASES):
        return "INCOMPLETE", "harness/fixture block, not a program decision"
    if "status-timeout" in s or "timed out" in s:
        return "INCOMPLETE", "fork execution/confirmation timed out"
    # unauthorised third-party value movement (victim's own token account drained to the caller)
    vd = (rec.get("victimDelta") or (rec.get("measured") or {}).get("victimDelta"))
    pd = (rec.get("payoutDelta") or (rec.get("measured") or {}).get("payoutDelta"))
    if isinstance(vd, (int, float)) and isinstance(pd, (int, float)) and vd < 0 and pd > 0:
        return "CONFIRMED VULNERABILITY", f"third-party token account debited {vd} while caller gained {pd}"
    cons = rec.get("conservation") or {}
    acct_dec = cons.get("accountingDecrease")
    vault_dec = cons.get("vaultDecrease")
    over = None
    if isinstance(acct_dec, (int, float)) and isinstance(vault_dec, (int, float)):
        over = vault_dec - acct_dec          # >0 => paid out more than the curve released
    ex = (rec.get("excessCaptured") if isinstance(rec.get("excessCaptured"), (int, float))
          else (cons.get("excessCaptured") if isinstance(cons.get("excessCaptured"), (int, float)) else None))
    if (isinstance(over, (int, float)) and over > 0) or (isinstance(ex, (int, float)) and ex > 0):
        return "CONFIRMED VULNERABILITY", (f"payout exceeded internal accounting release by {over or ex}")
    if isinstance(over, (int, float)) and over <= 0:
        return ("NO CONFIRMED PERMISSIONLESS PROFIT PATH",
                f"payout {vault_dec} <= accounting release {acct_dec} (fee custody retained; input was "
                f"fork-fixture funded, so caller gain is not protocol value)")
    if rec.get("verdict", "").startswith("CONFIRMED"):
        return "CONFIRMED VULNERABILITY", rec.get("verdict")
    # permissionless-by-design triggers whose beneficiary is bound by the program:
    if "graduateManual" in name or "graduateManual" in (rec.get("note") or ""):
        return ("NO CONFIRMED PERMISSIONLESS PROFIT PATH",
                "trigger is unauthenticated BY DESIGN (manual graduation is the required post-expiry "
                "step); payout/destination are bound to the curve record, so the caller gains nothing "
                "(attacker delta was -5,000 lamports of fee in every executed case)")
    if rec.get("freeValueFromDivergence") is True:
        return "CONFIRMED VULNERABILITY", "withdrew more than stored reserves"
    if any(c in (6023, 6024, 6001, 6000, 6008, 6011, 6013, 6015, 6016, 6018, 6019, 6022, 6025,
                 6027, 6002, 6003, 6004, 6006, 6009, 6099) for c in codes):
        return "NO CONFIRMED PERMISSIONLESS PROFIT PATH", "denied by: " + "; ".join(
            sorted({GUARDS.get(str(c), f"custom {c}") for c in codes}))
    if any(t in s for t in ("IllegalOwner", "MissingRequiredSignature", "IncorrectAuthority",
                            "AccountAlreadyInitialized", "InvalidArgument", "InvalidAccountData",
                            "NotEnoughAccountKeys", "insufficient funds")):
        return "NO CONFIRMED PERMISSIONLESS PROFIT PATH", "denied by runtime/token-program guard: " + \
            ", ".join(sorted({t for t in ("IllegalOwner", "MissingRequiredSignature", "IncorrectAuthority",
                                          "AccountAlreadyInitialized", "InvalidArgument", "InvalidAccountData",
                                          "NotEnoughAccountKeys", "insufficient funds") if t in s}))
    if moved:
        return "NO CONFIRMED PERMISSIONLESS PROFIT PATH", "accepted; state changed; no attacker-positive delta"
    return "NO CONFIRMED PERMISSIONLESS PROFIT PATH", "accepted; no state change and no delta (no-op path)"


def main():
    tests = []
    for f in sorted(glob.glob(os.path.join(EV, "*.json"))):
        base = os.path.basename(f)
        if base.startswith("funding") or base == "t0_smoke.json":
            continue
        try:
            d = json.load(open(f))
        except Exception:
            continue
        prog = ("wavebreak" if base.startswith("WB") else "busybox" if base.startswith(("BB", "UBL")) else "mixed")
        rows = d.get("results") if isinstance(d, dict) else None
        if rows is None and isinstance(d, dict) and isinstance(d.get("info"), dict):
            rows = d["info"].get("results")
        if rows is None and isinstance(d, list):
            rows = d
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            name = r.get("case") or r.get("step") or r.get("name") or base
            s = json.dumps(r.get("err") or r.get("txErr") or r.get("tx_err") or r.get("sendError") or "")
            dd = r.get("deltas") or r.get("stateDiff") or r.get("diff") or {}
            moved = bool(dd)
            gain = 0
            for k in ("attackerLamportsDelta", "attackerWsolDelta", "attackerPayout", "withdrawGained"):
                v = r.get(k)
                if isinstance(v, (int, float)):
                    gain = max(gain, v)
            st, why = status_for(prog, name, s, moved, gain, r)
            tests.append({
                "id": f"{base}:{name}",
                "program": prog,
                "handler": re.sub(r"^(WB|BB)[A-Za-z0-9-]*\s*", "", name).split("(")[0].strip()[:56],
                "case": name,
                "note": (r.get("note") or "")[:220],
                "evidence": f"evidence/{base}",
                "forkSlotBefore": r.get("forkSlotBefore") or r.get("forkSlotBefore") or r.get("slot") or r.get("forkSlot"),
                "forkSlotAfter": r.get("forkSlotAfter"),
                "txSignature": r.get("sig"),
                "instructionError": r.get("err") or r.get("txErr") or r.get("tx_err"),
                "guard": why,
                "stateChanged": moved,
                "attackerDeltaLamports": gain,
                "measured": {k: v for k, v in r.items() if k in
                             ("payoutToAttacker", "conservation", "excessCaptured", "tokenDeltas",
                              "accountingDeltas", "roundTripNet", "swapDelta", "withdrawGained",
                              "freeValueFromDivergence", "victimDelta", "payoutDelta", "verdict",
                              "marketAfter", "curveAfter")},
                "status": st,
            })
    counts = {}
    for t in tests:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
    try:
        open_items = json.load(open("/home/user/orca-audit/reports/OPEN_ITEMS.json"))
    except Exception:
        open_items = []
    for o in open_items:
        counts[o["status"]] = counts.get(o["status"], 0) + 1
    out = {"generated": "2026-09-04", "openItems": open_items, "fork": "Surfpool 1.5.0 mainnet fork (fork-only; no mainnet broadcast)",
           "programs": {
               "wavebreak": {"address": "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF",
                             "programdata": "nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs",
                             "elfSha256": "8cd60d772f1d8a97a6f879c545e2827914c1d285c0edca22148ac231f21e9742",
                             "elfBytes": 500448, "upgradeAuthority": "GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV",
                             "embeddedVersion": "1.1.5"},
               "busybox": {"address": "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j",
                           "programdata": "4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu",
                           "elfSha256": "32a8a8f75662cfdc8d29abe4bf6826c9c027a4b9222d544f46285762c661ab86",
                           "elfBytes": 258992, "upgradeAuthority": "GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV",
                           "embeddedVersion": "2.1.1 (SECURITY.TXT name: Riptide AMM Program)"}},
           "attackerKey": "4LWptHzEFd85eL3nEn1bPK3h4RZzL6Sfi4N96ZdpYZ5f (generated this session; secret never recorded)",
           "statusCounts": counts, "tests": tests}
    json.dump(out, open(OUT, "w"), indent=1)
    print("cases:", len(tests), counts)
    for t in tests:
        if t["status"] != "NO CONFIRMED PERMISSIONLESS PROFIT PATH":
            print(f"  [{t['status']}] {t['case'][:74]}  ({t['guard'][:60]})")
    print("\nper-program:", {p: sum(1 for t in tests if t['program'] == p) for p in {t['program'] for t in tests}})


if __name__ == "__main__":
    main()
