"""Build the machine-readable test ledger from every evidence file (fork runs) + the read-only
inventory scans, with a status per case using the mandated vocabulary:
  CONFIRMED VULNERABILITY | NO CONFIRMED PERMISSIONLESS PROFIT PATH | INCOMPLETE
"""
import sys, os, json, glob, hashlib

sys.path.insert(0, "/home/user/orca-audit/tools")
EV = "/home/user/orca-audit/evidence"
OUT = "/home/user/orca-audit/reports/TESTS_MACHINE_READABLE.json"

STATE_DENIALS = ("6000", "6001", "6002", "6003", "6004", "6006", "6008", "6011", "6013", "6015",
                 "6016", "6017", "6018", "6019", "6022", "6023", "6024", "6025", "6026", "6027",
                 "6028", "6099", "IllegalOwner", "MissingRequiredSignature", "NotEnoughAccountKeys",
                 "InvalidArgument", "InvalidAccountData", "IncorrectAuthority", "AccountAlreadyInitialized")


def errstr(e):
    if e is None:
        return ""
    return json.dumps(e)


def classify(rec, program):
    """decide a per-test status from the executed outcome + measured state change"""
    s = errstr(rec.get("err") or rec.get("txErr") or rec.get("tx_err") or rec.get("sendError"))
    deltas = rec.get("deltas") or rec.get("stateDiff") or rec.get("diff") or {}
    moved = bool(deltas) and any(
        (isinstance(v, dict) and (v.get("tokenAmount") or v.get("lamports") or v.get("tokenAmountDelta")
                                   or v.get("lamportsDelta") or v.get("supply") or v.get("supplyDelta")
                                   or v.get("curveFields") or v.get("market")))
        for v in deltas.values())
    attacker_gain = 0
    at = rec.get("attackerLamportsDelta")
    if isinstance(at, (int, float)):
        attacker_gain = at
    for k in ("attackerWsolDelta", "payout", "attackerPayout", "withdrawGained", "freeValueFromDivergence"):
        v = rec.get(k)
        if isinstance(v, dict):
            attacker_gain = max([attacker_gain] + [x for x in v.values() if isinstance(x, (int, float))])
        elif isinstance(v, (int, float)):
            attacker_gain = max(attacker_gain, v)
    cons = rec.get("conservation") or {}
    excess = cons.get("excessCaptured") if isinstance(cons, dict) else None
    if isinstance(rec.get("excessCaptured"), (int, float)):
        excess = rec["excessCaptured"]
    status = None
    if "status-timeout" in s or rec.get("sendError") and "absent" in json.dumps(rec.get("sendError")):
        status = "INCOMPLETE"
    elif isinstance(excess, (int, float)) and excess > 0:
        status = "CONFIRMED VULNERABILITY"
    elif attacker_gain > 5000 and moved:      # more than the 5000-lamport base fee
        status = "CONFIRMED VULNERABILITY"
    elif any(t in s for t in STATE_DENIALS):
        status = "NO CONFIRMED PERMISSIONLESS PROFIT PATH"
    elif not s or s == "null" or s == '""':
        status = "REPLAY-ACCEPTED-NO-DELTA" if not moved else "STATE-CHANGED-NO-ATTACKER-DELTA"
    else:
        status = "DENIED-OTHER"
    return status, moved, attacker_gain, s


def main():
    tests = []
    files = sorted(glob.glob(os.path.join(EV, "*.json")))
    for f in files:
        try:
            d = json.load(open(f))
        except Exception as e:
            print("skip", f, e); continue
        base = os.path.basename(f)
        prog = ("wavebreak" if base.startswith(("WB", "WBF", "WBR", "WBS", "WBC", "WBL", "WBG"))
                else "busybox" if base.startswith(("BB", "UBL")) else "setup")
        rows = []
        if isinstance(d, dict) and isinstance(d.get("results"), list):
            rows = d["results"]
        elif isinstance(d, dict) and isinstance(d.get("log"), list):
            rows = d["log"]
        elif isinstance(d, dict) and isinstance(d.get("info"), dict):
            rows = d["info"].get("results", [])
        elif isinstance(d, list):
            rows = d
        for r in rows:
            if not isinstance(r, dict):
                continue
            name = r.get("case") or r.get("step") or r.get("name") or base
            raw_err = r.get("err") or r.get("txErr") or r.get("tx_err")
            status, moved, gain, s = classify(r, prog)
            tests.append({
                "evidenceFile": f"evidence/{base}",
                "program": prog,
                "test": name,
                "note": (r.get("note") or "")[:200],
                "forkSlotBefore": r.get("forkSlotBefore") or r.get("forkSlot") or r.get("slot"),
                "forkSlotAfter": r.get("forkSlotAfter"),
                "txSignature": r.get("sig"),
                "instructionError": raw_err,
                "programLogTail": [x for x in (r.get("logs") or r.get("programLogs") or [])
                                   if "log:" in x or "failed" in x][:6],
                "stateChanged": moved,
                "attackerPositiveLamports": gain,
                "measured": {k: v for k, v in r.items()
                             if k in ("payoutToAttacker", "attackerWsolDelta", "attackerPayout",
                                      "tokenDeltas", "accountingDeltas", "deltas", "conservation",
                                      "excessCaptured", "roundTripNet", "swapDelta", "withdrawGained",
                                      "freeValueFromDivergence", "reservesAfter", "vaultAfter")},
                "status": status,
            })
    counts = {}
    for t in tests:
        counts[t["status"]] = counts.get(t["status"], 0) + 1
    out = {"generatedAtUtc": "2026-09-04", "harness": "Surfpool 1.5.0 mainnet fork, fork-only; "
           "state-preserving transactions, per-instruction before/after capture",
           "statusCounts": counts, "tests": tests}
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, "w"), indent=1)
    print("tests:", len(tests), counts)
    for t in tests:
        if t["status"] not in ("NO CONFIRMED PERMISSIONLESS PROFIT PATH",):
            print(f"  [{t['status']:38s}] {t['program']:9s} {t['test'][:70]}")


if __name__ == "__main__":
    main()
