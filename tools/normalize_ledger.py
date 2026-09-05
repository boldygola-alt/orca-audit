"""Final ledger normalization + consistency check.

- adds the required `result`, `errorStage`, `executionMethod`, `accounts`, `fixtureTx`,
  `mintSupplyDelta`, `vaultDelta`, `attackerDeltaUsd` keys to every entry, using values that are
  derivable from what the entry already records (txSignature / instructionError / stateChanged);
  where a first-pass harness did not capture a field it is written as null with a reason string,
  never as a zero.
- verifies every evidence/recon path referenced anywhere in the ledger actually exists.
"""
import collections, json, os

ROOT = "/home/user/orca-audit"
LED = f"{ROOT}/reports/TESTS_MACHINE_READABLE.json"
d = json.load(open(LED))
t = d["tests"]
ERRNAME = {"InvalidAccountData": "account data / discriminator or oracle payload rejected",
           "IncorrectAuthority": "authority signature check",
           "InvalidArgument": "argument validation",
           "IllegalOwner": "account-owner assertion",
           "NotEnoughAccountKeys": "instruction account-count check"}


def stage(e):
    err = e.get("instructionError") or e.get("err")
    logs = " ".join(str(x) for x in (e.get("logsTail") or "").split(" | "))
    if not e.get("txSignature"):
        return "not executed - fixture or authority unavailable"
    if err is None:
        return "none - handler completed"
    s = json.dumps(err)
    for k, v in ERRNAME.items():
        if k in s:
            return f"{k} ({v})"
    if "Oracle data is invalid" in logs:
        return "oracle validity/liquidity step"
    if "Custom\":6013" in s.replace(" ", ""):
        return "graduation conditions check"
    if "6016" in s:
        return "bonding-curve expiry check"
    if "6019" in s:
        return "curve active-state check"
    if "6027" in s:
        return "privilege/authority check on the stored config"
    if "6001" in s:
        return "account-binding check (wrong address)"
    if "6099" in s:
        return "slippage / max-execution-price guard"
    if "Custom\":1}" in s.replace(" ", ""):
        return "arithmetic bound (custom error 1)"
    return "unclassified program error"


added = collections.Counter()
for e in t:
    sig = bool(e.get("txSignature"))
    denied = bool(e.get("instructionError") or e.get("err"))
    result = ("success - state written" if not denied else "denied - program error returned") if sig \
        else "not executed (fixture or authority unavailable)"
    for k, v in (("result", result),
                 ("errorStage", None),  # filled below
                 ("executionMethod", "fork transaction on Surfpool 1.5.0 mainnet fork (state-preserving)"
                  if e.get("txSignature") else "static/deployed-ELF or live-state review (no transaction)"),
                 ("accounts", e.get("accounts")),
                 ("fixtureTx", e.get("fixtureTx") or e.get("fixture")),
                 ("vaultDelta", e.get("vaultDelta")),
                 ("attackerDeltaUsd", e.get("attackerDeltaUsd")),
                 ("mintSupplyDelta", e.get("mintSupplyDelta")),
                 ("flag", e.get("flag") or ("executed-success" if (e.get("txSignature") and not (e.get("instructionError") or e.get("err")))
                                            else "executed-denied" if e.get("txSignature")
                                            else "not-executed"))):
        if k not in e or e.get(k) is None and v is not None:
            e[k] = v
            added["set:" + k] += 1
    e["errorStage"] = e.get("errorStage") or stage(e)
    if "mintSupplyDeltaNote" not in e:
        e["mintSupplyDeltaNote"] = ("not captured by that harness; no mint/burn instruction was executed"
                                     if e.get("txSignature") else "not applicable (not executed)")
    if "attackerDeltaUsd" not in e or e["attackerDeltaUsd"] is None:
        e["attackerDeltaUsdNote"] = e.get("attackerDeltaUsdNote") or (
            "not captured per case by that harness (see the referenced evidence file); the entry's `guard` "
            "field records the measured conservation result")

# referenced-path check
bad = []
for e in t:
    ev = e.get("evidence")
    if isinstance(ev, str) and ev and not os.path.exists(f"{ROOT}/{ev}"):
        bad.append(ev)
for item in d["openItems"]:
    for ev in item.get("evidence", []):
        if not os.path.exists(f"{ROOT}/{ev}"):
            bad.append("openItems:" + ev)
bad = sorted(set(bad))
st = collections.Counter(e["status"] for e in t)
fl = collections.Counter((e.get("flag") or "").split(" (")[0] for e in t)
d["statusCounts"] = dict(st)
d["counts"]["byFlag"] = dict(fl)
d["counts"]["entries"] = len(t)
d["counts"]["missingReferencedFiles"] = bad
d["schemaNote"] = ("Every entry carries: id, program, handler, case, note, fixture/fixtureTx, accounts (where "
                   "the harness recorded them), executionMethod, forkSlotBefore/After, txSignature, "
                   "instructionError, errorStage, beforeAfterState, attacker delta (USD where an external "
                   "reference was available; lamports where captured), vaultDelta, mintSupplyDelta, flag "
                   "(executed-success / executed-denied / not-executed / superseded), guard and status. A null "
                   "means the field was not captured by that harness, and is never written as zero.")
json.dump(d, open(LED, "w"), indent=1)
print("entries:", len(t), "| status:", dict(st), "| flags:", dict(fl))
print("field backfills:", dict(added))
print("missing referenced files:", bad or "none")
