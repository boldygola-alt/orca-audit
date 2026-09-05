"""WS7: full authority-event history for GwH3Hiv5.. / 23zF9Azp.. (public RPC).

Pages getSignaturesForAddress (1000/call) back as far as the endpoint serves, then
fetches each transaction and records: slot, blockTime, the instruction program set,
and every BPFLoader-Upgradeable instruction (with the ProgramData/Program account it
targets and the new-authority value if the instruction is a setAuthority).

Purpose: enumerate every program/ProgramData this authority root has ever deployed,
re-upgraded, locked or delegated -- the only public-RPC way to bound "did the deployer
put any OTHER value-holding program under this root". Results go to
recon/s4_auth_walk_<tag>.json. No fork mutations, no signing: read-only.
"""
import json, sys, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import rpc
from solders.pubkey import Pubkey

BPF = "BPFLoaderUpgradeab1e1111111111111111111111111111111"
SQUADS = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"
# BPFLoaderUpgradeable instruction enum: 0 init, 1 deployWithMaxDataLen, 2 upgrade,
# 3 setAuthority, 4 closeAccount, 5 deployWithBuffer, 6 extendProgram(?)
NAMES = {0: "initBuffer", 1: "deployWithMaxDataLen", 2: "upgrade", 3: "setAuthority",
         4: "closeBuffer", 5: "deployWithBuffer", 6: "setAuthorityChecked?", 7: "extendProgram?"}
EP = "https://solana-mainnet.rpc.extrnode.com"   # placeholder replaced below


def call(method, params, tries=3):
    for ep in rpc.MAINNET_ENDPOINTS:
        for t in range(tries):
            try:
                r = rpc.rpc(method, params, url=ep, tries=1, timeout=40)
                if isinstance(r, dict) and "result" in r:
                    return r["result"]
            except Exception:
                time.sleep(0.5)
    return None


def main(auth_addr):
    tag = auth_addr[:8]
    sigs, before = [], None
    for page in range(12):
        p = {"limit": 1000, "commitment": "finalized"}
        if before:
            p["before"] = before
        res = call("getSignaturesForAddress", [auth_addr, p])
        if not res:
            print(f"  page {page}: nothing back; stopping", flush=True)
            break
        sigs += [r for r in res]
        print(f"  page {page}: +{len(res)} (total {len(sigs)}) oldest slot {res[-1].get('slot')}", flush=True)
        if len(res) < 1000:
            break
        before = res[-1]["signature"]
    sigs.sort(key=lambda r: r.get("slot", 0))
    out = {"authority": auth_addr, "sigCount": len(sigs), "slotRange": [sigs[0]["slot"], sigs[-1]["slot"]]
           if sigs else None, "events": [], "programDataSeen": {}, "programsSeen": {}}
    for i, r in enumerate(sigs):
        tx = call("getTransaction", [r["signature"], {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
        if tx is None:
            out["events"].append({"sig": r["signature"], "slot": r.get("slot"), "unavailable": True})
            continue
        msg = tx.get("transaction", {}).get("message", {})
        keys = [k["pubkey"] for k in msg.get("accountKeys", [])]
        prog = set()
        for ci in msg.get("instructions", []):
            pid = ci.get("programId")
            prog.add(pid)
            if pid == BPF:
                dat = ci.get("data")
                ty = ci.get("programId") and ci.get("data")
                d = dat if isinstance(dat, list) else ci.get("parsed", {}).get("info", {}).get("data") if isinstance(ci.get("parsed"), dict) else None
                tag_id = None
                if isinstance(d, list) and d:
                    raw = base64.b64decode(d[0])
                    tag_id = raw[0] if raw else None
                # jsonParsed gives `type` for known programs
                ptype = ci.get("parsed", {}).get("type") if isinstance(ci.get("parsed"), dict) else None
                info = ci.get("parsed", {}).get("info", {}) if isinstance(ci.get("parsed"), dict) else {}
                accounts = [a.get("pubkey") for a in info.get("accounts", [])] if isinstance(info.get("accounts"), list) else []
                new_auth = info.get("newAuthority")
                rec = {"sig": r["signature"], "slot": r.get("slot"), "time": tx.get("blockTime"),
                       "bpfType": ptype or NAMES.get(tag_id, f"tag{tag_id}"),
                       "accounts": accounts[:8], "newAuthority": new_auth,
                       "keys": keys}
                out["events"].append(rec)
                for a in accounts:
                    if a in keys:
                        continue
                    out["programDataSeen"][a] = out["programDataSeen"].get(a, 0) + 1
            elif pid == SQUADS:
                info = ci.get("parsed", {}).get("info", {}) if isinstance(ci.get("parsed"), dict) else {}
                out["events"].append({"sig": r["signature"], "slot": r.get("slot"), "time": tx.get("blockTime"),
                                      "squadsType": ci.get("parsed", {}).get("type") if isinstance(ci.get("parsed"), dict) else None,
                                      "accounts": [a.get("pubkey") for a in info.get("accounts", [])][:8] if isinstance(info.get("accounts"), list) else []})
        for k in keys:
            if k not in (BPF, SQUADS, "ComputeBudget111111111111111111111111", "1111111111111111111111111111111111111111111111111111111"):
                out["programsSeen"][k] = out["programsSeen"].get(k, 0) + 1
        if i % 100 == 0:
            json.dump(out, open(f"recon/s4_auth_walk_{tag}.json", "w"), indent=1)
            print(f"  [{i}/{len(sigs)}] events={len(out['events'])} progData={len(out['programDataSeen'])}", flush=True)
    json.dump(out, open(f"recon/s4_auth_walk_{tag}.json", "w"), indent=1)
    print(f"done: {len(out['events'])} events, {len(out['programDataSeen'])} programdata targets", flush=True)


if __name__ == "__main__":
    main(sys.argv[1])
