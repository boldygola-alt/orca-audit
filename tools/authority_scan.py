"""Workstream F: classify every transaction signed by a deployer-family authority key.

Read-only. Writes JSONL progress so it can run in the background and be resumed.
Classification is by the programs each transaction touches +, for
BPFLoaderUpgradeable instructions, the instruction name from jsonParsed.
"""
import sys, json, os, base64, collections, concurrent.futures as cf, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import rpc

AUTH = {
    "GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV": "shared-upgrade-authority",
    "23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG": "amm-upgrade-authority",
    "BWyVTPPRW7A5kpHM3tNgPhRz6JekR9sL8iFx2o4X1w9C": "wavebreak-authority-config-slot0",
    "8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor": "wavebreak-fee-privilege",
    "FEDMRB62snymMLV75sdBCCeEfDM4EVdp3xBXrMSTA2FS": "wavebreak-creator",
}
WL = "BPFLoaderUpgradeab1e11111111111111111111111"


def scan_authority(authority, label, out_path, limit=1000):
    done = set()
    if os.path.exists(out_path):
        for line in open(out_path):
            try:
                done.add(json.loads(line)["signature"])
            except Exception:
                pass
    sigs = []
    before = None
    while len(sigs) < limit:
        params = [authority, {"limit": min(1000, limit - len(sigs)), "until": before}] if before else \
                 [authority, {"limit": min(1000, limit)}]
        r = rpc.rpc("getSignaturesForAddress", params)
        if "result" not in r:
            time.sleep(2); continue
        chunk = r["result"]
        if not chunk:
            break
        sigs.extend(chunk)
        before = chunk[-1]["signature"]
        if len(chunk) < params[-1]["limit"]:
            break
    todo = [s for s in sigs if s["signature"] not in done]
    print(f"[{label}] {len(sigs)} signatures, {len(todo)} to fetch", flush=True)
    fh = open(out_path, "a")
    lock_time = time.time()

    def one(s):
        sig = s["signature"]
        tx = rpc.get_tx(sig)
        if tx.get("__absent__"):
            return {"signature": sig, "slot": s.get("slot"), "err": s.get("err"), "absent": True}
        msg = tx.get("transaction", {}).get("message", {})
        progs = collections.Counter()
        ix_names = []
        for ix in msg.get("instructions", []):
            pid = ix.get("programId")
            progs[pid] += 1
            if pid == WL:
                p = ix.get("parsed") or {}
                ix_names.append(p.get("type") or "upgradeable:raw")
                info = p.get("info") or {}
                if info.get("authority") or info.get("upgradeAuthority"):
                    ix_names[-1] += ":" + str(info.get("authority") or info.get("upgradeAuthority"))
            else:
                p = ix.get("parsed") or {}
                t = p.get("type")
                if t:
                    ix_names.append(f"{ix.get('program')}:{t}")
        meta = tx.get("meta") or {}
        inner = 0
        il = collections.Counter()
        for grp in meta.get("innerInstructions") or []:
            for ixx in grp.get("instructions", []):
                inner += 1
                il[ixx.get("programId")] += 1
        return {"signature": sig, "slot": tx.get("slot"), "blockTime": tx.get("blockTime"),
                "err": (meta.get("err") or s.get("err")), "programs": dict(progs),
                "inner_programs": dict(il), "ix": ix_names[:24], "nAccounts": len(msg.get("accountKeys", [])),
                "fee": meta.get("fee"), "label": label}

    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        for rec in ex.map(one, todo):
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
    fh.close()
    print(f"[{label}] done in {time.time()-lock_time:.0f}s", flush=True)


if __name__ == "__main__":
    os.makedirs("/home/user/orca-audit/recon/authority_events", exist_ok=True)
    a = sys.argv[1]
    lim = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    scan_authority(a, AUTH.get(a, a), f"/home/user/orca-audit/recon/authority_events/{a[:8]}.jsonl", lim)
