"""Fast parallel scan of recent Wavebreak/Busybox transactions -> instruction forms.

Read-only. Produces fixture manifests with every account + raw data, so fork tests use
live-observed forms only (no invented accounts).
"""
import sys, json, base64, collections, concurrent.futures as cf
from base58 import b58decode


def _dec(d):
    """jsonParsed encodes instruction data as base58"""
    if not isinstance(d, str) or not d:
        return b""
    try:
        return b58decode(d)
    except Exception:
        try:
            return base64.b64decode(d)
        except Exception:
            return b""
sys.path.insert(0, "/home/user/orca-audit/tools")
import rpc

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"


def program_ixs(tx, program):
    msg = tx.get("transaction", {}).get("message", {})
    keys = msg.get("accountKeys", [])
    alt = []
    for lk in msg.get("addressTableLookups", []) or []:
        alt.append({"writable": lk.get("writableIndexes", []), "readonly": lk.get("readonlyIndexes", [])})
    out = []
    for i, ix in enumerate(msg.get("instructions", [])):
        pid = ix.get("programId")
        if pid != program:
            continue
        accs = ix.get("accounts", [])
        resolved = None
        if accs and all(isinstance(a, str) for a in accs):
            resolved = accs                      # jsonParsed already gives pubkeys
        else:
            resolved = [keys[i] for i in accs]
        raw = _dec(ix.get("data"))
        out.append({"index": i, "tag": raw[0] if raw else None, "dlen": len(raw),
                    "data_b58": ix.get("data"), "data_hex": raw.hex(), "accounts": resolved,
                    "nAccounts": len(resolved)})
    return keys, out, alt


def scan(program, limit=400, workers=10):
    sigs = [s for s in rpc.sigs_for(program, limit=limit) if not s.get("err")]
    res = collections.Counter()
    forms = {}
    slots = []

    def one(s):
        tx = rpc.get_tx(s["signature"])
        if tx.get("__absent__") or tx is None:
            return None
        keys, ixs, alt = program_ixs(tx, program)
        return {"sig": s["signature"], "slot": tx.get("slot"), "keys": keys, "ixs": ixs,
                "lookups": alt, "err": (tx.get("meta") or {}).get("err"),
                "inner": bool((tx.get("meta") or {}).get("innerInstructions"))}

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(one, sigs):
            if not r:
                continue
            if r.get("slot"): slots.append(r["slot"])
            for ix in r["ixs"]:
                res[ix["tag"]] += 1
                if ix["tag"] not in forms:
                    r2 = dict(r)
                    r2["ix"] = ix
                    forms[ix["tag"]] = r2
    return res, forms, (min(slots) if slots else None), (max(slots) if slots else None), len(slots)


if __name__ == "__main__":
    prog = {"wb": WB, "bb": BB}[sys.argv[1]]
    lim = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    res, forms, lo, hi, n = scan(prog, lim)
    print(f"{sys.argv[1]}: {n} successful txs, slots {lo}..{hi}")
    print("tag histogram:", dict(sorted(res.items(), key=lambda x: (x[0] is None, x[0]))))
    for t, f in sorted(forms.items(), key=lambda x: (x[0] is None, x[0])):
        ix = f["ix"]
        accs = ix["accounts"]
        print(f"\n-- tag {t} nAccounts={ix['nAccounts']} sig={f['sig'][:32]} slot={f['slot']}")
        print("   data:", ix["data_hex"][:120])
        print("   accts:", [str(a)[:16] for a in accs[:12]], "..." if len(accs) > 12 else "")
    out = {"program": prog, "n": n, "slotRange": [lo, hi],
           "histogram": {str(k): v for k, v in res.items()},
           "forms": {str(k): v for k, v in forms.items()}}
    json.dump(out, open(f"/home/user/orca-audit/recon/{sys.argv[1]}_ix_forms.json", "w"), indent=1)
    print("\nsaved recon/%s_ix_forms.json" % sys.argv[1])
