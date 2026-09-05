"""Faithful live-transaction fixture recovery (Workstream B).

Given a transaction signature, rebuild every instruction of a target program with its
*complete* resolved account list (address-lookup-table entries included) so fork tests
replay exactly what real users sent - no invented accounts, no wrong ordering.
"""
import sys, json, base64, struct
sys.path.insert(0, "/home/user/orca-audit/tools")
import rpc
from base58 import b58decode, b58encode

TARGETS = {
    "wavebreak": "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF",
    "busybox": "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j",
    "whirlpool": "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
}


def _addr(a):
    return b58encode(bytes(a)).decode()


def alt_addresses(alt_addr, commitment="confirmed"):
    v = rpc.get_account(alt_addr, commitment=commitment)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    META = 56  # AddressLookupTable state: 4 depadding + 8 slot + 33 optional authority + 4 last_free_index (padded)
    out = []
    i = META
    while i + 32 <= len(raw):
        out.append(_addr(raw[i:i + 32]))
        i += 32
    return out


def full_key_list(msg, commitment="confirmed", _cache={}):
    """static keys + ALT-loaded keys in the canonical order (writable then readonly per lookup)"""
    keys = list(msg["accountKeys"])
    for lk in msg.get("addressTableLookups", []) or []:
        alt = lk["accountKey"]
        if alt not in _cache:
            _cache[alt] = alt_addresses(alt, commitment)
        addrs = _cache[alt]
        if addrs is None:
            raise RuntimeError(f"ALT {alt} not found at this slot")
        for i in lk.get("writableIndexes", []):
            keys.append(addrs[i])
        for i in lk.get("readonlyIndexes", []):
            keys.append(addrs[i])
    return keys


def key_classes(msg, n_static):
    """(signer, writable) per index for the static keys only"""
    h = msg["header"]
    ns = h["numRequiredSignatures"]
    rs = h["numReadonlySignedAccounts"]
    ru = h["numReadonlyUnsignedAccounts"]
    out = []
    for i in range(n_static):
        signer = i < ns
        total = n_static
        if signer:
            writable = i < ns - rs
        else:
            writable = i < total - ru
        out.append((signer, writable))
    for i in range(n_static, len(msg["accountKeys"])):
        out.append((False, True))
    return out


def extract(sig, program, commitment="confirmed"):
    tx = rpc.rpc("getTransaction", [sig, {"encoding": "json", "maxSupportedTransactionVersion": 0,
                                          "commitment": commitment}]).get("result")
    if not tx:
        return None
    msg = tx["transaction"]["message"]
    n_static = len(msg["accountKeys"])
    keys = full_key_list(msg, commitment)
    classes = key_classes(msg, n_static)
    out = []
    for i, ix in enumerate(msg["instructions"]):
        pid = keys[ix["programIdIndex"]]
        raw = b58decode(ix["data"]) if ix.get("data") else b""
        accs = [keys[a] for a in ix["accounts"]]
        meta = [classes[a] if a < len(classes) else (False, True) for a in ix["accounts"]]
        rec = {"index": i, "programId": pid, "tag": raw[0] if raw else None, "data_hex": raw.hex(),
               "accounts": [{"pubkey": a, "writable": w, "signer": s} for a, (s, w) in zip(accs, meta)],
               "isTopLevel": True}
        if pid == program:
            out.append(rec)
    # inner (CPI) instructions for the same program
    for grp in (tx.get("meta") or {}).get("innerInstructions") or []:
        for ix in grp.get("instructions", []):
            pid = keys[ix["programIdIndex"]] if ix.get("programIdIndex") is not None else ix.get("programId")
            if pid != program:
                continue
            raw = b58decode(ix["data"]) if ix.get("data") else b""
            accs = ix.get("accounts") or []
            out.append({"index": None, "programId": pid, "tag": raw[0] if raw else None,
                        "data_hex": raw.hex(),
                        "accounts": [{"pubkey": keys[a] if isinstance(a, int) else a, "writable": True,
                                      "signer": False} for a in accs],
                        "isTopLevel": False})
    return {"signature": sig, "slot": tx.get("slot"), "blockTime": tx.get("blockTime"),
            "err": (tx.get("meta") or {}).get("err"), "fee": (tx.get("meta") or {}).get("fee"),
            "lookups": msg.get("addressTableLookups", []), "nStaticKeys": n_static,
            "ixs": out, "rawMeta": {k: (tx.get("meta") or {}).get(k) for k in
                                    ("preTokenBalances", "postTokenBalances", "logMessages")}}


def newest_program_txs(program, limit=200, tag_filter=None):
    """scan recent successful txs of `program`, return one fixture per instruction tag"""
    import concurrent.futures as cf
    sigs = [s["signature"] for s in rpc.sigs_for(program, limit=limit) if not s.get("err")]

    def one(sig):
        try:
            ex = extract(sig, program)
        except Exception as e:
            return {"sig": sig, "scan_error": str(e)}
        if not ex:
            return None
        keep = [i for i in ex["ixs"] if i["isTopLevel"] and (tag_filter is None or i["tag"] in tag_filter)]
        if not keep:
            return None
        ex["ixs"] = keep
        return ex

    found = {}
    with cf.ThreadPoolExecutor(max_workers=6) as ex:
        for r in ex.map(one, sigs):
            if not r or r.get("scan_error"):
                continue
            for ix in r["ixs"]:
                if ix["tag"] not in found:
                    found[ix["tag"]] = {"slot": r["slot"], "signature": r["signature"],
                                        "blockTime": r["blockTime"], "ix": ix,
                                        "lookups": r["lookups"], "nStaticKeys": r["nStaticKeys"]}
    return found, sigs


if __name__ == "__main__":
    sig, which = sys.argv[1], sys.argv[2]
    e = extract(sig, TARGETS[which])
    print("slot", e["slot"], "err", e["err"])
    for ix in e["ixs"]:
        print(f"  ix#{ix['index']} tag={ix['tag']} nAcc={len(ix['accounts'])} data={ix['data_hex'][:48]}")
        for i, a in enumerate(ix["accounts"]):
            print(f"     {i:2d} {a['pubkey']:44s} w={int(a['writable'])} s={int(a['signer'])}")
