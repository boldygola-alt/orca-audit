"""Pure-python base58 (no external deps beyond solders) + Wavebreak/Busybox tx classification.

Read-only mainnet helper: fetch a program's recent signatures, decode each top-level
instruction's 1-byte discriminator, and cache the raw tx so fixture building never re-hits RPC.
"""
import base64, json, os, sys, collections

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
WHIRL = "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"
AMM = "9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP"

WB_TAGS = {0: "PermissionConsumeTopLevel", 1: "PermissionConsumeCpi", 2: "PermissionConfigInitialize",
           3: "PermissionConfigUpdate", 4: "PermissionConfigClose", 5: "PermissionRevoke",
           6: "PermissionRefund", 8: "TokenBuyExactIn", 9: "TokenBuyExactOut",
           10: "TokenSellExactIn", 11: "TokenSellExactOut", 12: "TokenRefund",
           16: "AuthorityConfigInitialize", 17: "AuthorityConfigGrant", 18: "AuthorityConfigRevoke",
           24: "MintConfigInitialize", 25: "MintConfigClose", 26: "MintConfigUpdate",
           32: "GraduateWhirlpool", 33: "GraduateManual", 40: "CreateLockedlaunch",
           41: "CreateLaunch", 42: "CreatePresale", 48: "BondingCurveInitialize",
           49: "BondingCurveCollectFees", 50: "BondingCurveGraduate", 51: "BondingCurveClose",
           56: "LpHarvest", 57: "LpTransfer", 58: "LpTakeover"}
BB_TAGS = {0: "ProgramVersion", 1: "OracleUpdate", 2: "SwapExactIn", 3: "SwapExactOut",
           4: "ReservedSwapX", 5: "ReservedSwapY", 6: "ReservedSwapZ", 7: "ReservedSwapA",
           8: "MarketInitialize", 9: "MarketUpdate", 10: "MarketDeposit", 11: "MarketWithdraw",
           12: "MarketClose", 13: "ReservedMarketX", 14: "ReservedMarketY", 15: "ReservedMarketZ"}


def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def b58encode(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + s


def decode_data(d):
    """jsonParsed instruction data -> bytes (base58 per the public RPC)."""
    if d is None:
        return b""
    if isinstance(d, dict):
        d = d.get("data")
    if isinstance(d, list):
        return bytes(d)
    if isinstance(d, str):
        try:
            return b58decode(d)
        except ValueError:
            return base64.b64decode(d)
    return b""


def fetch_tx(sig, cache_dir="recon/txs"):
    os.makedirs(cache_dir, exist_ok=True)
    p = os.path.join(cache_dir, sig + ".json")
    if os.path.exists(p):
        return json.load(open(p))
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rpc
    r = rpc.rpc("getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
    res = r.get("result")
    if res is not None:
        json.dump(res, open(p, "w"))
    return res


def program_instructions(tx, pid):
    """Yield (tag_or_None, data_bytes, accounts, program_index) for every top-level ix of pid."""
    msg = tx["transaction"]["message"]
    keys = [k["pubkey"] for k in msg["accountKeys"]]
    for ix in msg["instructions"]:
        p = ix.get("programId") or (keys[ix["programIdIndex"]] if "programIdIndex" in ix else None)
        if p != pid:
            continue
        raw = decode_data(ix.get("data"))
        accts = ix.get("accounts") or []
        if accts and isinstance(accts[0], int):
            accts = [keys[i] for i in accts]
        yield (raw[0] if raw else None, raw, accts, len(accts))


def classify(sigs, pid, tags, limit=400):
    out = collections.Counter()
    rows = []
    for s in sigs[:limit]:
        tx = fetch_tx(s["signature"])
        if tx is None:
            out["fetch_failed"] += 1
            continue
        for tag, raw, accts, n in program_instructions(tx, pid):
            name = tags.get(tag, f"tag{tag}")
            out[name] += 1
            rows.append({"slot": s["slot"], "sig": s["signature"], "tag": tag, "name": name,
                         "n_accounts": n, "err": (tx.get("meta") or {}).get("err"),
                         "accounts": accts, "data_hex": raw.hex()})
    return out, rows


if __name__ == "__main__":
    pid = sys.argv[1] if len(sys.argv) > 1 else WB
    tags = WB_TAGS if pid == WB else BB_TAGS
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 150
    sys.path.insert(0, "tools")
    import rpc
    r = rpc.rpc("getSignaturesForAddress", [pid, {"limit": min(n, 250), "commitment": "confirmed"}])
    sigs = r.get("result") or []
    more = []
    while len(sigs) < n and len(r.get("result") or []) == 250:
        r = rpc.rpc("getSignaturesForAddress", [pid, {"limit": 250, "before": sigs[-1]["signature"], "commitment": "confirmed"}])
        new = r.get("result") or []
        if not new:
            break
        sigs += new
    print("signatures fetched:", len(sigs), "slot range", sigs[-1]["slot"], "->", sigs[0]["slot"])
    counts, rows = classify(sigs, pid, tags, limit=n)
    print(json.dumps(dict(counts), indent=1))
    json.dump(rows, open(f"recon/s4_tags_{pid[:4]}.json", "w"))
