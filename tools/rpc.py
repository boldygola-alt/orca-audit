"""Read-only Solana RPC helper with public-endpoint failover (no credentials).

Used for inventory + transaction retrieval only (mandate rule 6).
`fork=True` endpoints are never written to from this module: this module has
no sendTransaction path at all -- transaction submission lives in forknet.py.
"""
import json, time, urllib.request, urllib.error, itertools

MAINNET_ENDPOINTS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-rpc.publicnode.com",
]

FORK_ENDPOINT = "http://127.0.0.1:8899"

_state = {"ep": itertools.cycle(range(len(MAINNET_ENDPOINTS))), "fail": {}}


def _post(url, payload, timeout=25):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def rpc(method, params=None, url=None, timeout=25, tries=None):
    """JSON-RPC call.  Tries the primary endpoint then fails over (rule 6)."""
    params = params if params is not None else []
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    if url:
        return _post(url, payload, timeout)
    attempts = tries if tries is not None else len(MAINNET_ENDPOINTS) * 2
    last = None
    for i in range(attempts):
        ep = MAINNET_ENDPOINTS[i % len(MAINNET_ENDPOINTS)]
        try:
            res = _post(ep, payload, timeout)
            if "error" in res:
                # endpoint-level rate limiting looks like an error; rotate on -32xxx 429-ish
                code = res["error"].get("code")
                msg = str(res["error"].get("message", ""))
                if code in (429, -32005, -32603) and "Block not available" not in msg:
                    last = res
                    time.sleep(0.35)
                    continue
            return res
        except Exception as e:  # HTTP 429/5xx, timeout, conn reset
            last = {"error": {"code": "transport", "message": f"{type(e).__name__}: {e}", "endpoint": ep}}
            time.sleep(0.4)
    return last if last else {"error": {"code": "unreachable", "message": "no endpoint reachable"}}


def get_slot(url=None):
    r = rpc("getSlot", [], url=url)
    return r.get("result")


def get_account(addr, url=None, enc="base64", commitment="finalized"):
    r = rpc("getAccountInfo", [addr, {"encoding": enc, "commitment": commitment}], url=url)
    v = r.get("result", {}).get("value")
    return v


def get_accounts(addrs, url=None, enc="base64", commitment="finalized", chunk=90):
    """getMultipleAccounts in chunks -> dict addr -> value (or None)."""
    out = {}
    for i in range(0, len(addrs), chunk):
        part = addrs[i:i + chunk]
        r = rpc("getMultipleAccounts", [part, {"encoding": enc, "commitment": commitment}], url=url)
        vals = r.get("result", {}).get("value", [])
        for a, v in zip(part, vals):
            out[a] = v
        time.sleep(0.05)
    return out


def get_tx(sig, url=None, max_options=None):
    for _ in range(6):
        r = rpc("getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}], url=url)
        if "error" in r:
            msg = str(r["error"].get("message", ""))
            if "Block not available" in msg or "Skipped" in msg:
                return {"__absent__": msg}
            time.sleep(0.4)
            continue
        return r.get("result")
    return {"__error__": "retries exhausted"}


def sigs_for(addr, limit=25, before=None, url=None, commitment="finalized"):
    p = {"limit": limit, "commitment": commitment}
    if before:
        p["before"] = before
    r = rpc("getSignaturesForAddress", [addr, p], url=url)
    return r.get("result", [])


def get_token_largest(mint, url=None, limit=5):
    r = rpc("getTokenLargestAccounts", [mint, {"commitment": "finalized"}], url=url)
    return r.get("result", {}).get("value", [])


def get_supply(mint, url=None):
    r = rpc("getTokenSupply", [mint, {"commitment": "finalized"}], url=url)
    return r.get("result", {}).get("value")


def get_balance(addr, url=None, commitment="finalized"):
    r = rpc("getBalance", [addr, {"commitment": commitment}], url=url)
    return r.get("result", {}).get("value")


def get_token_accounts_by_owner(owner, program=None, url=None, commitment="finalized"):
    p = {"commitment": commitment}
    if program:
        p["programId"] = program
    else:
        p["encoding"] = "jsonParsed"
    r = rpc("getTokenAccountsByOwner", [owner, {"programId": program or "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}, p], url=url)
    return r.get("result", {}).get("value", [])


def get_token_accounts(owner, program, url=None):
    r = rpc("getTokenAccountsByOwner", [owner, {"programId": program}, {"encoding": "jsonParsed", "commitment": "finalized"}], url=url)
    return r.get("result", {}).get("value", [])


def get_block(slot, url=None, styles="jsonParsed"):
    r = rpc("getBlock", [slot, {"encoding": styles, "maxSupportedTransactionVersion": 0,
                               "transactionDetails": "full", "rewards": False}], url=url)
    return r.get("result")
