"""Fork-only transaction harness (Surfpool) with state capture.

- builds/sends state-preserving transactions to the local fork (never mainnet)
- captures before/after account state (lamports, data hash, token balances, mint supply)
- returns decoded error + logs for every test

Signer: fresh session keypair only (keys/actor_session2.json). No workspace keys reused.
"""
import base64, hashlib, json, os, struct, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rpc  # for fork URL + read helpers

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
from solders.message import to_bytes_versioned, MessageV0
from solders.transaction import VersionedTransaction
from solders.hash import Hash

FORK = rpc.FORK_ENDPOINT
KEYS = "/home/user/orca-audit/keys/actor_session2.json"

SYSTEM = "11111111111111111111111111111111"
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN22 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
ATA = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
MEMO = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
IX_SYSVAR = "Sysvar1nstructions1111111111111111111111111"
CLOCK_SYSVAR = "SysvarC1ock11111111111111111111111111111111"
RENT_SYSVAR = "SysvarRent111111111111111111111111111111111"
WSOL = "So11111111111111111111111111111111111111112"
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
COMPUTE = "ComputeBudget111111111111111111111111111111"

ERROR_CODES = {}  # filled by caller per program


def load_actor():
    return Keypair.from_bytes(bytes(json.load(open(KEYS))))


def b58(b):
    from base58 import b58encode
    return b58encode(bytes(b)).decode()


def pk(s):
    return Pubkey.from_string(s)


def AM(addr, writable=False, signer=False):
    """AccountMeta with explicit (writable, signer) ordering to avoid solders arg confusion"""
    k = pk(addr) if isinstance(addr, str) else addr
    return AccountMeta(k, bool(signer), bool(writable))


def get_slot():
    return rpc.rpc("getSlot", [{"commitment": "processed"}], url=FORK)["result"]


def get_blockhash():
    r = rpc.rpc("getLatestBlockhash", [{"commitment": "finalized"}], url=FORK)
    return r["result"]["value"]["blockhash"]


def get_account(addr, enc="base64", commitment="processed", tries=3):
    last = None
    for _ in range(tries):
        try:
            r = rpc.rpc("getAccountInfo", [addr, {"encoding": enc, "commitment": commitment}],
                        url=FORK, timeout=120)
        except Exception as e:
            last = e; time.sleep(1.0); continue
        if "result" in r:
            return r["result"].get("value")
        last = r
        time.sleep(0.5)
    return None


def get_many(addrs, enc="base64", chunk=90, commitment="processed"):
    out = {}
    for i in range(0, len(addrs), chunk):
        part = addrs[i:i + chunk]
        r = None
        for _ in range(3):
            try:
                r = rpc.rpc("getMultipleAccounts", [part, {"encoding": enc, "commitment": commitment}],
                            url=FORK, timeout=180)
                if "result" in r:
                    break
            except Exception:
                r = None
            time.sleep(1.0)
        if r is None or "result" not in r:
            for a in part:
                out[a] = None
            continue
        for a, v in zip(part, r["result"]["value"]):
            out[a] = v
    return out


def token_layout(data):
    """SPL/Token-2022 account: mint@1..33 owner@33..65 amount@64..72 (post 8-byte disc? ) -> use parsed"""
    # SPL Token Account: [32 mint][32 owner][8 amount][12 delegate][1 state][1 isdelegated][32 close][8 minRentReserve][121 mult]
    if not data or len(data) < 165:
        return None
    mint = b58(data[0:32]); owner = b58(data[32:64])
    amount = struct.unpack_from("<Q", data, 64)[0]
    state = data[108] if len(data) > 108 else None
    return {"mint": mint, "owner": owner, "amount": amount, "state": state}


def mint_layout(data):
    if not data or len(data) < 82:
        return None
    supply = struct.unpack_from("<Q", data, 36)[0]
    decimals = data[44]
    ma = data[45]
    mr = data[77]
    return {"supply": supply, "decimals": decimals,
            "mint_authority": b58(data[46:78]) if ma else None,
            "freeze_authority": b58(data[78:110]) if mr else None}


def snapshot(addrs, tokenaddrs=None, mints=None):
    """capture lamports+hash+decoded fields for a set of accounts"""
    accs = get_many(list(addrs))
    out = {}
    for a, v in (accs or {}).items():
        if v is None:
            out[a] = {"absent": True}
            continue
        raw = base64.b64decode(v["data"][0]) if v["data"][1] == "base64" else b""
        rec = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
               "executable": v["executable"], "dataHash": hashlib.sha256(raw).hexdigest(),
               "dataLen": len(raw)}
        if tokenaddrs and a in tokenaddrs:
            rec["token"] = token_layout(raw)
        if mints and a in mints:
            rec["mint"] = mint_layout(raw)
        out[a] = rec
    return out


def diff(before, after):
    d = {}
    for a, av in after.items():
        bv = before.get(a, {"absent": True})
        if av.get("absent") or bv.get("absent"):
            d[a] = {"absentBefore": bv.get("absent"), "absentAfter": av.get("absent")}
        if av.get("lamports") != bv.get("lamports"):
            d.setdefault(a, {})["lamportsDelta"] = (av.get("lamports", 0) or 0) - (bv.get("lamports", 0) or 0)
        if av.get("dataHash") != bv.get("dataHash"):
            d.setdefault(a, {})["dataChanged"] = True
        bt, at = bv.get("token") or {}, av.get("token") or {}
        if bt.get("amount") != at.get("amount"):
            d.setdefault(a, {})["tokenAmountDelta"] = (at.get("amount") or 0) - (bt.get("amount") or 0)
        bm, am = bv.get("mint") or {}, av.get("mint") or {}
        if bm.get("supply") != am.get("supply"):
            d.setdefault(a, {})["supplyDelta"] = (am.get("supply") or 0) - (bm.get("supply") or 0)
    return d


def build(ixs, payer, blockhash=None):
    msg = MessageV0.try_compile(payer.pubkey(), ixs, [], Hash.from_string(blockhash or get_blockhash()))
    return VersionedTransaction(msg, [payer])


def tx_detail(sig, tries=90):
    """poll the fork for the tx and return status + logs + token balance deltas"""
    for _ in range(tries):
        r = rpc.rpc("getSignatureStatuses", [[sig], {"searchTransactionHistory": True}], url=FORK)
        v = (r.get("result") or {}).get("value", [None])[0]
        if v:
            out = {"sig": sig, "slot": v.get("slot"), "err": v.get("err"),
                   "confirmationStatus": v.get("confirmationStatus")}
            t = rpc.rpc("getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}], url=FORK)
            meta = (t.get("result") or {}).get("meta") or {}
            out["logs"] = meta.get("logMessages", [])
            out["preTokenBalances"] = meta.get("preTokenBalances")
            out["postTokenBalances"] = meta.get("postTokenBalances")
            out["preBalances"] = meta.get("preBalances")
            out["postBalances"] = meta.get("postBalances")
            out["computeUnitsConsumed"] = meta.get("computeUnitsConsumed")
            out["returnData"] = meta.get("returnData")
            out["innerInstructions"] = meta.get("innerInstructions")
            return out
        time.sleep(0.5)
    return {"sig": sig, "err": "status-timeout"}


def wait_slot_ge(slot, tries=40):
    for _ in range(tries):
        if get_slot() >= slot:
            return True
        time.sleep(0.3)
    return False


def budget(limit=1_400_000):
    """SetComputeUnitLimit ix - without it the fork uses the 200k default and tests fail on CU
    exhaustion, which is an execution artifact rather than a program decision."""
    # ComputeBudget SetComputeUnitLimit = discriminator 2 + u32 (1/3 is heap size)
    return Instruction(pk(COMPUTE), bytes([2]) + struct.pack("<I", limit), [])


def send(ixs, payer, last_blockhash=None, tries=90):
    """sign+send a versioned tx to the FORK (state-preserving); returns rpc response"""
    ixs = [budget()] + list(ixs)
    bh = last_blockhash or get_blockhash()
    tx = build(ixs, payer, bh)
    raw = base64.b64encode(bytes(tx)).decode()
    r = rpc.rpc("sendTransaction", [raw, {"encoding": "base64", "skipPreflight": True,
                                          "maxRetries": 0,
                                          "commitment": "processed"}], url=FORK, timeout=180)
    if "result" in r:
        r["detail"] = tx_detail(r["result"], tries=tries)
    return r


def simulate(ixs, payer, last_blockhash=None):
    ixs = [budget()] + list(ixs)
    bh = last_blockhash or get_blockhash()
    tx = build(ixs, payer, bh)
    raw = base64.b64encode(bytes(tx)).decode()
    return rpc.rpc("simulateTransaction", [raw, {"encoding": "base64", "commitment": "finalized",
                                                 "replaceRecentBlockhash": True,
                                                 "sigVerify": True,
                                                 "schemas": [{"account": {"data": {"format": "uiList"}}}]}],
                   url=FORK, timeout=60)


def errcode(r):
    """extract instruction error code + logs from a send/simulate response"""
    if not r:
        return None
    if "error" in r:
        return {"raw_error": r["error"]}
    res = r.get("result", {})
    v = res.get("value", res)
    err = v.get("err")
    logs = v.get("logs", [])
    inner = v.get("innerInstructions") or []
    return {"err": err, "logs": logs, "unitsConsumed": v.get("unitsConsumed"),
            "innerInstructions": inner}


def airdrop(addr, lamports):
    return rpc.rpc("requestAirdrop", [addr, lamports, {"commitment": "finalized"}], url=FORK)


def wsol_sync_instruction(owner):
    """SyncNative (ix 17, 3 accounts) - wraps all native SOL in the WSOL ATA"""
    ata = str(Pubkey.find_program_address([bytes(pk(owner)), bytes(pk(TOKEN)), bytes(pk(WSOL))], pk(ATA))[0])
    return ata, Instruction(pk(TOKEN), bytes([17]),
                            [AM(ata, writable=True), AM(owner, writable=True, signer=True), AM(WSOL)])


def create_ata(owner, mint, token_program=TOKEN, payer_key=None):
    from solders.instruction import Instruction
    ata = str(Pubkey.find_program_address([bytes(pk(owner)), bytes(pk(token_program)), bytes(pk(mint))], pk(ATA))[0])
    return ata, Instruction(pk(ATA), bytes([1]), [
        AM(payer_key, writable=True, signer=True), AM(ata, writable=True), AM(owner), AM(mint),
        AM(SYSTEM), AM(token_program)])


def spl_transfer(source_owner_ata, dest_ata, amount, source_owner, token_program=TOKEN):
    return Instruction(pk(token_program), struct.pack("<BQ", 3, amount), [
        AM(source_owner_ata, writable=True), AM(dest_ata, writable=True), AM(source_owner, signer=True)])


def get_token_largest_fork(mint, limit=5):
    r = rpc.rpc("getTokenLargestAccounts", [mint, {"commitment": "finalized"}], url=FORK)
    return r.get("result", {}).get("value", [])
