"""Busybox/Riptide v2.1.1: legitimate funded lifecycle on a *synthetic self-owned* market.

The deployed-ELF tag sweep (evidence/BB_tagsweep.json) shows tag 8 `MarketInitialize` is reachable
with no privilege gate (it only complained about a short account list), while 9-12 require the market
authority. So an attacker - and, symmetrically, anyone - can create a market they control. That makes
the previously-blocked "legitimate funded deposit -> oracle update -> swap -> withdraw -> close"
accounting measurable without using anyone else's authority key or fabricating protocol balances.

Measured questions:
  * do stored reserves track the vault token balances exactly through the whole lifecycle?
  * is withdraw bounded by reserves (not by the vault), and close bounded by zero reserves?
  * can the *owner* of a self-created market extract more than they deposited (mint/rounding/fee bugs)?
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
actor = F.load_actor(); A = str(actor.pubkey())
WSOL, USDC = F.WSOL, F.USDC
ATA_WSOL = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"


def ata_of(o, m, p):
    return str(Pubkey.find_program_address([bytes(F.pk(o)), bytes(F.pk(p)), bytes(F.pk(m))], F.pk(F.ATA))[0])


def bal(a):
    v = F.get_account(a)
    if not v or v["space"] != 165:
        return None
    return struct.unpack_from("<Q", base64.b64decode(v["data"][0]), 64)[0]


def state(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return {"space": v["space"], "owner": v["owner"], "lamports": v["lamports"],
            "disc": raw[0], "bump": raw[1], "cuPen": raw[2], "imbalance": raw[3],
            "id": struct.unpack_from("<I", raw, 4)[0],
            "authority": F.b58(raw[8:40]), "updater": F.b58(raw[40:72]),
            "mintA": F.b58(raw[72:104]), "mintB": F.b58(raw[104:136]),
            "sequence": struct.unpack_from("<Q", raw, 136)[0],
            "validUntil": struct.unpack_from("<Q", raw, 144)[0],
            "oracleFirst16": raw[152:168].hex(),
            "minSpread": struct.unpack_from("<i", raw, 664)[0],
            "arbPenalty": struct.unpack_from("<I", raw, 668)[0],
            "jitod": struct.unpack_from("<I", raw, 672)[0],
            "minOracle": int.from_bytes(raw[688:704], "little"),
            "maxOracle": int.from_bytes(raw[704:720], "little"),
            "reservesA": struct.unpack_from("<Q", raw, 736)[0],
            "reservesB": struct.unpack_from("<Q", raw, 744)[0],
            "hash": F.hashlib.sha256(raw).hexdigest()}


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


LOG = []


def step(name, ixs, note=""):
    r = F.send(ixs, actor)
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    entry = {"step": name, "note": note, "forkSlot": F.get_slot(), "sig": r.get("result"),
             "err": det.get("err") or r.get("error"),
             "logs": logs, "computeUnits": det.get("unitsConsumed")}
    LOG.append(entry)
    print(f"\n### {name}   [{note}]")
    print("   err:", json.dumps(entry["err"])[:150])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:260])
    return r


def main():
    mid = 0x0FA11E01
    market = str(Pubkey.find_program_address([b"market", struct.pack("<I", mid)], F.pk(BB))[0])
    vA, vB = ata_of(market, WSOL, F.TOKEN), ata_of(market, USDC, F.TOKEN)
    uA, uB = ATA_WSOL, ata_of(A, USDC, F.TOKEN)
    print("synthetic market:", market, "vaults", vA, vB)
    for m in (USDC,):
        _, x = F.create_ata(A, m, F.TOKEN, A)
        step("setup: create attacker USDC ATA", [x])
    # fork-only funding of the ATTACKER's own accounts (documented; not exploit evidence)
    for addr, amount in ((uA, 200_000_000_000), (uB, 200_000_000)):
        v = F.get_account(addr)
        raw = bytearray(base64.b64decode(v["data"][0]))
        struct.pack_into("<Q", raw, 64, amount)
        F.rpc.rpc("surfnet_setAccount", [addr, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                                "owner": v["owner"], "executable": False}], url=F.FORK)
    LOG.append({"step": "fixture funding", "note": "attacker's own WSOL/USDC balances set via fork "
                  "cheatcode so the lifecycle has real inventory to move; not exploit evidence"})

    init = Instruction(F.pk(BB), bytes([8]) + struct.pack("<I", mid), [
        M(A, w=True, s=True), M(market, w=True), M(WSOL), M(USDC),
        M(vA, w=True), M(vB, w=True), M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(F.TOKEN)])
    step("BB-L01 marketInitialize (attacker = authority & updater)", [init],
         "permissionless market creation; market PDA = ['market', u32 id]")
    st0 = state(market)
    print("   market after init:", json.dumps(st0, indent=1)[:900] if st0 else "ABSENT")
    if not st0:
        json.dump({"log": LOG, "fatal": "market not created"}, open("/home/user/orca-audit/evidence/UBL_lifecycle.json", "w"), indent=1)
        return
    watch = [A, uA, uB, market, vA, vB, WSOL, USDC]

    def snap():
        return {w: state(w) if w == market else bal(w) for w in watch}

    s_before = snap()
    dep = Instruction(F.pk(BB), bytes([10]) + struct.pack("<QQ", 100_000_000_000, 100_000_000), [
        M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
        M(uA, w=True), M(uB, w=True), M(vA, w=True), M(vB, w=True), M(F.TOKEN), M(F.TOKEN), M(F.MEMO)])
    step("BB-L02 marketDeposit 100 WSOL + 100 USDC (attacker is the authority)", [dep])
    s_after_dep = snap()
    st_dep = state(market)
    print(f"   reserves after deposit: {st_dep['reservesA']:,} / {st_dep['reservesB']:,}"
          f"  vaults: {bal(vA):,} / {bal(vB):,}  reserves==vault: "
          f"{st_dep['reservesA'] == bal(vA) and st_dep['reservesB'] == bal(vB)}")

    # oracle update: FlatPrice 1.0 (Q64.64) with a future validUntil; attacker is the updater
    payload = bytearray(512)
    payload[0] = 1                                              # OracleData::FlatPrice
    struct.pack_into("<Q", payload, 1, 1 << 64)                  # price_q64_64 low
    struct.pack_into("<Q", payload, 9, 0)
    ou = Instruction(F.pk(BB), bytes([1]) + struct.pack("<QQ", st_dep["sequence"] + 1, F.get_slot() + 500) + bytes(payload),
                     [M(market, w=True), M(A, s=True)])
    step("BB-L03 oracleUpdate (attacker-signed; flat price 1.0)", [ou])
    st_or = state(market)
    print("   market after oracle:", json.dumps({k: st_or[k] for k in ("sequence", "validUntil", "oracleFirst16")}))

    def swap(tag, amount, is_a, partial=0, sl=None):
        data = bytes([tag]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
        data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<QQ", *sl) if isinstance(sl, tuple)
                                               else bytes([2]) + struct.pack("<Q", sl))
        data += bytes([partial])
        return Instruction(F.pk(BB), data, [
            M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
            M(uA, w=True), M(uB, w=True), M(vA, w=True), M(vB, w=True),
            M(F.TOKEN), M(F.TOKEN), M(F.MEMO), M(F.IX_SYSVAR)])

    s_pre_swap = snap()
    step("BB-L04 swapExactIn 1 WSOL -> USDC", [swap(2, 1_000_000_000, True)])
    s_post_swap = snap()
    dA = (s_post_swap[uA] or 0) - (s_pre_swap[uA] or 0)
    dB = (s_post_swap[uB] or 0) - (s_pre_swap[uB] or 0)
    print(f"   attacker WSOL {dA:+,} USDC {dB:+,}   implied price = {(abs(dB)/1e6)/(abs(dA)/1e9) if dA else float('nan'):.6f} USDC/WSOL")
    st_sw = state(market)
    print(f"   reserves after swap {st_sw['reservesA']:,}/{st_sw['reservesB']:,} vault {bal(vA):,}/{bal(vB):,} "
          f"reserves==vault: {st_sw['reservesA'] == bal(vA) and st_sw['reservesB'] == bal(vB)}")
    s_pre_rt = snap()
    step("BB-L05 swapExactIn back: sell the USDC for WSOL (round trip)", [swap(2, abs(dB), False)])
    s_post_rt = snap()
    netA = (s_post_rt[uA] or 0) - (s_pre_rt[uA] or 0)
    netB = (s_post_rt[uB] or 0) - (s_pre_rt[uB] or 0)
    print(f"   round trip net: WSOL {netA:+,} USDC {netB:+,}")
    print("   >>> FREE VALUE ON ROUND TRIP" if (netA > 0 and netB >= 0) or (netB > 0 and netA >= 0)
          else "   round trip is lossless-or-negative for the swapper (no free value)")
    LOG[-1]["roundTripNet"] = {"wsol": netA, "usdc": netB}
    LOG[-2]["swapDelta"] = {"wsol": dA, "usdc": dB}

    # swap with no slippage bound and max amounts, then a reserves-vs-vault divergence attempt:
    # send tokens DIRECTLY into the vault (no instruction) and then try to withdraw more than reserves
    F.send([F.spl_transfer(uA, vA, 50_000_000_000, A)], actor)
    st_div = state(market)
    print(f"\n   after a direct vault transfer: reserves {st_div['reservesA']:,} vault {bal(vA):,} "
          f"-> divergence {bal(vA) - st_div['reservesA']:+,}")
    wd = Instruction(F.pk(BB), bytes([11]) + struct.pack("<QQ", st_div["reservesA"] + 10 ** 11, 0), [
        M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
        M(uA, w=True), M(uB, w=True), M(vA, w=True), M(vB, w=True), M(F.TOKEN), M(F.TOKEN), M(F.MEMO)])
    s_pre_wd = snap()
    step("BB-L06 withdraw reserves+100 SOL (should be bounded by reserves, not by the vault)", [wd])
    s_post_wd = snap()
    gained = (s_post_wd[uA] or 0) - (s_pre_wd[uA] or 0)
    st_wd = state(market)
    print(f"   attacker WSOL gained {gained:+,}; reserves now {st_wd['reservesA']:,}; vault {bal(vA):,}")
    LOG[-1]["withdrawGained"] = gained
    LOG[-1]["reservesAfter"] = st_wd["reservesA"]
    LOG[-1]["vaultAfter"] = bal(vA)
    LOG[-1]["freeValueFromDivergence"] = gained > st_div["reservesA"]

    # close with non-zero reserves, then zero them out and close; where do the lamports go?
    cl = Instruction(F.pk(BB), bytes([12]), [
        M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
        M(vA, w=True), M(vB, w=True), M(uA, w=True), M(uB, w=True),
        M(F.SYSTEM), M(F.ATA), M(F.TOKEN), M(F.TOKEN)])
    step("BB-L07 marketClose with non-zero reserves (must be rejected)", [cl])
    st_c = state(market)
    # drain the vault-vs-reserves gap: is it recoverable by the authority?
    amt_left = bal(vA) or 0
    if amt_left:
        wd2 = Instruction(F.pk(BB), bytes([11]) + struct.pack("<QQ", amt_left, bal(vB) or 0), [
            M(A, w=True, s=True), M(market, w=True), M(WSOL, w=True), M(USDC, w=True),
            M(uA, w=True), M(uB, w=True), M(vA, w=True), M(vB, w=True), M(F.TOKEN), M(F.TOKEN), M(F.MEMO)])
        s_pre = snap()
        step("BB-L08 withdraw the exact vault balances (reserves < vault)", [wd2])
        s_post = snap()
        print("   gained:", (s_post[uA] or 0) - (s_pre[uA] or 0), (s_post[uB] or 0) - (s_pre[uB] or 0))
        LOG[-1]["gained"] = {"wsol": (s_post[uA] or 0) - (s_pre[uA] or 0),
                            "usdc": (s_post[uB] or 0) - (s_pre[uB] or 0)}
    st_c2 = state(market)
    print("\n   market before final close:", json.dumps({k: st_c2[k] for k in
          ("disc", "reservesA", "reservesB", "lamports")} if st_c2 else "absent"))
    pre_lam = (state(market) or {}).get("lamports")
    a_pre = F.get_account(A)["lamports"]
    step("BB-L09 marketClose after reserves are zero (rent custody destination)", [cl])
    st_fin = state(market)
    a_post = F.get_account(A)["lamports"]
    print(f"   market lamports before {pre_lam:,}; attacker lamports delta {a_post-a_pre:+,} "
          f"(fee 5000); market now: {st_fin}")
    LOG.append({"marketFinal": st_fin, "attackerLamportsDelta": a_post - a_pre})
    json.dump({"market": market, "mid": mid, "vaults": {"A": vA, "B": vB},
               "attacker": {"A": uA, "B": uB}, "log": LOG},
              open("/home/user/orca-audit/evidence/UBL_lifecycle.json", "w"), indent=1)
    print("\nsaved evidence/UBL_lifecycle.json")


if __name__ == "__main__":
    main()
