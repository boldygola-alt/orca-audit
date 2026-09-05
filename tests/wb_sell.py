"""Wavebreak SELL-path battery (permissionless by configuration: sell_requires_permission=False
on all 1537 live curves). Executed as state-preserving fork transactions with per-instruction
before/after state capture.

Attacker base balances used here are FORK-ONLY FIXTURE FUNDING (documented in
evidence/funding_base_ata.json); they exist so the tests reach the program's own guards
instead of failing on an empty account. Artificial funding is never counted as exploit
evidence -- what matters is the measured payout and whether any state/payout invariant breaks.
"""
import sys, os, json, struct, base64, time
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


def ata_of(owner, mint, prog=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(owner)), bytes(F.pk(prog)), bytes(F.pk(mint))],
                                           F.pk(F.ATA))[0])


RESULTS = []


def snap(addrs):
    return F.snapshot(addrs, tokenaddrs=set(addrs), mints=set(addrs))


def run(name, ixs, watch, note=""):
    before = snap(watch)
    sb = F.get_slot()
    r = F.send(ixs, actor)
    after = snap(watch)
    d = F.diff(before, after)
    det = r.get("detail", {})
    err = det.get("err") or (r.get("error") or {}).get("message")
    logs = [l.strip() for l in det.get("logs", [])]
    rec = {"case": name, "note": note, "forkSlotBefore": sb, "forkSlotAfter": F.get_slot(),
           "sig": r.get("result"), "txErr": err, "sendError": r.get("error"), "logs": logs,
           "stateDiff": d,
           "before": {k: {"lamports": v.get("lamports"), "hash": (v.get("dataHash") or "")[:12],
                          "token": (v.get("token") or {}).get("amount"),
                          "supply": (v.get("mint") or {}).get("supply")} for k, v in before.items()},
           "after": {k: {"lamports": v.get("lamports"), "hash": (v.get("dataHash") or "")[:12],
                         "token": (v.get("token") or {}).get("amount"),
                         "supply": (v.get("mint") or {}).get("supply")} for k, v in after.items()}}
    RESULTS.append(rec)
    punch = [l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l]
    print(f"\n### {name}  [{note}]")
    print("   slot", rec["forkSlotBefore"], "->", rec["forkSlotAfter"], "sig", (rec["sig"] or "")[:30])
    print("   err :", json.dumps(err)[:140])
    print("   logs:", " | ".join(punch)[:280])
    print("   diff:", json.dumps(d)[:260])
    return rec


def ix(tag, metas, data=b""):
    return Instruction(F.pk(WB), bytes([tag]) + data, metas)


def M(k, w=False, s=False):
    return F.AM(k, writable=w, signer=s)


def sell_ix(curve, mint, vault, base_ata, quote_ata, tag=10, amount=0, partial=0, thr=None,
            base_prog=F.TOKEN, quote_prog=F.TOKEN, seller=None):
    d = struct.pack("<QB", amount & (2**64 - 1), partial)
    d += b"\x00" if thr is None else (b"\x01" + struct.pack("<QQ", *thr))
    return ix(tag, [M(seller or A, w=True, s=True), M(curve, w=True), M(mint, w=True), M(base_ata, w=True),
                    M(WSOL), M(vault, w=True), M(quote_ata, w=True), M(F.SYSTEM), M(F.ATA),
                    M(base_prog), M(quote_prog)], d)


def main():
    cands = json.load(open("/home/user/orca-audit/recon/wb_custody_full.json"))["perCurve"] if False else None
    # pick a non-graduated WSOL curve with vault>0 and the largest positive vault divergence,
    # plus the largest vault overall (deep-liquidity target)
    cur = [c for c in CURVES.values()
           if c["quote_mint"] == WSOL and not any(m["graduated"] for m in c["graduation_methods"])]
    byvault = sorted(cur, key=lambda c: -c["quote_amount"])
    target = byvault[1]          # a big, live, pre-graduation curve
    T = target["address"]; BASE = target["base_mint"]
    VAULT = ata_of(T, WSOL)
    print("target curve", T, "baseMint", BASE, "quote_amount", f"{target['quote_amount']:,}",
          "graduationTarget", f"{target['graduation_target']:,}")
    # attacker's own ATAs (real accounts, created by the attacker)
    _, ixc = F.create_ata(A, BASE, F.TOKEN, A)
    r0 = F.send([ixc], actor)
    print("create attacker base ATA:", json.dumps((r0.get("detail") or {}).get("err")))
    base_ata = ata_of(A, BASE)
    v = F.get_account(base_ata)
    print("base ata:", bool(v), (v or {}).get("space"))
    # fork-only fixture funding: give the attacker `fund` base tokens and raise supply to match,
    # so the sell path reaches the program's own math instead of failing on an empty account.
    mv = F.get_account(BASE)
    mraw = bytearray(base64.b64decode(mv["data"][0]))
    supply0 = struct.unpack_from("<Q", mraw, 36)[0]
    dec = mraw[44]
    ma = struct.unpack_from("<B", mraw, 45)[0]
    print("mint decimals", dec, "supply", f"{supply0:,}", "mintAuthoritySet", ma)
    fund = 10 ** (dec + 2)        # 100 tokens
    v2 = bytearray(base64.b64decode(F.get_account(base_ata)["data"][0]))
    struct.pack_into("<Q", v2, 64, fund)
    rs1 = F.rpc.rpc("surfnet_setAccount", [base_ata, {"lamports": 2039280, "data": bytes(v2).hex(),
                                                       "owner": F.TOKEN, "executable": False}], url=F.FORK)
    rs2 = F.rpc.rpc("surfnet_setSupply", [BASE, {"total": str(supply0 + fund)}], url=F.FORK)
    funding = {"note": "FORK-ONLY fixture funding of the attacker's own base ATA (Surfpool cheatcodes) so "
                       "sell/refund tests reach program guards; not exploit evidence.",
               "curve": T, "mint": BASE, "ata": base_ata, "decimals": dec, "funded": fund,
               "supplyBefore": supply0, "setAccount": rs1.get("result") or rs1.get("error"),
               "setSupply": rs2.get("result") or rs2.get("error"), "forkSlot": F.get_slot()}
    json.dump(funding, open("/home/user/orca-audit/evidence/funding_base_ata.json", "w"), indent=1)
    chk = snap([base_ata, BASE])
    print("after funding:", json.dumps({"amount": (chk[base_ata].get("token") or {}).get("amount"),
                                        "supply": (chk[BASE].get("mint") or {}).get("supply")}))
    watch = [A, ATA_WSOL, base_ata, T, VAULT, BASE]

    run("WB-S01 sell exact-in, tiny amount", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=10 ** dec)],
        watch, "1 token of 100 fixture balance")
    run("WB-S02 sell exact-in, full balance", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=fund)],
        watch, "all fixture tokens")
    run("WB-S03 sell exact-in twice in one tx", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=fund // 2),
                                                 sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=fund // 2)],
        watch, "sequence carry-over: two sells, same curve")
    run("WB-S04 sell then buy in one tx", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=fund // 4),
                                          ix(8, [M(A, w=True, s=True), M(T, w=True), M(BASE, w=True),
                                                 M(base_ata, w=True), M(WSOL), M(VAULT, w=True),
                                                 M(ATA_WSOL, w=True), M(F.SYSTEM), M(F.ATA), M(F.TOKEN),
                                                 M(F.TOKEN)], struct.pack("<QB", 10 ** 8, 1) + b"\x00")],
        watch, "sell->buy state carry-over (buy should be permission-blocked, sell should not leak)")
    run("WB-S05 sell with tight price threshold", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=10 ** dec,
                                                            thr=(2 ** 64 - 1, 1))],
        watch, "minOut above any possible payout")
    run("WB-S06 sell zero amount", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=0)], watch, "amount 0")
    run("WB-S07 sell max u64", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=2 ** 64 - 1)],
        watch, "overflow check")
    run("WB-S08 sell: redirect payout to another wallet's ATA",
        [sell_ix(T, BASE, VAULT, base_ata, ata_of("9gmP91zD3DP5NGJzuZqKAXqY4PpQq3pBQqJ3MhJcE1oq", WSOL))],
        watch, "recipient binding (does it have to be the seller's ATA?)")
    run("WB-S09 sell: quote vault = attacker ATA (vault substitution)",
        [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL)], watch, "control")
    # burn from a THIRD PARTY's token account (real mainnet holder) -> owner binding
    lg = F.rpc.rpc("getTokenLargestAccounts", [BASE, {"commitment": "confirmed"}])
    holders = [h["address"] for h in (lg.get("result") or {}).get("value", [])] or []
    # the fork only lazily copies accounts it has touched; make sure the victim ATA is loaded
    for h in holders[:3]:
        F.get_account(h)
    victim = next((h for h in holders if h != base_ata), None)
    if victim:
        run("WB-S10 sell: burn from a victim's base ATA", [sell_ix(T, BASE, VAULT, victim, ATA_WSOL,
                                                                   amount=10 ** 12)],
            watch + [victim], "attacker signs; token account owned by someone else")
    run("WB-S11 sell: wrong base token program", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=10 ** dec,
                                                           base_prog=F.TOKEN22)], watch, "pinning")
    run("WB-S12 sell: wrong quote token program", [sell_ix(T, BASE, VAULT, base_ata, ATA_WSOL, amount=10 ** dec,
                                                            quote_prog=F.TOKEN22)], watch, "pinning")
    run("WB-S13 sell on the graduated curve", [sell_ix("Ec5jrDHtT1iFnjzBqQTCfiGMmiGfEQVGdm42aM8Doo2N",
                                                        "F2FbvxXLxo4h1fJBTVuggHF4Ev2c3ZEyxZTSrAJvwave",
                                                        ata_of("Ec5jrDHtT1iFnjzBqQTCfiGMmiGfEQVGdm42aM8Doo2N", WSOL),
                                                        ata_of(A, "F2FbvxXLxo4h1fJBTVuggHF4Ev2c3ZEyxZTSrAJvwave"),
                                                        ATA_WSOL, amount=10 ** 9)],
        [A, ATA_WSOL, T], "post-graduation state gate")
    json.dump({"funding": funding, "results": RESULTS},
              open("/home/user/orca-audit/evidence/WBS_sell.json", "w"), indent=1)
    print("\n==== saved evidence/WBS_sell.json:", len(RESULTS), "cases")


if __name__ == "__main__":
    main()
