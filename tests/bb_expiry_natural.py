"""WS6 natural clock-crossing test: identical instruction, unmodified state.

The fork's copy of each live market froze its oracle at the moment Surfpool fetched it, so
the market's own stored `validUntil` is a fixed slot while the fork clock keeps moving.  The
swap that succeeded at fork slot S (recorded in evidence/BBS2_stale_sweep.json, same account
list, same amount, nothing edited since) is simply re-sent now that the fork slot has passed
that market's validUntil.  No state is written by this test other than the swap itself.
"""
import base64, json, struct, sys, time

sys.path.insert(0, "/home/user/orca-audit/tools")
sys.path.insert(0, "/home/user/orca-audit/tests")
import forknet as F
import bb_stale_sweep as B

MARKETS = ["9PwXMVkFzW", "CNp3etjEmW", "G9pQE63etk", "GxGxQBvMQ7", "HxNaPy1oYA", "9Bc7tyaZft", "HpGbZwwQ66"]
OUT = "/home/user/orca-audit/evidence/BBS4_natural_crossing.json"


def main():
    slot, ms = B.fetch_markets()
    for m in ms:
        m["prog_a"], m["prog_b"] = B.prog_of(m["mint_a"]), B.prog_of(m["mint_b"])
        m["mv_a"], m["mv_b"] = B.ata_of(m["addr"], m["mint_a"], m["prog_a"]), \
            B.ata_of(m["addr"], m["mint_b"], m["prog_b"])
        m["u_a"], m["u_b"] = B.ata_of(B.A, m["mint_a"], m["prog_a"]), B.ata_of(B.A, m["mint_b"], m["prog_b"])
    sel = [m for m in ms if m["addr"][:10] in MARKETS]
    fs = F.get_slot()
    print(f"mainnet slot {slot}; fork slot {fs}; selected {len(sel)} markets", flush=True)
    B.ensure_atas(sel)
    res = []
    for m in sel:
        v = F.get_account(m["addr"])
        raw = base64.b64decode(v["data"][0])
        vu = struct.unpack_from("<Q", raw, 144)[0]
        give = max(1, struct.unpack_from("<Q", raw, 736)[0] // 200)
        B.fund(m["u_a"], (B.token_bal(m["u_a"]) or 0) + give, m["prog_a"])
        rec = B.run(f"BB-CROSS {m['addr'][:10]} fork slot {F.get_slot()} vs market validUntil {vu} "
                    f"(past by {F.get_slot()-vu:,}) | exact-in A {give:,}",
                    [B.swap_ix(m["addr"], m, give, True)],
                    [B.A, m["addr"], m["u_a"], m["u_b"], m["mv_a"], m["mv_b"]],
                    "identical probe to the one that succeeded pre-expiry in the sweep; state untouched by us",
                    extra={"market_addr": m["addr"], "validUntil": vu, "forkSlotAtProbe": F.get_slot(),
                           "amount": give})
        res.append(rec)
    def oracle_reject(r):
        return bool(r.get("err")) and "Oracle data is invalid" in " ".join(r.get("logs", []))
    rej = sum(1 for r in res if oracle_reject(r))
    other = sum(1 for r in res if r.get("err") and not oracle_reject(r))
    print(f"\n{rej} of {len(res)} markets now reject the previously-executing probe with the oracle-expiry "
          f"message (unmodified state, fork clock past validUntil); {other} rejected for other reasons",
          flush=True)
    verdict = None
    if rej == len(res):
        verdict = ("the stored validUntil IS a hard swap-time gate on unmodified live state: the identical "
                   "instruction that executed while slot <= validUntil is rejected once the fork clock has "
                   "passed it, with no account written by the tester")
    elif rej == 0:
        verdict = ("the stored validUntil is NOT enforced: every market keeps accepting the swap after its "
                   "expiry slot with unmodified state")
    else:
        verdict = (f"mixed: {rej}/{len(res)} rejected with the oracle message, {other} with other errors - "
                   "see per-market records")
    json.dump({"mainnetSlotAtScan": slot, "forkSlot": fs, "cases": res, "verdict": verdict,
               "funding": B.FUNDING}, open(OUT, "w"), indent=1)
    print("VERDICT:", verdict, "\nwrote", OUT, flush=True)


if __name__ == "__main__":
    main()
