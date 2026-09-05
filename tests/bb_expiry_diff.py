"""WS6 differential control: is Riptide's stored `validUntil` enforced by the deployed
swap handler at all?

FORK-ONLY DIAGNOSTIC.  A single u64 field (the market's own oracle `validUntil`) is
flipped on the fork copy of a market and back again; nothing else about the market, its
vaults, its oracle payload or any authority is touched, and no protocol balance is
created.  The point is *not* to make an attack work - it is to attribute the rejection we
observe on expired markets to the expiry field or to rule it out, because
`Oracle data is invalid` is emitted both for a payload that fails to deserialize / has no
liquidity and (if it is reached) for an expired oracle.  Each state edit is immediately
followed by a re-run of the identical instruction with the field restored, so a change of
outcome can be attributed to that one field and nothing else.

Reads/exploits nothing on mainnet.  Evidence is written with the exact bytes changed.
"""
import base64, json, struct, sys, time

sys.path.insert(0, "/home/user/orca-audit/tools")
sys.path.insert(0, "/home/user/orca-audit/tests")
import forknet as F
import rpc
import bb_stale_sweep as B

OUT = "/home/user/orca-audit/evidence/BBS3_expiry_diff.json"
RES = []


def read_market(addr):
    v = F.get_account(addr)
    raw = bytearray(base64.b64decode(v["data"][0]))
    return v, raw


def write_market(addr, v, raw, why):
    r = rpc.rpc("surfnet_setAccount", [addr, {"lamports": v["lamports"], "data": bytes(raw).hex(),
                                              "owner": v["owner"], "executable": v["executable"]}],
                url=F.FORK)
    B.FUNDING.append({"editedAccount": addr, "why": why, "note": "fork-only single-field "
                      "diagnostic toggle of the market's own validUntil; not exploit evidence",
                      "result": "error" not in r})
    return "error" not in r


def probe(tag, addr, m, amount, is_a, note):
    v, raw = read_market(addr)
    vu = struct.unpack_from("<Q", raw, 144)[0]
    slot = F.get_slot()
    give = amount
    B.fund(m["u_a"], (B.token_bal(m["u_a"]) or 0) + give, m["prog_a"])
    B.fund(m["u_b"], (B.token_bal(m["u_b"]) or 0) + give * 2, m["prog_b"])
    rec = B.run(f"{tag} | {addr[:10]} slot={slot} validUntil={vu} ({'valid' if slot <= vu else 'EXPIRED'}) "
                f"| {note}", [B.swap_ix(addr, m, give, is_a)],
                [B.A, addr, m["u_a"], m["u_b"], m["mv_a"], m["mv_b"]],
                "identical instruction, only the market's validUntil field differs between probes",
                extra={"forkSlot": slot, "validUntil": vu, "expired": slot > vu, "amount": give,
                       "direction": "A" if is_a else "B"})
    RES.append(rec)
    return rec


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "CzuQ"
    slot, ms = B.fetch_markets()
    byp = {m["addr"][:10]: m for m in ms}
    for m in ms:
        m["prog_a"], m["prog_b"] = B.prog_of(m["mint_a"]), B.prog_of(m["mint_b"])
        m["mv_a"], m["mv_b"] = B.ata_of(m["addr"], m["mint_a"], m["prog_a"]), \
            B.ata_of(m["addr"], m["mint_b"], m["prog_b"])
        m["u_a"], m["u_b"] = B.ata_of(B.A, m["mint_a"], m["prog_a"]), B.ata_of(B.A, m["mint_b"], m["prog_b"])
    live = [m for m in ms if m["resA"] > 10 ** 9 and m["resB"] > 10 ** 9 and m["variant"] in (3, 4)]
    cand = byp.get(target) or next(m for m in ms if m["addr"].startswith(target))
    give = max(1, cand["resA"] // 200)

    print(f"mainnet slot {slot}; candidate {cand['addr']} variant={cand['variant']} "
          f"validUntil={cand['valid_until']:,} staleBy={cand['stale_by']:,}", flush=True)
    B.ensure_atas([cand] + live[:2])

    # 1) baseline on the expired market (expected: rejected)
    probe("BB-DIFF 1 baseline (unmodified expired market)", cand["addr"], cand, give, True,
          "expect the same Oracle-data-is-invalid rejection seen in the sweep")

    # 2) only change: push validUntil past the fork clock
    v, raw = read_market(cand["addr"])
    orig = bytes(raw)
    struct.pack_into("<Q", raw, 144, F.get_slot() + 5000)
    ok = write_market(cand["addr"], v, raw, "validUntil moved forward to clear the expiry field")
    print("  setAccount ok:", ok, flush=True)
    probe("BB-DIFF 2 same market, validUntil := forkSlot+5000", cand["addr"], cand, give, True,
          "if this succeeds where probe 1 failed, the rejection IS caused by the expiry field")

    # 3) restore, re-probe: outcome must return to probe 1
    v, raw = read_market(cand["addr"])
    struct.pack_into("<Q", raw, 144, struct.unpack_from("<Q", orig, 144)[0])
    write_market(cand["addr"], v, raw, "restore of the market's original bytes")
    probe("BB-DIFF 3 restored original bytes", cand["addr"], cand, give, True,
          "control: same rejection as probe 1 means the flip - not ordering - caused probe 2")

    # 4) reverse direction on a live funded market: expire it (single field) and re-send
    tgt = next((m for m in live if m["addr"][:10] == "9PwXMVkFzW"),
               next((m for m in live if m["addr"][:10] != "CNp3etjEmW"), live[0]))
    give2 = max(1, tgt["resA"] // 200)
    probe("BB-DIFF 4a live market before edit", tgt["addr"], tgt, give2, True, "control")
    v, raw = read_market(tgt["addr"])
    keep = struct.unpack_from("<Q", raw, 144)[0]
    struct.pack_into("<Q", raw, 144, F.get_slot() - 10)
    write_market(tgt["addr"], v, raw, "validUntil moved into the past on a live market (diagnostic only)")
    probe("BB-DIFF 4b same live market, validUntil := slot-10", tgt["addr"], tgt, give2, True,
          "if this still succeeds the deployed swap path does not enforce validUntil at all")
    v, raw = read_market(tgt["addr"])
    struct.pack_into("<Q", raw, 144, keep)
    write_market(tgt["addr"], v, raw, "restore of the market's original bytes")
    probe("BB-DIFF 4c restored live market", tgt["addr"], tgt, give2, True, "control")

    verdict = None
    p1, p2, p3 = RES[0], RES[1], RES[2]
    if p1.get("err") and not p2.get("err") and p3.get("err"):
        verdict = "validUntil IS a swap-time gate: clearing only that field turns the rejection into a success"
    elif p1.get("err") and p2.get("err"):
        verdict = ("validUntil is NOT what rejects this market: the same instruction fails with the "
                   "expiry field cleared, so the rejection comes from the oracle payload/liquidity path")
    if len(RES) >= 6:
        p4a, p4b, p4c = RES[3], RES[4], RES[5]
        if not p4a.get("err") and not p4b.get("err") and not p4c.get("err"):
            verdict = ("deployed swap handler does NOT enforce the stored validUntil: a live market whose "
                       "expiry field is moved into the past keeps accepting identical swaps "
                       "(fork-diagnostic; confirmed in the natural clock-crossing test BB-EXP)")
        elif not p4a.get("err") and p4b.get("err"):
            verdict = ("deployed swap handler DOES enforce validUntil: the same swap is rejected once the "
                       "market's expiry field is in the past (and accepted after restore)")
    json.dump({"mainnetSlotAtScan": slot, "candidates": {c: byp[c]["addr"] for c in byp},
               "cases": RES, "fundingAndEdits": B.FUNDING, "verdict": verdict},
              open(OUT, "w"), indent=1)
    print("\nVERDICT:", verdict, "\nwrote", OUT, flush=True)


if __name__ == "__main__":
    main()
