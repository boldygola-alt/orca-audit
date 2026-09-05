"""WS6: attacker net-USD table from the fork sweep evidence (analysis only).

Self-consistent by construction: every token account that changed hands is read back from
the fork, its mint and owner are taken from the account itself, decimals from the mint, and
the USD value from the external reference price captured at the same scan.  Only accounts
owned by our fresh non-privileged actor are counted as the attacker's side; the market vault
deltas are reported separately so that "what the actor gained" and "what left the market"
can be compared.  Nothing is re-executed.
"""
import base64, json, re, struct, sys

sys.path.insert(0, "/home/user/orca-audit/tools")
import forknet as F
from solders.keypair import Keypair

EV = sys.argv[1] if len(sys.argv) > 1 else "/home/user/orca-audit/evidence/BBS2_stale_sweep.json"
OUT = "/home/user/orca-audit/evidence/BBS2_net_deltas.json"
A = str(F.load_actor().pubkey())
_d = json.load(open(EV))
prices = _d["prices"]
_c = {}


def acc(addr):
    if addr not in _c:
        _c[addr] = F.get_account(addr)
    return _c[addr]


def info(addr):
    """(mint, owner, decimals) for a token account, read from the fork copy"""
    v = acc(addr)
    if not v:
        return None
    raw = base64.b64decode(v["data"][0])
    if len(raw) < 72:
        return None
    from solders.pubkey import Pubkey
    mint = str(Pubkey.from_bytes(bytes(raw[0:32])))
    owner = str(Pubkey.from_bytes(bytes(raw[32:64])))
    mv = acc(mint)
    dec = base64.b64decode(mv["data"][0])[44] if mv else None
    return mint, owner, dec


rows = []
for c in _d["cases"]:
    mm = re.match(r"BB-SW (\w{10}).*?\| (.*)$", c["case"])
    if not mm:
        continue
    mkt, what = mm.group(1), mm.group(2)
    mb, ma = c.get("marketBefore") or {}, c.get("marketAfter") or {}
    mine, mkt_legs = [], []
    for addr, delta in (c.get("tokenDeltas") or {}).items():
        i = info(addr)
        if not i or i[2] is None:
            continue
        mint, owner, dec = i
        p = prices.get(mint)
        usd = (delta / 10 ** dec * p) if p is not None else None
        rec = (mint[:10], dec, delta, round(p, 4) if p else None,
               round(usd, 4) if usd is not None else None)
        (mine if owner == A else mkt_legs).append(rec)
    tot = sum(r[4] for r in mine if r[4] is not None)
    priced = all(r[4] is not None for r in mine) and len(mine) == 2
    rows.append({"case": what, "market": mkt, "ok": c.get("err") is None, "err": c.get("err"),
                 "forkSlot": c.get("forkSlotAfter"), "validUntil": mb.get("vu"),
                 "executedAfterStoredExpiry": bool(mb.get("vu")) and (c.get("forkSlotAfter") or 0) > mb["vu"],
                 "actorLegs": mine, "marketVaultLegs": mkt_legs,
                 "actorNetUsd": round(tot, 4), "bothLegsPriced": priced,
                 "marketReserveDelta": {"A": ma.get("resA", 0) - mb.get("resA", 0),
                                        "B": ma.get("resB", 0) - mb.get("resB", 0)} if ma else None,
                 "sig": c.get("sig")})

ok = [r for r in rows if r["ok"]]
val = [r for r in ok if r["bothLegsPriced"]]
print(f"executed cases {len(rows)}  succeeded {len(ok)}  with both legs priced {len(val)}\n")
print(f"{'market':11} {'probe':46} {'netUSD':>10} {'afterExpiry':>12}")
for r in sorted(val, key=lambda x: (x["market"], x["case"])):
    print(f"{r['market']:11} {r['case'][:46]:46} {r['actorNetUsd']:10.2f} {str(r['executedAfterStoredExpiry']):>12}")
pos = [r for r in val if r["actorNetUsd"] > 0]
print(f"\nnet-positive (both legs priced, external reference): {len(pos)} of {len(val)}")
for r in sorted(pos, key=lambda x: -x["actorNetUsd"])[:14]:
    print(f"   {r['market']} {r['case'][:42]:42} {r['actorNetUsd']:9.2f} USD  legs={r['actorLegs']}")
per = {}
for r in val:
    per.setdefault(r["market"], []).append(r["actorNetUsd"])
print("\nper-market net USD (min..max over sizes and both directions):")
for k, v in sorted(per.items()):
    print(f"   {k}: n={len(v)} min={min(v):.2f} max={max(v):.2f} sum={sum(v):.2f}")
json.dump({"evidence": EV, "externalPriceSlot": _d.get("externalPriceSlot"),
           "mainnetSlotAtScan": _d.get("mainnetSlotAtScan"), "rows": rows,
           "netPositiveCases": len(pos), "maxNetPositiveUsd": max([r["actorNetUsd"] for r in pos], default=0),
           "method": "actor legs = the two token accounts owned by the fresh actor keypair, valued at the "
                     "external reference captured for the same scan; market vault legs reported separately"},
          open(OUT, "w"), indent=1)
print("\nwrote", OUT)
