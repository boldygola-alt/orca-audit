"""Workstream B driver: recover live Wavebreak transaction forms for every instruction tag
that is actually exercised on mainnet, then verify each referenced account exists at the
fork tip so fork tests are never run against a stale/absent fixture (rule 10).
"""
import sys, json, collections
sys.path.insert(0, "/home/user/orca-audit/tools")
import rpc, forknet as F
import fixtures

WB = fixtures.TARGETS["wavebreak"]
INTEREST = {0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 16, 17, 18, 24, 25, 26, 32, 33, 40, 41, 42,
            48, 49, 50, 51, 56, 57, 58}


def main(limit=250):
    found, scanned = fixtures.newest_program_txs(WB, limit=limit, tag_filter=INTEREST)
    print(f"scanned {len(scanned)} successful txs; recovered tags: {sorted(found)}")
    allacct = []
    for t, f in found.items():
        allacct += [a["pubkey"] for a in f["ix"]["accounts"]]
    allacct = sorted(set(allacct))
    exist = F.get_many(allacct)
    missing = [a for a, v in exist.items() if v is None]
    print(f"fixture accounts total {len(allacct)}, missing at fork tip {len(missing)}")
    out = {}
    for t, f in sorted(found.items()):
        miss = [a["pubkey"] for a in f["ix"]["accounts"] if exist.get(a["pubkey"]) is None]
        f["missingAtFork"] = miss
        f["complete"] = not miss
        out[str(t)] = f
        print(f"  tag {t:>3} slot={f['slot']:>10} nAcc={len(f['ix']['accounts']):>3} "
              f"dataLen={len(bytes.fromhex(f['ix']['data_hex'])):>4} complete={f['complete']}"
              + (f"  MISSING={len(miss)}" if miss else ""))
    json.dump({"program": WB, "scannedTxs": len(scanned), "forkSlot": F.get_slot(),
               "mainnetSlot": rpc.get_slot(), "forms": out},
              open("/home/user/orca-audit/recon/wb_fixtures_verified.json", "w"), indent=1)
    print("saved recon/wb_fixtures_verified.json")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 250)
