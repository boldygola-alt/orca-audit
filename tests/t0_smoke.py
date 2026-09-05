import sys, json, struct
sys.path.insert(0,'/home/user/orca-audit/tools')
import forknet as F
actor = F.load_actor()
print("actor:", actor.pubkey(), "fork slot:", F.get_slot())
ata, ix_create = F.create_ata(str(actor.pubkey()), F.WSOL, F.TOKEN, str(actor.pubkey()))
ata2, ix_sync = F.wsol_sync_instruction(str(actor.pubkey()))
assert ata == ata2, (ata, ata2)
before = F.snapshot([str(actor.pubkey()), ata], tokenaddrs={ata})
r = F.send([ix_create, ix_sync], actor)
after = F.snapshot([str(actor.pubkey()), ata], tokenaddrs={ata})
print("sig:", r.get("result"), "err:", json.dumps(r.get("detail",{}).get("err")))
print("diff:", json.dumps(F.diff(before, after)))
print("wsol:", after[ata].get("token"), "actor lamports:", after[str(actor.pubkey())]["lamports"])
json.dump({"slot": F.get_slot(), "sig": r.get("result"), "detail": r.get("detail"),
           "before": before, "after": after, "diff": F.diff(before, after)},
          open("/home/user/orca-audit/evidence/t0_smoke.json","w"), indent=1)
