"""Wavebreak LP-escrow handlers (LpHarvest 56 / LpTransfer 57 / LpTakeover 58) on live-derived PDAs.

The escrow PDA is ["lp_escrow", authority] (verified against the v1.1.5 client's own test vectors:
authority A1tYHa32.. -> escrow DKX4hTCVRz..). Live mainnet state shows 0 token-2022 position
accounts held by any lp_escrow, so a *funded* harvest/transfer fixture does not exist; these tests
therefore establish exactly which guard rejects an unprivileged caller (seed binding vs privilege
vs authority binding) rather than relying on a zero-balance success.
"""
import sys, json, base64, struct
sys.path.insert(0,'/home/user/orca-audit/tools')
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey
WB="waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
ACTOR=F.load_actor(); A=str(ACTOR.pubkey())
def pda(seeds):
    for b in range(255,-1,-1):
        try: return str(Pubkey.create_program_address(list(seeds)+[bytes([b])], F.pk(WB)))
        except Exception: continue
    return None
def M(k,w=False,s=False): return F.AM(k,writable=w,signer=s)
def verify_client_vectors():
    # the client's own unit-test vectors, recomputed with our seed derivation
    v1=pda([b"lp_escrow", bytes(F.pk("A1tYHa3233WKDX5fZuZNmHMUVTSB12sR1RoVeGT8XV85"))])
    v2=pda([b"mint_config", bytes(F.pk("A1tYHa3233WKDX5fZuZNmHMUVTSB12sR1RoVeGT8XV85")), bytes([10])])
    v3=pda([b"bonding_curve", bytes(F.pk("62dSkn5ktwY1PoKPNMArZA4bZsvyemuknWUnnQ2ATTuN"))])
    v4=pda([b"permission_config", bytes(F.pk("62dSkn5ktwY1PoKPNMArZA4bZsvyemuknWUnnQ2ATTuN"))])
    return {"lp_escrow":(v1,"DKX4hTCVRzu9nLJJvmtxiKU2wBLUyQby5k6cMDgNsSz2",v1=="DKX4hTCVRzu9nLJJvmtxiKU2wBLUyQby5k6cMDgNsSz2"),
            "mint_config":(v2,"4UUnyGNdumaALFL21mFwocZvLuoqFeBrszJkkET3LJJH",v2=="4UUnyGNdumaALFL21mFwocZvLuoqFeBrszJkkET3LJJH"),
            "bonding_curve":(v3,"umyTygGGkyBw4oCxxKRPrkFCAFg1bL7DqSHwtgfKoh3",v3=="umyTygGGkyBw4oCxxKRPrkFCAFg1bL7DqSHwtgfKoh3"),
            "permission_config":(v4,"GBriG7QANWP33M5diRdCUruEXcWmu3YCo8kAjEJDEUA9",v4=="GBriG7QANWP33M5diRdCUruEXcWmu3YCo8kAjEJDEUA9")}
RES=[]
def run(name,ixs,watch,note=""):
    b={a:(F.get_account(a) or {}) for a in watch}
    slot0=F.get_slot(); r=F.send(ixs,ACTOR); a={x:(F.get_account(x) or {}) for x in watch}
    det=r.get("detail",{}); logs=[l.strip() for l in det.get("logs",[])]
    d={}
    for k in watch:
        bl=(b[k] or {}).get("lamports"); al=(a[k] or {}).get("lamports")
        bh=F.hashlib.sha256(base64.b64decode(b[k]["data"][0])).hexdigest() if b.get(k,{}).get("data") else None
        ah=F.hashlib.sha256(base64.b64decode(a[k]["data"][0])).hexdigest() if a.get(k,{}).get("data") else None
        if bl!=al or bh!=ah: d[k]={"lamports":[bl,al],"hashChanged":bh!=ah}
    rec={"case":name,"note":note,"forkSlotBefore":slot0,"forkSlotAfter":F.get_slot(),"sig":r.get("result"),
         "err":det.get("err") or r.get("error"),"logs":logs,"deltas":d,"before":{k:{'lamports':(v or {}).get('lamports'),'space':(v or {}).get('space')} for k,v in b.items()},
         "after":{k:{'lamports':(v or {}).get('lamports'),'space':(v or {}).get('space')} for k,v in a.items()}}
    RES.append(rec)
    print(f"\n### {name}  [{note}]")
    print("   err:",json.dumps(rec["err"])[:140])
    print("   logs:"," | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:300])
    print("   deltas:",json.dumps(d)[:260])
    return rec
def main():
    print("PDA seed vectors recomputed from the deployed program id (must match the v1.1.5 client's own unit tests):")
    vec=verify_client_vectors()
    for k,(got,exp,ok) in vec.items(): print(f"   {k:20s} ok={ok}  {got}")
    LP="BWyVTPPRW7A5kpHM3tNgPhRz6JekR9sL8iFx2o4X1w9C"   # live address with privileges; also a busybox market authority
    esc=pda([b"lp_escrow", bytes(F.pk(LP))]); newesc=pda([b"lp_escrow", bytes(F.pk(A))])
    print(f"\nescrow(live authority)={esc} exists={bool(F.get_account(esc))}")
    print(f"escrow(attacker)      ={newesc} exists={bool(F.get_account(newesc))}")
    watch=[A,esc,newesc,LP]
    # LpTransfer: [lpAuthority*, newLpAuthority, lpEscrow W, newLpEscrow W, positionMint, position,
    #              positionTokenAccount W, newPositionTokenAccount W, lockConfig, system, token22, ata, whirlpool]
    dummy=esc
    lt=Instruction(F.pk(WB),bytes([57]),[M(LP,w=True,s=True),M(A),M(esc,w=True),M(newesc,w=True),
        M(dummy,w=True),M(dummy,w=True),M(dummy,w=True),M(dummy,w=True),M(dummy),M(F.SYSTEM),
        M(F.TOKEN22),M(F.ATA),M("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")])
    run("WB-L01 lpTransfer signed by a LIVE authority key? (we cannot sign as it -> attacker-signed variant)",
        [Instruction(F.pk(WB),bytes([57]),[M(A,w=True,s=True),M(LP),M(esc,w=True),M(newesc,w=True),
         M(dummy,w=True),M(dummy,w=True),M(dummy,w=True),M(dummy,w=True),M(dummy),M(F.SYSTEM),
         M(F.TOKEN22),M(F.ATA),M("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")])], watch,
        "attacker as lpAuthority over the live escrow PDA")
    # LpTakeover: [authority*, authorityConfig, lpAuthority, newLpAuthority, lpEscrow W, newLpEscrow W, ...]
    ltk=Instruction(F.pk(WB),bytes([58]),[M(A,w=True,s=True),M("5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"),
        M(LP),M(A),M(esc,w=True),M(newesc,w=True),M(dummy,w=True),M(dummy,w=True),M(dummy,w=True),
        M(dummy,w=True),M(dummy),M(F.SYSTEM),M(F.TOKEN22),M(F.ATA),
        M("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")])
    run("WB-L02 lpTakeover by attacker (ExecuteLpTakeover privilege holder only)",[ltk],watch,
        "does the attacker reach a position move?")
    # LpHarvest: [lpAuthority*, lpEscrow, whirlpool, position, positionTokenAccount, tick arrays, mints, atAs, vaults, ...]
    lh=Instruction(F.pk(WB),bytes([56]),[M(A,w=True,s=True),M(esc,w=True)]+[M(esc,w=True) for _ in range(29)])
    run("WB-L03 lpHarvest by attacker on the live escrow",[lh],watch,"31-account live shape, attacker as lpAuthority")
    json.dump({"pdaVectorsRecomputed":vec,"escrowLive":esc,"escrowAttacker":newesc,"results":RES},
              open("/home/user/orca-audit/evidence/WBL_lp.json","w"),indent=1)
    print("\nsaved evidence/WBL_lp.json")
if __name__=="__main__":
    main()
