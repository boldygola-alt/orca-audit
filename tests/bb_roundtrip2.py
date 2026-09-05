"""Busybox swap accounting: multi-leg round trip on a live small market (GtBJeuFzSCnDf9...,
USDT/USDC, reserves ~12.4M/13.6M units) plus a repeated same-direction leg to see whether the
anti-arbitrage penalty (arbPenaltyPerM / cuPenaltyMultiplier) actually escalates and whether an
attacker can dodge it (fee-bypass => attacker-positive delta).
Swaps are permissionless by design here; the audit question is whether the guards hold.
"""
import sys, json, struct, base64
sys.path.insert(0,'/home/user/orca-audit/tools')
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey
BB="riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j"
MKT="GtBJeuFzSCnDf9Eqycuf4DVxqVw1gmpv5VdsTBULV579"
actor=F.load_actor(); A=str(actor.pubkey())
def prog_of(m):
    v=F.get_account(m); return (v or {}).get("owner") or F.TOKEN
def ata_of(o,m,p):
    return str(Pubkey.find_program_address([bytes(F.pk(o)),bytes(F.pk(p)),bytes(F.pk(m))],F.pk(F.ATA))[0])
def raw(a):
    v=F.get_account(a); return None if not v else base64.b64decode(v["data"][0])
def tok(a):
    d=raw(a)
    return None if not d or len(d)<72 else struct.unpack_from("<Q",d,64)[0]
def st(a):
    d=raw(a)
    return {"sequence":struct.unpack_from("<Q",d,136)[0],"validUntil":struct.unpack_from("<Q",d,144)[0],
            "variant":d[152],"price":int.from_bytes(d[153:169],"little"),
            "minSpread":struct.unpack_from("<i",d,664)[0],"arb":struct.unpack_from("<I",d,668)[0],
            "jitod":struct.unpack_from("<I",d,672)[0],"cu":d[2],"imb":d[3],
            "resA":struct.unpack_from("<Q",d,736)[0],"resB":struct.unpack_from("<Q",d,744)[0],
            "mintA":F.b58(d[72:104]),"mintB":F.b58(d[104:136]),"auth":F.b58(d[8:40]),"updater":F.b58(d[40:72]),
            "lamports":F.get_account(a)["lamports"]}
def M(k,w=False,s=False): return F.AM(k,writable=w,signer=s)
LOG=[]
def swap(tag,amount,is_a,partial=0,sl=None,src=None,dst=None,signer=None):
    s0=st(MKT); mA,mB=s0["mintA"],s0["mintB"]; pa,pb=prog_of(mA),prog_of(mB)
    va,vb=src or ata_of(A,mA,pa), dst or ata_of(A,mB,pb)
    data=bytes([tag])+struct.pack("<Q",amount)+bytes([1 if is_a else 0])
    data+=bytes([0]) if sl is None else (bytes([1])+struct.pack("<QQ", sl[0] & (2**64-1), sl[1] & (2**64-1)) if isinstance(sl,tuple) else bytes([2])+struct.pack("<Q", sl & (2**64-1)))
    data+=bytes([partial])
    return Instruction(F.pk(BB),data,[M(signer or A,w=True,s=True),M(MKT,w=True),M(mA,w=True),M(mB,w=True),
        M(va,w=True),M(vb,w=True),M(ata_of(MKT,mA,pa),w=True),M(ata_of(MKT,mB,pb),w=True),
        M(pa),M(pb),M(F.MEMO),M(F.IX_SYSVAR)]),[va,vb,ata_of(MKT,mA,pa),ata_of(MKT,mB,pb)]
def step(nm,ixs,watch,note=""):
    ixs = ixs if isinstance(ixs,(list,tuple)) else [ixs]
    b={w:tok(w) for w in watch}; s0=st(MKT); slot=F.get_slot()
    r=F.send(ixs,actor); det=r.get("detail",{})
    a={w:tok(w) for w in watch}; s1=st(MKT)
    logs=[l.strip().split("log:")[-1].strip() for l in det.get("logs",[]) if "log:" in l or "failed" in l]
    e={"case":nm,"note":note,"forkSlot":slot,"sig":r.get("result"),"err":det.get("err") or r.get("error"),
       "logs":logs[:5],"tokenDelta":{w:(a[w] or 0)-(b[w] or 0) for w in watch if (a[w] or 0)!=(b[w] or 0)},
       "reserves":(s0["resA"],s1["resA"],s0["resB"],s1["resB"]),"seq":(s0["sequence"],s1["sequence"]),
       "price":(s0["price"],s1["price"])}
    LOG.append(e)
    print(f"\n### {nm}  [{note}]")
    print("   err:",json.dumps(e["err"])[:120]," logs:"," | ".join(logs)[:200])
    print("   tokenDelta:",json.dumps(e["tokenDelta"]))
    print("   reserves A",f"{s0['resA']:,} -> {s1['resA']:,}"," B",f"{s0['resB']:,} -> {s1['resB']:,}",
          " seq",s0["sequence"],"->",s1["sequence"])
    return e
s0=st(MKT)
dA=raw(s0["mintA"])[44]; dB=raw(s0["mintB"])[44]
print("market state:",json.dumps(s0)[:600])
for m in (s0["mintA"],s0["mintB"]):
    _,x=F.create_ata(A,m,prog_of(m),A); F.send([x],actor)
# attacker-side funding (fork fixture, documented)
u=ata_of(A,s0["mintA"],prog_of(s0["mintA"])); v=raw(u)
d=bytearray(v); struct.pack_into("<Q",d,64,50*10**dA)
F.rpc.rpc("surfnet_setAccount",[u,{"lamports":F.get_account(u)["lamports"],"data":bytes(d).hex(),"owner":F.get_account(u)["owner"],"executable":False}],url=F.FORK)
LOG.append({"fixture":"attacker mintA ATA funded 50 units (fork cheatcode); not exploit evidence"})
# now the reverse leg to close the round trip
# zero-slippage + huge partial-fill request (fee/slippage guard probes)
ix,watch=swap(2,10**dA,True,partial=1,sl=None); step("BB-RT5 tiny amount with partial fill allowed",ix,watch,"rounding floor")
ix,watch=swap(2,10**dA,True,sl=(0,2**127-1)); step("BB-RT6 MaxExecutionPrice extreme",ix,watch,"slippage bound accepts worst case")
ix,watch=swap(2,10**dA,True,sl=(0,1)); step("BB-RT7 MaxExecutionPrice=(0,1) impossible",ix,watch,"slippage guard rejects")
# duplicate mutable account: pass the market vault as the trader's B account
ix,watch=swap(2,10**dA,True,dst=ata_of(MKT,s0["mintB"],prog_of(s0["mintB"])))
step("BB-RT8 trader B account := market vault B",ix,watch,"payout redirected to the market's own vault")
json.dump({"market":MKT,"start":s0,"log":LOG},open("/home/user/orca-audit/evidence/BBR_roundtrip2.json","w"),indent=1)
print("\nsaved evidence/BBR_roundtrip2.json")