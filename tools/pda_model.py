"""Recover / verify the PDA seed vectors of the Wavebreak graduation flow by solving a REAL
mainnet GraduateWhirlpool transaction's account list (recon/wb_graduate_fixture.json).

Only seed words that physically exist in the deployed Wavebreak ELF .rodata are considered.
A rule is accepted only if find_program_address reproduces the address mainnet actually used.
"""
import json, struct, sys
from solders.pubkey import Pubkey

WB = Pubkey.from_string("waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF")
WHIRL = Pubkey.from_string("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")
ATA = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
TOKEN22 = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
CFG = Pubkey.from_string("2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ")

WORDS = ["bonding_curve", "mint_config", "permission_config", "consumed_permission",
         "lp_escrow", "authority_config", "whirlpool", "oracle", "whirlpool_position_mint",
         "tick_array", "token_badge", "lock_config", "position", "fee_tier", "config",
         "metadata", "position_bundle", "whirlpool_authority", "pool_authority",
         "lp_authority", "launch", "token_launch", "graduation", "init_authority",
         "fee_authority", "update_authority"]

ROLES = ['signer', 'lp_authority', 'bonding_curve', 'quote_mint', 'quote_vault',
         'signer_quote_ata', 'lp_authority_quote_ata', 'whirlpool_quote_vault', 'base_mint',
         'base_vault', 'lp_authority_base_ata', 'whirlpool_base_vault', 'whirlpool_config',
         'fee_tier', 'whirlpool', 'oracle', 'position', 'position_mint', 'position_token_account',
         'lp_authority_token_account', 'lower_tick_array', 'upper_tick_array',
         'quote_token_badge', 'base_token_badge', 'whirlpool_init_authority',
         'whirlpool_update_authority', 'lock_config', 'system_program', 'ata_program',
         'quote_token_program', 'base_token_program', 'token22_program', 'memo_program',
         'whirlpool_program', 'rent']


def fp(prog, seeds):
    """find_program_address -> address string, or None if no bump works (never happens in practice)."""
    try:
        return str(Pubkey.find_program_address([s if isinstance(s, bytes) else bytes(s) for s in seeds], prog)[0])
    except Exception:
        return None


def ata(owner, mint, prog):
    return fp(ATA, [bytes(owner), bytes(prog), bytes(mint)])


def load(path="/home/user/orca-audit/recon/wb_graduate_fixture.json"):
    f = json.load(open(path))
    return {ROLES[i]: Pubkey.from_string(a["pubkey"]) for i, a in enumerate(f["ixs"][0]["accounts"])}, f


def selftest():
    ok = True
    pool = Pubkey.from_string("2kJmUjxWBwL2NGPBV2PiA5hWtmLCqcKY6reQgkrPtaeS")
    ok &= fp(WHIRL, [b"oracle", pool]) == "821SHenpVGYY7BCXUzNhs8Xi4grG557fqRw4wzgaPQcS"
    pm = Pubkey.from_string("6sf6fSK6tTubFA2LMCeTzt4c6DeNVyA6WpDDgtWs7a5p")
    ok &= fp(WHIRL, [b"position", pm]) == "2EtH4ZZStW8Ffh2CbbW4baekdtWgPLcBXfYQ6FRmMVsq"
    ok &= fp(WHIRL, [b"tick_array", pool, b"0"]) == "8PhPzk7n4wU98Z6XCbVtPai2LtXSxYnfjkmgWuoAU8Zy"
    ok &= fp(WHIRL, [b"fee_tier", CFG, struct.pack("<H", 1)]) == "62dSkn5ktwY1PoKPNMArZA4bZsvyemuknWUnnQ2ATTuN"
    a = Pubkey.from_string("So11111111111111111111111111111111111111112")
    b = Pubkey.from_string("2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo")
    ok &= fp(WHIRL, [b"whirlpool", CFG, a, b, struct.pack("<H", 2)]) == "JDQ9GDphXV5ENDrAQtRFvT98m3JwsVJJk8BYHoX8uTAg"
    ok &= fp(WHIRL, [b"token_badge", CFG, b]) == "HX5iftnCxhtu11ys3ZuWbvUqo7cyPYaVNZBrLL67Hrbm"
    ok &= fp(WB, [b"bonding_curve", Pubkey.from_string("62dSkn5ktwY1PoKPNMArZA4bZsvyemuknWUnnQ2ATTuN")]) == \
        "umyTygGGkyBw4oCxxKRPrkFCAFg1bL7DqSHwtgfKoh3"
    ok &= fp(WB, [b"authority_config"]) == "5yXDawwQ5s3hZXMJjLWryvDWsNKHYKqp6vkdSfgsaee4"
    print("client-vector selftest:", "PASS" if ok else "FAIL")
    return ok


def solve(fx, targets, bases_extra=()):
    bases = list(fx.items()) + list(bases_extra)
    out = {}
    for t in targets:
        tgt = str(fx[t])
        done = False
        for prog, pn in ((WHIRL, "whirl"), (WB, "wavebreak")):
            for w in WORDS:
                if fp(prog, [w.encode()]) == tgt:
                    print(f"{t:26s} = {pn}:[{w}]"); out[t] = [pn, w]; done = True; break
                for n1, b1 in bases:
                    if fp(prog, [w.encode(), b1]) == tgt:
                        print(f"{t:26s} = {pn}:[{w}, {n1}]"); out[t] = [pn, w, n1]; done = True; break
                    for n2, b2 in bases:
                        for tail, desc in ((None, None), (struct.pack("<H", 0), "u16=0")):
                            seeds = [w.encode(), b1, b2] if tail is None else [w.encode(), b1, b2, tail]
                            if fp(prog, seeds) == tgt:
                                lbl = f"{pn}:[{w}, {n1}, {n2}]" + ("" if desc is None else f" +{desc}")
                                print(f"{t:26s} = {lbl}"); out[t] = [pn, w, n1, n2, desc]; done = True; break
                        if done: break
                    if done: break
                if done: break
            if done: break
        if not done:
            print(f"{t:26s} UNRESOLVED {tgt}")
            out[t] = None
    return out


if __name__ == "__main__":
    if not selftest():
        sys.exit(1)
    fx, f = load()
    print("== canonical whirlpool formulas vs fixture")
    pool = fx["whirlpool"]
    checks = {
        "oracle": fp(WHIRL, [b"oracle", pool]) == str(fx["oracle"]),
        "position": fp(WHIRL, [b"position", fx["position_mint"]]) == str(fx["position"]),
        "lock_config": fp(WHIRL, [b"lock_config", fx["position"]]) == str(fx["lock_config"]),
    }
    for i in range(0, 8192):
        if fp(WHIRL, [b"fee_tier", CFG, struct.pack("<H", i)]) == str(fx["fee_tier"]):
            checks["fee_tier_index"] = i
    for (a, an), (b, bn) in [((fx["base_mint"], "base"), (fx["quote_mint"], "quote")),
                              ((fx["quote_mint"], "quote"), (fx["base_mint"], "base"))]:
        for i in range(0, 8192):
            if fp(WHIRL, [b"whirlpool", CFG, a, b, struct.pack("<H", i)]) == str(pool):
                checks["pool"] = f"mintA={an},mintB={bn},feeTierIndex={i}"
    for k, v in checks.items():
        print(f"  {k:16s} {v}")
    # tick arrays: search plausible start indices (multiples of tick spacing)
    spacing = None
    for sp in [1, 4, 8, 16, 32, 64, 96, 128, 192, 256]:
        hits = 0
        for m in range(-3600, 3601):
            st = m * sp
            if fp(WHIRL, [b"tick_array", pool, str(st).encode()]) == str(fx["lower_tick_array"]):
                hits += 1
                print("  lower tick_array start index", st, "spacing", sp)
            if fp(WHIRL, [b"tick_array", pool, str(st).encode()]) == str(fx["upper_tick_array"]):
                hits += 1
                print("  upper tick_array start index", st, "spacing", sp)
        if hits:
            break
    # token accounts
    print("== ata formulas")
    mints = {"quote_mint": fx["quote_mint"], "base_mint": fx["base_mint"], "position_mint": fx["position_mint"]}
    owners = {"signer": fx["signer"], "lp_authority": fx["lp_authority"], "curve": fx["bonding_curve"],
              "pool": fx["whirlpool"]}
    for t in ["quote_vault", "base_vault", "signer_quote_ata", "lp_authority_quote_ata",
              "lp_authority_base_ata", "lp_authority_token_account", "position_token_account",
              "whirlpool_quote_vault", "whirlpool_base_vault"]:
        h = []
        for on, o in owners.items():
            for mn, m in mints.items():
                for pn, p in (("Token", TOKEN), ("Token22", TOKEN22)):
                    if ata(o, m, p) == str(fx[t]):
                        h.append(f"ATA({on},{mn},{pn})")
        print(f"  {t:26s} {' '.join(h) if h else 'unmatched '+str(fx[t])}")
    print("== wavebreak-side seeds")
    solved = solve(fx, ["lp_authority", "position_mint", "quote_token_badge", "base_token_badge",
                        "whirlpool_init_authority", "whirlpool_update_authority"])
    json.dump({"checks": {k: str(v) for k, v in checks.items()}, "solved": solved},
              open("/home/user/orca-audit/recon/s4_grad_seeds.json", "w"), indent=1)
