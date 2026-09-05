"""Recover the exact PDA seed vectors of the Wavebreak graduation flow by solving the
deployed program's own seed vocabulary against a *live mainnet* GraduateWhirlpool
transaction's account list (recon/wb_graduate_fixture.json).

Nothing here is invented: the words come from the deployed ELF's .rodata (0x6b6df region
and 0x6b91a region), and a derivation is only accepted when it reproduces an address that
real mainnet state actually used.
"""
import json, struct, sys, itertools
from solders.pubkey import Pubkey

WB = Pubkey.from_string("waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF")
WHIRL = Pubkey.from_string("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc")
ATA = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")

WORDS = ["bonding_curve", "mint_config", "permission_config", "consumed_permission",
         "lp_escrow", "authority_config", "whirlpool", "oracle", "whirlpool_position_mint",
         "tick_array", "token_badge", "lock_config", "position", "fee_tier", "config",
         "metadata", "whirlpool_config", "init_authority", "update_authority",
         "whirlpool_authority", "pool_authority", "badge", "launch", "curve", "escrow",
         "lp", "position_mint", "tick_array_lower", "tick_array_upper"]

ROLES = ['signer', 'lp_authority', 'bonding_curve', 'quote_mint', 'quote_vault',
         'signer_quote_ata', 'lp_authority_quote_ata', 'whirlpool_quote_vault', 'base_mint',
         'base_vault', 'lp_authority_base_ata', 'whirlpool_base_vault', 'whirlpool_config',
         'fee_tier', 'whirlpool', 'oracle', 'position', 'position_mint', 'position_token_account',
         'lp_authority_token_account', 'lower_tick_array', 'upper_tick_array',
         'quote_token_badge', 'base_token_badge', 'whirlpool_init_authority',
         'whirlpool_update_authority', 'lock_config', 'system_program', 'ata_program',
         'quote_token_program', 'base_token_program', 'token22_program', 'memo_program',
         'whirlpool_program', 'rent']


def derive(program, seeds):
    try:
        return str(Pubkey.create_program_address(seeds, program))
    except Exception:
        return None


def load_fixture():
    f = json.load(open("/home/user/orca-audit/recon/wb_graduate_fixture.json"))
    accts = f["ixs"][0]["accounts"]
    return {ROLES[i]: a["pubkey"] for i, a in enumerate(accts)}, f


def solve(target, bases, programs=(WB, WHIRL, ATA), ints=True, deep=True):
    """Return (program, [seeds]) reproducing target, or None."""
    hits = []
    for pid in programs:
        for w in WORDS:
            if derive(pid, [w.encode()]) == target:
                hits.append((pid, [w]))
    for pid in programs:
        for w in WORDS:
            for b in bases:
                if derive(pid, [w.encode(), bytes(b)]) == target:
                    hits.append((pid, [w, "pk1"]))
                    return (str(pid), w, [bytes(b).hex()], hits)
    for pid in programs:
        for w in WORDS:
            for b1, b2 in itertools.permutations(bases, 2):
                if derive(pid, [w.encode(), bytes(b1), bytes(b2)]) == target:
                    return (str(pid), w, [bytes(b1).hex(), bytes(b2).hex()], hits)
    if ints:
        # numeric suffix variants (fee tier index u16, tick index i32)
        for pid in programs:
            for w in WORDS:
                for b in bases:
                    for n in list(range(0, 400)) + [-894000, -887200, -886400, -885600, 885600, 886400, 887200, 894000]:
                        for enc in (struct.pack("<H", n % 65536), struct.pack("<i", n)):
                            if derive(pid, [w.encode(), bytes(b), enc]) == target:
                                return (str(pid), w, [bytes(b).hex(), enc.hex()], hits)
    return None


if __name__ == "__main__":
    fx, f = load_fixture()
    keys = list(fx)
    bases = sorted({Pubkey.from_string(fx[k]) for k in keys})
    out = {}
    targets = sys.argv[1:] or ["lp_authority", "whirlpool_config", "fee_tier", "whirlpool",
                               "oracle", "position", "position_mint", "lower_tick_array",
                               "upper_tick_array", "quote_token_badge", "base_token_badge",
                               "whirlpool_init_authority", "whirlpool_update_authority",
                               "lock_config", "quote_vault", "base_vault"]
    for t in targets:
        tgt = fx[t]
        r = solve(Pubkey.from_string(tgt), bases)
        print(t, tgt, "->", r if r is None else (r[0], r[1], r[2]))
        out[t] = {"addr": tgt, "solved": (None if r is None else {"program": r[0], "word": r[1], "extra": r[2]})}
    json.dump({"fixture": f["signature"], "solved": out, "accounts": fx}, open("/home/user/orca-audit/recon/s4_grad_seeds.json", "w"), indent=1)
