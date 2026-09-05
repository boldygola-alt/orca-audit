"""Wavebreak live-state enumeration (read-only mainnet RPC).

BondingCurve layout (verified against deployed ELF 1.1.5 + official client codegen):
 0:u8 disc | 32 base_mint | 32 quote_mint | 32 creator | 1 retain_mint_authority
 | 1 buy_requires_permission | 32 buy_bitmap | 1 sell_requires_permission | 32 sell_bitmap
 | 2 quote_fee_bps | 2 base_fee_bps | 8 control_points | 16 start_price | 16 end_price
 | 8 quote_amount | 8 base_amount | 8 launch_time | 8 creator_reward | 8 graduation_target
 | 8 graduation_time | 8 graduation_reward | 8 max_buy | 8 max_sell | 2 swap_fee_bps
 | 2 base_allocation_bps | 8*128 graduation_methods | 2 min_reserve_bps | 2 pad | 8 preminted
MintConfig also has size 2048 -> distinguished by discriminator byte.
"""
import struct, json, base64, sys, time

SIZE = 2048


def parse_curve(addr, data):
    o = 0

    def u8():
        nonlocal o
        v = data[o]; o += 1; return v

    def u16():
        nonlocal o
        v = struct.unpack_from("<H", data, o)[0]; o += 2; return v

    def u64():
        nonlocal o
        v = struct.unpack_from("<Q", data, o)[0]; o += 8; return v

    def u128():
        nonlocal o
        v = struct.unpack_from("<Q", data, o)[0] | (struct.unpack_from("<Q", data, o + 8)[0] << 64)
        o += 16; return v

    def pk():
        nonlocal o
        from solders.pubkey import Pubkey
        v = str(Pubkey.from_bytes(data[o:o + 32])); o += 32; return v

    d = {}
    d["address"] = addr
    d["discriminator"] = u8()
    d["base_mint"] = pk()
    d["quote_mint"] = pk()
    d["creator"] = pk()
    d["retain_mint_authority"] = bool(u8())
    d["buy_requires_permission"] = bool(u8())
    o += 32
    d["sell_requires_permission"] = bool(u8())
    o += 32
    d["quote_fee_bps"] = u16()
    d["base_fee_bps"] = u16()
    d["control_points"] = [u16() for _ in range(4)]
    d["start_price"] = u128()
    d["end_price"] = u128()
    d["quote_amount"] = u64()
    d["base_amount"] = u64()

    def i64():
        nonlocal o
        v = struct.unpack_from("<q", data, o)[0]; o += 8; return v
    d["launch_time"] = i64()
    d["creator_reward"] = u64()
    d["graduation_target"] = u64()
    d["graduation_time"] = u64()
    d["graduation_reward"] = u64()
    d["max_buy_amount"] = u64()
    d["max_sell_amount"] = u64()
    d["swap_fee_bps"] = u16()
    d["base_allocation_bps"] = u16()
    methods = []
    for i in range(8):
        m = {}
        m["label"] = u8()
        m["graduated"] = bool(u8())
        m["fee_tier_index"] = u16()
        m["split_bps"] = u16()
        m["destination"] = pk()
        m["unlocked"] = bool(u8())
        o += 89
        methods.append(m)
    d["graduation_methods"] = methods
    d["min_reserve_bps"] = u16()
    o += 2
    d["preminted_supply"] = u64()
    d["_offset_used"] = o
    return d


def fetch_curves(rpc, filters=None, max_results=4000):
    params = ["waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF",
              {"encoding": "base64", "commitment": "confirmed",
               "filters": (filters or [{"dataSize": SIZE}]),
               "dataSlice": {"offset": 0, "length": 1330}}]
    r = rpc.rpc("getProgramAccounts", params, timeout=120)
    if "error" in r:
        return None, r["error"]
    out = []
    from solders.pubkey import Pubkey
    for it in r["result"]:
        raw = base64.b64decode(it["account"]["data"][0])
        if len(raw) < 1330:
            continue
        if raw[0] != 2:      # BondingCurve only
            continue
        try:
            c = parse_curve(it["pubkey"], raw)
        except Exception as e:
            c = {"address": it["pubkey"], "parse_error": str(e)}
        c["lamports"] = it["account"]["lamports"]
        out.append(c)
    return out, None


def ata_addr(owner, mint, token_program, ata="ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"):
    from solders.pubkey import Pubkey
    a, _bump = Pubkey.find_program_address(
        [bytes(Pubkey.from_string(owner)), bytes(Pubkey.from_string(token_program)),
         bytes(Pubkey.from_string(mint))], Pubkey.from_string(ata))
    return str(a)


if __name__ == "__main__":
    sys.path.insert(0, "/home/user/orca-audit/tools")
    import rpc
    curves, err = fetch_curves(rpc)
    if err:
        print("ERR", json.dumps(err)[:400]); sys.exit(1)
    print("curves:", len(curves))
    json.dump(curves, open("/home/user/orca-audit/recon/wb_curves.json", "w"), indent=1)
