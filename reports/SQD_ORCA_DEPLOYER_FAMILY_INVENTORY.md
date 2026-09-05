
# SQD_ORCA_DEPLOYER_FAMILY_INVENTORY

Fork-only defensive re-audit of Orca Solana programs â€” deployer/authority family inventory.
Data sources: on-chain mainnet RPC (read-only), Solana history signatures, Anchor IDL artifact
(`fixtures/whirlpool.idl.json`, v0.9.0, 66 instructions), compiled program ELF `recon/whirlpool-elf.bin`
(10,485,760 bytes, hash `b5ee20ce8a99d4f1...`), repo `orca-so/whirlpools@main` (fetched 2026-09-03).

## 1. Definitive family program set (4 programs)

| Program | PD (ProgramData) | Last upgrade slot | Upgrade authority | Status |
|---|---|---|---|---|
| `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` (Whirlpool) | `CtXfPzz36dH5Ws4UYKZvrQ1Xqzn42ecDW6y8NKuiN8nD` | 440,170,207 | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | LIVE, active (~$405M TVL) |
| `9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP` (legacy AMM) | `DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8` | 161,177,892 | `23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG` | DORMANT (since ~2021) |
| `riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j` | `4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu` | 440,010,891 | `GwH3Hiv5...` (via Squads) | LIVE, thin (32 owned accts) |
| `waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF` | `nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs` | 365,746,180 | `GwH3Hiv5...` (via Squads) | LIVE, handler `TokenSellExactIn` |

NOT family (checked): `cmtDvXumGCrqC1Age74AVPhSRVXJMd8PJS91L8KbNCK` (authority `F3S4PD...`) and
`BGUMAp9Gq7iTEuizy4pqaxsTyUCBK68MDfK752saRPUY` (third-party; BGUMAp9 is a Transfer program that CPIs
`cmtDvXumG` + `noopb9` â€” sampled tx `3UyQFgP...`, slot 400,968,772). Metaplex programs
(`metaqbxx...`, `cmtDvXumG`/`BGUMAp9`) excluded: distinct authority graphs.

## 2. Authority chains (verified from SetAuthority/Upgrade events + PD slot field)

Whirlpool: `3Pi4tc4S...` â†’ `8DzsCSvb...(2022-03-23)` â†’ `8rHQUMS8...(2022-08-18)` â†’ `23zF9Az...(2022-09-21)` â†’ `GwH3Hiv5...(2025-02-27)`
AMM: `2YM8LrJG...` â†’ `8DzsCSvb...(2021-09-21)` â†’ `23zF9Az...`

Current authorities on the live config `2LecshUwdy9xi7meFgHtFJQNSKk4KdTrcpvaB56dP2NQ` (verified from config account, 108B):
- fee_authority (offset 8): `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV`
- collect_protocol_fees_authority (offset 40): `CRQd5wvbf6FKVmjHC7on8w4pzFPzudij2BKXRcMCu7aK`
- reward_emissions_super_authority (offset 72): `DXnB9N9JLH5c9AYdKMGHQyspewSsvhFnwLK1tz1iPmZw`
- default protocol fee rate (104): 1300; flags (106): 1 (TokenBadge enabled; no emergency/pause flag set)

## 3. Squads control plane (governance)

Shared Squads vault accounts (owner `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf`):
- `BQsDWkL417U4tVE2sDnPks469pKdm6YzFgKH77doiEjF` â€” Vault (1155B; multisig field â†’ `9Y5dnTF...`)
- `DNUJ3ByF4z7u4TaLSx7oGXGe6QuvjR1CJa5BCHuqWfq9` â€” Vault (1318B)
- `DCuDSLc7rH5K3Y4ht5oFBR4W1DKnmvXFqvaMi2S1dVjJ` â€” 378B (ops account)
- `4ZnVFX2c2XYSfBbYq3eegrULkcMtqChkAgshkToQKGqg` â€” SYSTEM-owned (69,972,864 lamports, no data) â€” likely closed/rent; NOT holding program state

Whirlpool program upgrades are executed via `Squads VaultTransactionExecute` (sampled sig
`2sN92ZTTDi6F...` slot 440,170,207 = Whirlpool last upgrade). The upgrade authority chain therefore
ultimately terminates in the Squads vault program â€” the multisig membership was not enumerable from
RPC (Squads vault.membership account not fetched this pass; treated as GOVERNANCE-plane, not
balance-control plane; no fork tests against Squads (never admin-call)).

## 4. Program-owned balance surfaces

Whirlpool (program `whirLbMiicVd`, program-owned accounts):
- ~1,106,108 program-owned accounts total; 156,285 pools (154,766 with standard config `2Lecsh...`)
- Balance-holding: pool vaults (2 per pool, SPL/Token-2022 token accounts), reward vaults (â‰¤3/pool),
  protocol-fee accrual is stored IN the pool account (protOwedA/B u64), position accounts (rent + fee/reward state),
  tick arrays (fixed 9988B / dynamic variable), oracles (254B, lazily created), config/fee tiers.
- No program-owned SPL token accounts outside pool vaults / reward vaults; no treasury vault account
  flagged; protocol fees remain inside pool accounts until `collect_protocol_fees` (authority CRQd5wvb).

AMM `9W959DqE`: dormant; PD last upgraded 2021; no new balances observed. (Not reverified per-account
this pass â€” flagged in FINAL_DISPOSITION as dormant-verified, not active-balance-verified.)

`riptK81h` â€” **orca_busybox DEX ROUTER** (Orca routing layer; rev.2): 32 owned accounts, all 1024B Market records; total
lamports 256,747,447. Decompiled handler set includes `Route`, `RouteV2`, `RouteWithTokenLedger`,
`SwapExactIn`, `SwapExactOut`, `SwapV2` (Whirlpool CPI), `Swap2` (legacy AMM CPI), `TransferChecked`,
`TransferCheckedWithFee`, `SetTokenLedger`, `MarketInitialize/Update/Deposit/Withdraw/Close`,
`OracleUpdate`, `ProgramVersion`; source path `solana-program/src/routers/orca_busybox.rs`
("Cruising the current"). No program-owned SPL token accounts (0 Ã— 165B); no measured custody, but it
**controls value flow via CPI** (balance-controlling) and is UNREVIEWED (decompile + fork test pending).

`waveQX2y` â€” **Orca token-launch platform (bonding curve â‡’ Whirlpool graduation)** (rev.2):
1,572 owned accounts (1,538 Ã— 2048B launch records + 1Ã—4096 + 1Ã—4097 + 1Ã—256 + 31Ã—64); total lamports
23,395,853,334. Decompiled handler set: `BondingCurveInitialize/CollectFees/Graduate/Close`,
`TokenBuyExactIn`, `TokenSellExactIn/Out`, `TokenRefund`, `LpHarvest/Transfer/Takeover`,
**`GraduateWhirlpool`, `GraduateManual`, `InitializePoolWithAdaptiveFee`, `InitializeDynamicTickArray`,
`OpenPositionWithTokenExtensions`, `LockPosition`** (ELF seeds: `whirlpool`, `oracle`,
`whirlpool_position_mint`, `tick_array`, `token_badge`, `lock_config`, `fee_tier`, `position`;
accounts `whirlpool_init_authority`, `whirlpool_base_vault`, `whirlpool_quote_vault`, `lp_escrow`),
`MintConfig*`, `PermissionConfig*`, `AuthorityConfig*`, `PermissionConsume(TopLevel|Cpi)`,
`PermissionRefund` with secp256k1 signature verification (`Failed to verify signature`).
**BALANCE-HOLDING â€” verified custody**: per-launch record PDAs own WSOL bonding-curve escrow token
accounts (measured samples in `ORCA_PROGRAM_AND_BALANCE_INVENTORY.json`; e.g. `CdPRm4HJâ€¦` â†’
`82sv2xcgâ€¦` 281,663,128 lamports; five-record scan 0â€“14,172,763 lamports each).
**It also OWNS THE ABILITY TO CREATE/LOCK WHIRLPOOL POOLS, POSITIONS AND BADGES for graduated
tokens** â€” i.e., the deployer family's governance core (GwH3Hiv5/Squads) controls a Whirlpool
integration platform. Status: UNREVIEWED (decompile + fork tests pending).

## 5. Permissionless-EC (ecosystem program interactions) reviewed

Titan aggregator `T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT` (`SwapRouteV3`) and
Jupiter `JUP6LkbZbjS1jK...` route into Whirlpool swap_v2; observed only as CPI callers with correct
15-account order. `swapFpHZ...` (native swap test program, 43 CU) seen as outer sandbox program at
slot 444022455 â€” no Whirlpool state involvement beyond the CPI.

## 6. Residual items (moved to FINAL_DISPOSITION)

- Squads multisig membership (vault `9Y5dnTF...`) not enumerated (governance plane).
- 637 "other" authority txs (of the 816 authority events) not fully triaged per-event this pass.
- AMM legacy program balance surface re-verification (dormant assumed, not proven per-account).

