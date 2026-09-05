
# ORCA_COMPANION_TRIAGE (rev. 2 â€” corrected identification)

Companion programs in the Orca deployer-family (same Squads/upgrade-authority graph).
**Rev.2 corrects the earlier "thin helper" reading: both live companions are balance-holding /
balance-controlling integration programs.** Per mandate, neither is CLEAR yet:
- waveQX2y: custody measured (PDA-owned WSOL bonding-curve escrows) â€” logic not decompiled.
- riptK81h: routes value (SwapV2/TransferChecked CPIs) â€” logic not decompiled.

## 1. `waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF` â€” **Wavebreak** (Orca token-launch platform; BONDING CURVE â‡’ WHIRLPOOL GRADUATION)

> Third-party corroboration (solanacompass.com/projects/orca): "Wavebreak is a token launchpad on
> Solana that uses bonding curve mechanics to distribute new tokens transparently, graduating
> successful tokens into Orca Whirlpools for liquidity. The platform employs CAPTCHA integration
> with on-chain permission structures to prevent bot activity." Consistent with every decompiled
> string/handler below. First-party Orca product (same governance authority GwH3Hiv5 / Squads).

- PD `nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs`; authority `GwH3Hiv5...`; last upgrade 365,746,180 (Squads). Program ELF 500,493B.
- Decompiled handler set (from ELF strings incl. `src/instructions/*.rs` + live logs):
  - **Launch/BondingCurve**: `BondingCurveInitialize`, `BondingCurveCollectFees`, `BondingCurveGraduate`, `BondingCurveClose`, `TokenBuyExactIn`, `TokenSellExactIn`, `TokenSellExactOut`, `TokenRefund`, `LpHarvest`, `LpTransfer`, `LpTakeover`, `lp_escrow`
  - **Whirlpool graduation (DIRECT integration)**: `GraduateWhirlpool`, `GraduateManual`, `InitializePoolWithAdaptiveFee`, `InitializeDynamicTickArray`, `OpenPositionWithTokenExtensions`, `LockPosition`, `whirlpool_init_authority`, `whirlpool_base_vault`, `whirlpool_quote_vault`, `Whirlpool position must be locked`, `whirlpool fee tier index is not in the allowed range`
  - **Config/control**: `MintConfigInitialize/Update/Close`, `AuthorityConfigInitialize/Grant/Revoke`, `PermissionConfigInitialize/Update/Close`, `PermissionConsume(Cpi|TopLevel)`, `PermissionRefund`, `Permission` (secp256k1 signature-gated; `Failed to verify signature`), `mint_config`, `permission_config`, `authority_config`, `consumed_permissions`
- Owned accounts: **1,572** = 1,538Ã—2048B launch records + 1Ã—4096 + 1Ã—4097 + 1Ã—256 + 31Ã—64. Program-owned SPL token accounts: **0**.
- **CUSTODY (measured, evidence `custquant.mjs`)**: per-launch record PDAs own WSOL token accounts (bonding-curve escrows). Sample: `CdPRm4HJâ€¦` â†’ `82sv2xcgâ€¦` 281,663,128 lamports; 5-record scan: `HGDmxsgiâ€¦` 4,975,001; `E8ShcbGHâ€¦` 0; `NnbTFLwPâ€¦` 199,001; `9sTkdSPCâ€¦` 14,172,763; `HWn1N8euâ€¦` 3,243,250. Total program+escrow exposure â‰ˆ 23.4 SOL lamports + per-launch WSOL.
- Live handler mix (last 40 txs): TokenSellExactInÃ—12, TokenBuyExactInÃ—15, PermissionConsumeTopLevelÃ—15, PermissionRefundÃ—53, BondingCurveGraduateÃ—1, GraduateWhirlpoolÃ—1, InitializePoolWithAdaptiveFeeÃ—1, InitializeDynamicTickArrayÃ—2, OpenPositionWithTokenExtensionsÃ—1, LockPositionÃ—1, MintTox1, SetAuthorityÃ—1.

**Assessment**: THIS IS A BALANCE-HOLDING, BALANCE-CONTROLLING COMPANION. It holds WSOL escrow custody for live launches and creates/controls Whirlpool pools+positions for graduated tokens (AdaptiveFee pools, locked positions, token badges presumably). It is governance-controlled by the same Squads/DGn (GwH3Hiv5) as Whirlpool â€” meaning Whirlpool's governance core also controls a launch platform that can initialize pools/positions and lock them.
**Status**: BLOCKED â€” requires (a) decompile review of graduation + escrow withdrawal paths; (b) fork tests of BondingCurveGraduate/GraduateWhirlpool money paths; (c) review of the permission/signature model (secp256k1) for refunder/authority escalation. Not part of the Aâ€“D test matrix executed this pass.

## 2. `riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j` â€” **orca_busybox** DEX ROUTER (Orca smart-order-routing layer; CPIs Whirlpool swap_v2 + legacy AMM Swap2)

- PD `4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu`; authority `GwH3Hiv5...`; last upgrade 440,010,891 (Squads). ELF 259,037B.
- Decompiled handlers: `MarketInitialize/Update/Deposit/Withdraw/Close`, `SwapExactIn`, `SwapExactOut`, `RouteV2`, `Route`, `RouteWithTokenLedger`, `SwapV2`, `Swap2` (Orca AMM), `OracleUpdate`, `ProgramVersion`, `TransferChecked`, `TransferCheckedWithFee`, `SetTokenLedger`, `src/routers/orca_busybox.rs`, `Cruising the current`.
- Owned accounts: **32 Ã— 1024B** Market records; program-owned SPL token accounts: 0; custody direct-measure: 0 token accounts in first-20 embedded keys sample (vaults may be derived, not embedded).
- Live handler mix (last 40): RouteV2Ã—1, SwapExactInÃ—2, SwapV2Ã—2 (Whirlpool), RouteÃ—1, Swap2Ã—2, TransferCheckedÃ—4, TransferCheckedWithFeeÃ—1, SetTokenLedgerÃ—1, RouteWithTokenLedgerÃ—1, 43-CU `GetAccountDataSize`/`InitializeAccount3` ops.

**Assessment**: a routing/settlement router that CPIs Whirlpool swap_v2 + legacy AMM Swap2 and transfers tokens â€” balance-CONTROLLING (it moves other programs' balances by CPI with caller-supplied accounts), but does not itself custodied funds (1024B market state, no token accounts measured). Requires decompile + CPI-account-validation review: a router with permissive CPI account lists is a classic source of authorization bugs (route hijack etc.).
**Status**: UNREVIEWED (decompile/fork-test pending).

## 3. `9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP` â€” legacy AMM (dormant)

- PD `DrrJDyBzy...`, authority `23zF9Az...`; last upgrade slot 161,177,892 (2021). Dormant; per-account balance re-enumeration NOT completed (flagged).

## 4. Non-family contacts (excluded)

`cmtDvXumGâ€¦` (auth F3S4PDâ€¦), `BGUMAp9Gq7â€¦` (third-party Transfer + CPI to noopb9/cmtDvXumG; tx `3UyQFgPâ€¦` slot 400,968,772). Metaplex graph, not Orca family.

## 5. Squads control plane

- Controller vault `BQsDWkL417U4tVE2sDnPks469pKdm6YzFgKH77doiEjF` (Squads-owned, 1155B; multisig `9Y5dnTFâ€¦`), Vaults `DNUJ3ByF4â€¦` (1318B), `DCuDSLc7râ€¦` (378B); `4ZnVFX2c2â€¦` system-owned 69.97M lamports (no data).
- Multisig membership NOT enumerated (governance plane; not decoded).

## Verdict
Mandate rule: â€œDo not mark CLEAR while any balance-holding or balance-controlling companion remains
unreviewed or fixture-blocked.â€
â†’ **waveQX2y (balance-holding: WSOL escrow custody, Whirlpool pool/position creation) and
riptK81h (balance-controlling router) are NOT fully reviewed â†’ overall re-audit status is INCOMPLETE**
(even though the Whirlpool program itself + all A/B/C/D/Q fork tests on it are CLEAR).

