# Orca Family Balance Path Matrix (WS7)

**Branch:** `arena/01a06ff8-orca-audit`  
**Session:** WS7 (continuation, 2026-09-05)  
**Defensive, fork-only. No mainnet broadcast.**

---

## 1. Program inventory with control roots and custody classification

| # | program | address | balance-holding? | balance-controlling? | upgrade authority | root type | custody measured? | handler review status | remaining blocker |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Wavebreak | `waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF` | **Yes** (bonding-curve WSOL escrows; 1,537 curves; fee custody +6.78 SOL divergence) | **Yes** (creates/manages Whirlpool pools and positions via `GraduateWhirlpool` CPI) | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | Off-curve PDA | Yes (`recon/wb_custody_full.json`, `recon/wb_fee_reconciliation.json`) | **INCOMPLETE** (`GraduateWhirlpool`, `LpHarvest`, `TokenRefund`, provider-signed buy, `graduateManual` residuals) | Fixture-blocked: 7 of 35 graduation accounts closed; no funded `lp_escrow`; no genuinely expired non-graduated curve; no provider signer key |
| 2 | Busybox / Riptide AMM | `riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j` | **No** (program-owned SPL token accounts: 0; custody is market vaults derived from PDA seeds) | **Yes** (routes tokens via CPI to Whirlpool `swap_v2` and Legacy AMM `Swap2`; moves reserves; updates pool state) | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | Off-curve PDA | Yes (`recon/busybox_custody_true.json`, `recon/busybox_custody_atomic_fixed.json`) | **INCOMPLETE** (funded lifecycle unmeasurable; penalty-selection arithmetic unmeasured) | Authority-blocked: `MarketInitialize` requires hardcoded initializer `CGYAxnDF…`; `OracleUpdate` requires `updater` key; no genuine deposit/withdraw/close fixture |
| 3 | Whirlpool | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | **Yes** (pool vaults, fee/reward towers, position NFTs — indexer: 1,106,108 accounts / 156,285 pools) | **Yes** (CPI target of Wavebreak graduation; CPI target of Busybox router; creates/manages pools and positions) | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | Off-curve PDA | **Partial** (ProgramData verified; indexer figure unverified from public RPC; per-account balances unenumerated) | **INCOMPLETE** (initial inventory only; complete security review pending) | Fixture-blocked (no complete handler-level test harness for Whirlpool in workspace); authority-blocked (no updater/authority fixture for complete CPI authorization tests) |
| 4 | Legacy AMM | `9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP` | **Yes** (pool vaults, fee/reward accounts — indexer: ~1.25 M accounts / 41.124 T lamports; public RPC capped at 167 accounts / 1.296 T lamports) | **Yes** (CPI target of Busybox router `RouteV2` / `Swap2`; manages reserves and fees) | `23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG` | **On-curve plain key** (23.891577114 SOL) | **Partial** (ProgramData verified; full custody unverified; per-account balances unenumerated) | **INCOMPLETE** (initial inventory only; complete security review pending) | Fixture-blocked (no complete handler-level test harness for Legacy AMM); authority-blocked (no authority fixture for complete CPI authorization tests); public RPC blocked (`getProgramAccounts` refused — HTTP 403) |

---

## 2. Control-root relationships (cross-program key reuse)

| key / address | role in Wavebreak | role in Busybox | role in Whirlpool | role in Legacy AMM | type | risk exposure |
|---|---|---|---|---|---|---|
| `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | Upgrade authority; off-curve PDA (cannot be signed directly) | Upgrade authority; same PDA | Upgrade authority; same PDA | **Not used** (Legacy AMM uses separate `23zF9Azp…`) | Off-curve PDA | **Governance exposure**: whoever derives this PDA controls three balance-holding/controlling programs in one signature. The deriving program was not identified from public RPC (`getProgramAccounts` on `BPFLoaderUpgradeable` refused — HTTP 403). The governing multisig remains unidentified (`recon/s4_squads_pda_search.json`: none of 834 Squads space-1318 accounts derive it). |
| `23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG` | Not used | Not used | Not used | Upgrade authority; plain on-curve key (23.891577114 SOL) | Plain EOA | **Single-secret exposure**: no on-chain mitigation. Has not signed an upgrade since slot 161,177,892. Last activity: 63 plain transfers + 1 self-rotation (`recon/authority_events_summary.json`). |
| `BWyVTPPRW7A5kpHM3tNgPhRz6JekR9sL8iFx2o4X1w9C` | `AuthorityConfig` slot 0 (privs 0, 2–8); creator of all 7 Manual curves | Authority / updater on 12 markets | Not directly used (but is the same key that controls Wavebreak and Busybox) | Not used | Plain EOA | **Cross-program exposure**: a single plain-key compromise spans Wavebreak's fee/permission/config authority and Busybox's market authority/updater functions. The `AuthorityConfig` holds only 2 of 64 slots; `PermissionConfig` holds 1 of 3 signer slots (`WAVE_BREAK_DEEP_REVIEW.md` §3, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §5). |
| `8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor` | `AuthorityConfig` slot 1 (privilege 1: ReceiveProtocolFees) — fee-claim destination | Not used | Not used | Not used | Plain EOA | **Bound recipient**: `BondingCurveCollectFees` binds the fee sweep to this privilege-1 authority (`WAVE_BREAK_DEEP_REVIEW.md` §4.2). Any attacker can trigger the sweep (`NO CONFIRMED PERMISSIONLESS PROFIT PATH` — no attacker-positive delta), but the recipient is fixed. |
| `CGYAxnDF1bYwmbzTtVx2pdo8xd3aviqE58WumVYRLYRH` | Not used | Hardcoded initializer (`0x38a48` in rodata) for `MarketInitialize` (`BUSYBOX_DEEP_REVIEW.md` §1.2) | Not used | Not used | Plain EOA | **Market creation gate**: only this key can create markets in the deployed v2.1.1 build. No impersonation performed; no cheatcode used to bypass (`BUSYBOX_DEEP_REVIEW.md` §4, `evidence/BBF_swap_guards.json`). |
| `BP8TxUroBDw97JWmc9bfg9bs8PoE6MA71SSihhBNUJR4` | Not used | `updater` on 22 markets (`BUSYBOX_DEEP_REVIEW.md` §2) | Not used | Not used | Plain EOA | **Oracle update gate**: only this key (and 8 per-market updater keys) can push `OracleUpdate`. No updater fixture exists (`OPEN_ITEMS_WS7.json` item 7). |

---

## 3. Balance path mapping (every balance-moving instruction mapped to control root, authorization, and remaining blocker)

### 3.1 Wavebreak (`waveQX2yP3…`)

| instruction / CPI | moves balance? | authorization gate | control root involved | tested? | remaining blocker |
|---|---|---|---|---|---|
| `BondingCurveInitialize` | Creates bonding curve PDA (program-owned lamports only) | Privilege-gated (`AuthorityConfig`) — `6027` for wrong privilege | `BWyVTPPR…` (priv 0) | Yes (`6027` measured) | None (authority gate decided; no balance extraction) |
| `TokenBuyExactIn` / `TokenBuyExactOut` | Yes (moves quote from buyer ATA to vault; mints base to buyer ATA) | `PermissionConsumeTopLevel` (`6018` without consume) + allowed signer binding (`6004` for wrong signature) + subject/consumer binding (`6001`) + expiry (`6003`) + curve active (`6019` after graduation) | `BWyVTPPR…` (priv 0, 2–8) for authority; `0359c54abfca…2b29` for permission signer | Yes (138 cases executed; all denied or zero-positive) | Fixture-blocked: genuine provider-signed permission unavailable (open item 5) |
| `TokenSellExactIn` / `TokenSellExactOut` | Yes (moves base from seller ATA to vault; moves quote to seller ATA; burns base supply) | No permission required (`sellRequiresPermission = false`); bounded by internal accounting (`quoteAmount`) — `6019` after graduation | `BWyVTPPR…` (priv 0) for authority (close/fee sweep) | Yes (all executed; payouts bounded) | None (no positive attacker delta measured) |
| `TokenRefund` | Yes (would move quote from vault to refund destination ATA) | Curve must be expired (`6016` if active) + refund destination must match stored value (`6001` for wrong address; `6000` for default/unwritable) | `BWyVTPPR…` (priv 0) for authority | Gate decided (`6016` enforced); arithmetic unmeasured | Fixture-blocked: no genuinely expired non-graduated curve (open item 4) |
| `GraduateWhirlpool` (CPI `whirLbMiic…`) | Yes (creates Whirlpool pool, opens locked position, moves base/quote to pool vaults) | Graduation conditions (`6019` if not met) + pool/position/account binding (`6022`/`6023` for wrong seeds) + authorization for Whirlpool CPI targets | `BWyVTPPR…` (priv 0) for Wavebreak authority; Whirlpool authorization unverified | Fixture-blocked (7 of 35 accounts closed) | Fixture-blocked: archival pre-state needed; Whirlpool authorization unverified (open item 2) |
| `GraduateManual` | Yes (moves remaining quote to destination ATA; mints residual base to destination ATA) | None (unauthenticated trigger) — intended public good | None (any wallet) | Yes (5 executions; zero attacker delta; destination bound) | Residual open: premature finalization before window (open item 1, but does not change profit conclusion) |
| `BondingCurveCollectFees` | Yes (moves fee from vault to fee-authority ATA) | Privilege 1 (`6027` for wrong privilege); ATA bound (`6023` for wrong seed) | `BWyVTPPR…` (priv 0); fee authority `8AbiHetk…` (priv 1) | Yes (attacker-signed sweep measured; divergence reconciled to 0) | None (no attacker-positive delta; recipient bound) |
| `LpHarvest` / `LpTransfer` / `LpTakeover` | Would move fees/rewards from escrow to recipient ATA | `LpTakeover`: privilege 11 (`6027`); `LpHarvest`: position ownership (seed-bound `6023`); `LpTransfer`: escrow ownership | `BWyVTPPR…` (priv 0, 11) for `LpTakeover` | Fixture-blocked (no funded escrow) | Fixture-blocked: no funded `lp_escrow` (open item 3) |

### 3.2 Busybox (`riptK81hDx…tBS7j`)

| instruction / CPI | moves balance? | authorization gate | control root involved | tested? | remaining blocker |
|---|---|---|---|---|---|
| `SwapExactIn` / `SwapExactOut` | Yes (moves tokens between user ATAs and market vaults; updates reserves) | Permissionless (only swapper sign required); market PDA writable; account-owner checks (`IllegalOwner` for aliased accounts); token-program pinning (`IllegalOwner` for Token-2022 substitution); `validUntil` gate (`InvalidAccountData` for expired); reserve/slippage/partial-fill bounds (`6099` / `custom 1`) | `BWyVTPPR…` (market authority on 12 markets); `CGYAxnDF…` (hardcoded initializer); `BP8TxUro…` (updater) | Yes (139 probes executed; all negative/neutral) | None for exploit hypothesis; arithmetic control open for updater-controlled penalties (open item 7) |
| `MarketInitialize` | Creates market PDA (program-owned lamports) | `IncorrectAuthority` — requires hardcoded initializer `CGYAxnDF1bYwmbzTtVx2pdo8xd3aviqE58WumVYRLYRH` (`BUSYBOX_DEEP_REVIEW.md` §1.2, `evidence/BBF_swap_guards.json`) | `CGYAxnDF…` | Yes (`IncorrectAuthority` measured) | Authority-blocked (open item 6) |
| `MarketUpdate` / `MarketDeposit` / `MarketWithdraw` / `MarketClose` | Updates reserves / fee parameters; moves tokens between vaults and user ATAs; closes market (pays authority) | `IncorrectAuthority` — requires market authority (`BWyVTPPR…` on 6 markets; `CGYAxnDF…` on 18; others per-market) | Per-market authority | Gate decided (`IncorrectAuthority`); full lifecycle unmeasured | Authority-blocked (open item 6) |
| `OracleUpdate` | Updates oracle payload (does not directly move user tokens; affects future swap prices) | `IncorrectAuthority` — requires market `updater` (`BP8TxUro…` or per-market updater) | Per-market updater | Gate decided (`IncorrectAuthority`); sequence replay not separately tested (authority binding sufficient) | Authority-blocked (open item 7 — requires updater to test arithmetic control of penalties) |

### 3.3 Whirlpool (`whirLbMiic…uctyCc`)

| instruction / CPI | moves balance? | authorization gate (unverified) | control root involved | tested? | remaining blocker |
|---|---|---|---|---|---|
| `InitializePoolWithAdaptiveFee` | Creates pool PDA, vaults, fee accounts | Unverified (assumed: requires `whirlpool_init_authority`) | `GwH3Hiv5…` (PDA — deriving program unidentified) | **Not tested** (fixture-blocked for complete graduation sequence) | Fixture-blocked + authorization unverified (open item 9) |
| `OpenPositionWithTokenExtensions` | Creates position NFT, binds tokens | Unverified (assumed: requires user token accounts, pool PDA, valid tick range) | Same PDA | **Not tested** | Same |
| `LockPosition` | Locks position (irreversible without unlock — unlock not present) | Unverified (assumed: requires position NFT ownership) | Same PDA | **Not tested** | Same (critical for graduation CPI — position must be locked) |
| `Swap` (CPI'd by Wavebreak graduation and Busybox router) | Moves tokens between user ATAs and pool vaults | Unverified (assumed: requires pool PDA, user ATAs, valid tick; no authorization beyond account binding) | Same PDA | **Not directly tested** (CPI authorization from Wavebreak/Busybox tested; Whirlpool target authorization unverified) | Authorization path through Whirlpool unverified (open item 9) |
| `ClosePosition` / `WithdrawLiquidity` / `UpdateFeesAndRewards` | Moves fees/rewards; burns position NFT; updates reserves | Unverified | Same PDA | **Not tested** | Complete review pending (open item 9) |

### 3.4 Legacy AMM (`9W959DqE…aQP`)

| instruction / CPI | moves balance? | authorization gate (unverified) | control root involved | tested? | remaining blocker |
|---|---|---|---|---|---|
| `Swap2` (CPI'd by Busybox router) | Moves tokens; updates reserves; applies fees | Unverified (assumed: requires pool PDA, user ATAs; authorization bound to pool PDA) | `23zF9Azp…` (plain on-curve key) | **Not directly tested** (Busybox router authorization tested; Legacy AMM target authorization unverified) | Authorization path through Legacy AMM unverified; custody unenumerated (open items 8, 9) |
| `Route` / `RouteV2` (router — CPI's Legacy AMM) | Routes through Legacy AMM pools; moves intermediate tokens | Unverified (router authorization tested; target authorization unverified) | `23zF9Azp…` | **Not directly tested** | Same |
| `InitializePool` / `InitializeMarket` / `UpdatePool` | Creates/manages pool PDA, vaults, fees | Unverified | `23zF9Azp…` | **Not tested** | Complete review pending (open item 9) |
| `Deposit` / `Withdraw` | Updates reserves; creates/destroys LP tokens | Unverified | `23zF9Azp…` | **Not tested** | Same |

---

## 4. Cross-program CPI authorization (what was tested; what remains open)

### 4.1 Wavebreak → Whirlpool (`GraduateWhirlpool` CPI)

- **What was tested:** Wavebreak's graduation trigger (`GraduateWhirlpool`) executed against a live fixture (`recon/s4_grad_ready.json`). The fixture had 7 of 35 accounts already closed (`evidence/WBZ_final3.json`), so the CPI terminated on `6022`/`6023` (account checks) before reaching Whirlpool authorization. The Wavebreak authorization (privilege gate `6027`, graduation conditions `6019`) is decided.
- **What remains open:** Whether the Whirlpool CPI target (`whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`) performs its own authorization checks on the pool PDA, vault PDAs, position PDA, token badges, and fee/reward accounts — and whether any of those checks can be bypassed by substituting attacker-controlled accounts into the CPI account list. This requires a complete graduation fixture replay (`OPEN_ITEMS_WS7.json` item 2).

### 4.2 Busybox → Whirlpool (`SwapV2` / `RouteV2` CPI)

- **What was tested:** The Busybox router (`riptK81hDx…tBS7j`) was tested with the correct 12-account shape (`evidence/BB_tagsweep.json`). Tags 2 (`SwapExactIn`) and 3 (`SwapExactOut`) execute and log their names. The router CPI to Whirlpool (`SwapV2`) and Legacy AMM (`Swap2`) occurs through the `RouteV2` path (referenced in rodata `src/routers/orca_busybox.rs`). The router's authorization (correct account list, token-program pinning, duplicate-account aliasing rejected) is decided.
- **What remains open:** Whether the Whirlpool CPI target (`whirLbMiic…`) performs authorization checks when called from the router that are different from its direct authorization checks — and whether any router-level account substitution can bypass them. This requires testing the full router + CPI path with substituted accounts (`WHIRLPOOL_HANDLER_REVIEW.md`, `LEGACY_AMM_HANDLER_REVIEW.md`).

### 4.3 Busybox → Legacy AMM (`Swap2` / `Route` CPI)

- **What was tested:** The router authorization (same as above) decided. The Legacy AMM CPI target authorization unverified.
- **What remains open:** Whether `Swap2` performs authorization checks (pool PDA ownership, user ATA ownership, mint compatibility) that can be bypassed by substituting a fake pool PDA or redirecting output ATAs through the router (`LEGACY_AMM_HANDLER_REVIEW.md`).

---

## 5. Authority / upgrade control summary (family-level)

| control point | key / PDA | covers | status | blocker |
|---|---|---|---|---|
| Shared upgrade root (PDA) | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | Whirlpool, Wavebreak, Busybox | **Verified** (ProgramData `0x01` present; off-curve) | Deriving program unidentified; governing multisig unidentified (`OPEN_ITEMS_WS7.json` item 8) |
| Separate upgrade root (plain key) | `23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG` | Legacy AMM only | **Verified** (ProgramData `0x01` present; on-curve; 23.891577114 SOL) | No additional blocker for audit (key is a known single secret; complete review of Legacy AMM is separate — open item 9) |
| Wavebreak authority (priv 0, 2–8) | `BWyVTPPRW7A5kpHM3tNgPhRz6JekR9sL8iFx2o4X1w9C` | Wavebreak config/authority/fee | **Verified** (live `recon/wb_authority_config.json`) | Cross-program exposure documented (`FINAL_DISPOSITION.md` §6) |
| Wavebreak fee-authority (priv 1) | `8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor` | Wavebreak fee sweep | **Verified** (bound recipient for `BondingCurveCollectFees`) | No additional blocker |
| Busybox hardcoded initializer | `CGYAxnDF1bYwmbzTtVx2pdo8xd3aviqE58WumVYRLYRH` (`rodata 0x38a48`) | Market creation only | **Verified** (rodata constant; `IncorrectAuthority` measured) | No additional blocker |
| Busybox updater | `BP8TxUroBDw97JWmc9bfg9bs8PoE6MA71SSihhBNUJR4` (22 markets) + 8 per-market | Oracle push | **Verified** (authority binding; `IncorrectAuthority` measured) | No updater fixture available (`OPEN_ITEMS_WS7.json` item 7) |
| Squads multisig (governing) | Unknown (scanned 834 space-1318 accounts; none derive `GwH3Hiv5…` or `BWyVTPPR…`) | Potential control of shared root PDA | **Unverified** | Requires indexer/archive or direct Squads account parsing (`recon/s4_squads_pda_search.json`) |

---

## 6. Safety rules verification for this session

- **Fork-only**: Confirmed. All executed tests used a Surfpool 1.5.0 mainnet fork. No mainnet broadcast.
- **No authority impersonation**: Confirmed. No `MarketInitialize` called with the hardcoded initializer; no `OracleUpdate` called with updater key; no `AuthorityConfig` / `PermissionConfig` update with `BWyVTPPR…`; no `BondingCurveCollectFees` with `8AbiHetk…` impersonated.
- **No cheatcode balances for protocol state**: Confirmed. Only `surfnet_setAccount` used for single-field `validUntil` differentials (`BBS3-diff-*`) and for funding the attacker's own token accounts (`evidence/funding_s4_sol.json`).
- **Fixture-blocked paths recorded as INCOMPLETE**: Confirmed. Every unavailable fixture or signer is documented in `OPEN_ITEMS_WS7.json` and `WS7_FIXTURE_MANIFEST.json`.
- **Every executed case measured**: Confirmed. All 322 entries in `TESTS_MACHINE_READABLE_WS7.json` include `txSignature` (or `null` for not-executed), `instructionError`, `beforeAfterState`, `attackerDeltaLamports`, `attackerDeltaUsd` (where available), `vaultDelta`, `mintSupplyDelta`, and `status`.
- **Same-transaction round trips included**: Confirmed. Busybox `A→B→A` round trips executed (`BBS2-run2-*`). Wavebreak `consume→buy` sequences preserved state across steps (though arithmetic path incomplete due to missing permission).
- **Cross-slot price artifacts excluded**: Confirmed. All swap profit measurements used the same-slot external reference (`Jupiter price/v3`) for both legs (`BUSYBOX_DEEP_REVIEW.md` §5.1; `FINAL_DISPOSITION.md` §4.5 correction).
- **Cross-program substitution tested**: Confirmed. Token-2022 substitution (`mintB` program replaced — `IllegalOwner`); duplicate mutable account aliasing (`swapperA` aliased onto `marketVaultA` — `InvalidAccountData`); counterfeit mint substitution (rejected by mint binding — `InvalidAccountData` / `6023`).
- **Token-program pinning verified**: Confirmed. SPL Token (`TokenkegQfe…`) and Token-2022 (`TokenzQdB…`) program IDs verified against rodata constants; `IllegalOwner` enforced.
- **AQUIFER-LESSON checks applied**: Confirmed (see `FINAL_DISPOSITION_WS7.md` §8 for full checklist verification).

---

*Matrix generated: 2026-09-05. Every balance-holding / balance-controlling program identified, classified, and documented with its exact remaining blocker. The family remains INCOMPLETE because Whirlpool (handler-level review) and Legacy AMM (handler-level review + custody enumeration + authority history + control-plane resolution) are unverified at handler level, and the Wavebreak / Busybox open items (fixture-blocked or authority-blocked) are formally documented but not decided positive or negative.*
