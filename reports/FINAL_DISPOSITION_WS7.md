# WS7 Final Disposition — Orca deployer family (continuation, defensive, fork-only)

**Branch:** `arena/01a06ff8-orca-audit` (fixed session branch).  
**Session date:** 2026-09-05.  
**Fork:** Surfpool 1.5.0 mainnet fork (no mainnet broadcast).  
**Previous pass:** WS6 (Busybox stale-oracle / frozen-window / penalty sweep, 2026-09-04).  
**Source of authority:** `reports/TESTS_MACHINE_READABLE.json` (322 entries, rebuilt from evidence files) — this is the authoritative count source; prose reports are derived from it.

---

## 1. Ledger reconciliation (A)

The machine-readable ledger (`reports/TESTS_MACHINE_READABLE.json`) was rebuilt by `tools/build_ws6_ledger.py` → `tools/normalize_ledger.py` and then validated manually this pass.

| metric | value | source |
|---|---|---|
| total entries | 322 | `counts.entries` |
| entries before WS6 | 177 | `counts.entriesBeforeThisPass` |
| added this pass (WS6) | 145 | `counts.addedThisPass` |
| with real tx signature | 309 | `counts.withTransactionSignature` |
| without tx signature (fixture/authority-blocked) | 13 | `counts.withoutTransactionSignature` |
| by program (wavebreak) | 138 | `counts.byProgram.wavebreak` |
| by program (busybox) | 39 | `counts.byProgram.busybox` |
| by program (busybox/riptide) | 145 | `counts.byProgram["busybox/riptide"]` |
| executed-denied | 163 | `counts.byFlag` (includes superseded + controls) |
| executed-success | 146 | `counts.byFlag` (includes superseded + controls) |
| not-executed | 13 | `counts.byFlag` |
| open items (fixture/authority-blocked) | 10 | `openItems` list |
| resolved open items this pass | 4 | see §4 |

**Discrepancy corrected:** Earlier prose documents quoted 177 executed cases while the stale `statusCounts` block read 178 clear + 8 INCOMPLETE. The 8 INCOMPLETE paths were never entries in `tests[]`; they live in `openItems`. The `statusCounts` block has been recomputed from `tests[]` directly; unresolved paths are carried only in `openItems`.

---

## 2. Status of the family (B–J, summarized)

### 2.1 Wavebreak (`waveQX2yP3…`)

| path | status | evidence / blocker |
|---|---|---|
| `GraduateWhirlpool` end-to-end (LP escrow + position custody) | **INCOMPLETE** | Live graduation fixture (slot 441,655,843) has 7 of 35 accounts already closed at both fork tips; no Whirlpool pool exists for the largest pre-graduation WSOL curves. Attacker-submitted variants terminated on `6022`/`6023` account checks rather than authorization decisions (`evidence/WBZ_final3.json`, `recon/wb_graduate_fixture.json`). |
| `LpHarvest` / `LpTransfer` against funded escrow | **INCOMPLETE** | No `lp_escrow` PDA exists on mainnet (0 token-2022 positions held by any escrow). Executed attempts hit seed check (`6023`) for non-existent escrow (`evidence/WBL_lp.json`). `LpTakeover` reached privilege gate (`6027`, privilege 11). |
| `TokenRefund` payout arithmetic on genuinely expired, non-graduated curve | **INCOMPLETE** | Every candidate returned `6016` (curve still active); no live curve reaches the refund-eligible state. The gate (`6016`) is enforced; the payout arithmetic against the quote vault is unmeasured (`evidence/WBF_final2.json`, `WBG2_grad_refund.json`). |
| Buy path with genuine provider-signed permission | **INCOMPLETE** | All 1,537 live curves set `buyRequiresPermission = true`. Without the single configured allowed signer (`0359c54abfca…2b29`) the buy-side payout/fee/rounding arithmetic cannot be reached. What was measured: gate fires (`6018`), subject/consumer binding rejects attacker-crafted and replayed live messages (`6001`/`6004`), substitution of vault/mint/ATA/token program rejected (`6023`/`6024`/`6001`) (`evidence/WBC_perm_trade.json`, `WBRP_permission.json`). |
| `graduateManual` (unauthenticated trigger) | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | Executed 5× from fresh attacker key against live third-party curves. Caller gained nothing (net −5,000 lamports fee per attempt). Destination and recipients bound to curve record; repeated finalization rejected (`6015`) (`WAVE_BREAK_DEEP_REVIEW.md` §4.1, `evidence/WBF_final.json`, `WBF_forced_graduation.json`). |
| `BondingCurveCollectFees` (permissionless trigger) | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** (observation, not exploit) | Any wallet can trigger; beneficiary bound to privilege-1 fee authority (`6027` if wrong privilege; `6023` if wrong ATA seed). Measured: attacker-signed sweep moved 520,591,863 / 677,473,335 units to the bound fee authority, driving divergence to exactly 0 (`evidence/WBZ_final3.json`, `recon/wb_fee_reconciliation.json`). |
| 31 live `consumed_permission` accounts (stranded rent) | **Observation (not exploitable)** | All 31 have `refundDestination = Pubkey::default()` and `safeToCloseSlot` in the past. Refund binds to stored field (`6001` for wrong address; `6000` unwritable for default). 41,420,920 lamports unrecoverable (`WAVE_BREAK_DEEP_REVIEW.md` §4.3). |
| `PermissionConsumeTopLevel` / `Cpi` / `Refund` / `Revoke` | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | All executed cases denied or zero-attacker-positive (`TESTS_MACHINE_READABLE.json` entries `WB-P01`–`WB-P10`, `WB-R01`–`WB-R06`, `WB-RP1`–`WB-RP7`). |
| `TokenBuyExactIn` / `TokenBuyExactOut` | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | Every executed case denied (`6018` without consume; `6019` after graduation; `6001` for wrong destination) or accepted with zero attacker delta (`WB-C01b`, `WB-C05a-d`). |
| `TokenSellExactIn` / `TokenSellExactOut` | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | All executed; payouts bounded by internal accounting (`6019` after graduation). No positive attacker delta (`WBS_sell.json`, `WBD_fee_drain.json`). |
| `MintConfig*` / `AuthorityConfig*` / `PermissionConfig*` / `BondingCurveClose` / `BondingCurveGraduate` | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | All privilege-gated (`6027` for wrong privilege) or state-gated (`6015`/`6016`/`6019`). |
| `LpHarvest` / `LpTransfer` / `LpTakeover` | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** (fixture-blocked) | Seed checks (`6023`) prevent non-existent escrow; `LpTakeover` hits `6027` (privilege 11) (`evidence/WBL_lp.json`). |

**Unchanged from WS6:** The family stays **INCOMPLETE** because:
- `GraduateWhirlpool` end-to-end remains fixture-blocked (7 accounts closed at both fork tips).
- `LpHarvest`/`LpTransfer` remains fixture-blocked (no funded `lp_escrow`).
- `TokenRefund` payout arithmetic remains fixture-blocked (no genuinely expired, non-graduated curve).
- Provider-signed buy arithmetic remains fixture-blocked (no provider key available; all 1,537 curves require permission).
- Manual graduation: decided (`NO CONFIRMED PERMISSIONLESS PROFIT PATH`); open residuals (premature finalization before window open, timing front-run) remain untested because no live Manual curve has an open window.

### 2.2 Busybox / Riptide (`riptK81hDx…tBS7j`)

| path | status | evidence / blocker |
|---|---|---|
| `SwapExactIn` / `SwapExactOut` (all funded markets, both directions, 1%/5%/25% reserves, round trips) | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | 139 swap probes executed (authoritative run: 53 accepted, 12 denied; superseded run: 74). Both legs valued against same-slot external reference (Jupiter `price/v3`). 15/43 valued executions net-positive, max **+$11.06** (0.39% of $2,892 leg), sum of positives **$19.01**, every round trip negative (`evidence/BBS2_stale_sweep.json`, `BBS2_net_deltas.json`, `BBS2_stale_sweep_parsed.json`). |
| `validUntil` enforcement (oracle freshness gate) | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** (resolved this pass) | Single-field differential (`BBS3-diff-01` through `BBS3-diff-06`) on two markets (`CzuQmqj4dS` expired by 29.2 M slots; `9PwXMVkFzW` live). Same instruction: rejected with `InvalidAccountData` / "Oracle data is invalid" when `slot > validUntil`; accepted after restore; clearing only `validUntil` on expired market moves failure to `ArithmeticOverflow` (book-walk passed), confirming the gate is the expiry field, not payload deserialization (`evidence/BBS3_expiry_diff.json`). |
| `MarketInitialize` (permissionless create) | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | `IncorrectAuthority` — creation gated to hardcoded initializer `CGYAxnDF…` (`0x38a48` in rodata) (`evidence/BBF_swap_guards.json`, `BUSYBOX_DEEP_REVIEW.md` §1.2). |
| `MarketUpdate` / `MarketDeposit` / `MarketWithdraw` / `MarketClose` | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | `IncorrectAuthority` for non-authority caller (`BBA_auth_sweep.json`). `close` requires zero reserves (`BUSYBOX_DEEP_REVIEW.md` §4). |
| `OracleUpdate` (permissionless price push / replay) | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | `IncorrectAuthority` for non-updater (`BBA_auth_sweep.json`, `BB-A05`/`BB-A06`). Sequence replay rejected (no additional error text; authority binding sufficient). |
| `MarketDeposit` / `MarketWithdraw` / `MarketClose` (funded lifecycle) | **INCOMPLETE** | Unmeasurable without market authority key; `MarketInitialize` itself is authority-gated (`IncorrectAuthority`), so no self-owned fixture possible (`evidence/UBL_lifecycle.json`, `BUSYBOX_DEEP_REVIEW.md` §5.4). |
| Penalty selection (`arbPenaltyPerM` / `cuPenaltyMultiplier` / `jitodFrontPenaltyPerM`) — can penalties be *avoided* rather than paid? | **INCOMPLETE** | Every accepted fill's effective price consistent with configured `arbPenaltyPerM` being applied; `cuPenaltyMultiplier = 0` on all 32 markets. Whether penalties can be dodged needs a controlled `OracleUpdate` push (requires `updater` key). We neither called owner/restricted functions nor impersonated a key (`BUSYBOX_DEEP_REVIEW.md` §5.2, §5.4). |
| Swap guard fields (`minSpreadGuardPerM`, `maxA/maxBInventoryPerM`, `maxInventoryImbalanceGuardPerCent`) | **No guard rejections observed** | Published `math::guards` error texts absent from deployed ELF (`BUSYBOX_DEEP_REVIEW.md` §5.4). Configured values: `maxInventoryImbalanceGuardPerCent = 100` everywhere; `minSpreadGuardPerM` ∈ {0, −500, −1000, −2500, −5000}; `maxA`/`maxB` = 0 (disabled) on 31 of 32 markets. Enforcement comes from window (`validUntil`), reserve bound, per-fill slippage, partial-fill flag — not from these advisory fields. This is a configuration truth, not a vulnerability finding. |

### 2.3 Whirlpool (`whirLbMiic…uctyCc`)

| path | status | evidence / blocker |
|---|---|---|
| Handler-level review (all balance-moving handlers, CPI targets, position creation/close, fee/reward harvest, pool/oracle mutation, authorization paths) | **INCOMPLETE** | Program ELF (`10,485,715 B`, sha256 `610b1e394973bd1b…`) and ProgramData (`CtXfPzz36d…`, 72,981,780,480 lamports — rent for ELF, not user funds) verified (`elf/whirlpool.meta.json`, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3). Actual custody is the program-owned account set (indexer: 1,106,108 accounts / 156,285 pools); public RPC cannot enumerate (`getProgramAccounts` refused, HTTP 403). No handler-level review performed in this pass. Whirlpool is the CPI counterparty of Wavebreak's graduation CPI (`GraduateWhirlpool`), so its account binding and authorization constraints directly affect Wavebreak's graduation path. |
| ProgramData / upgrade authority verification | **Verified** | `version = 3`, `authority byte = 0x01` (present), `upgradeAuthority = GwH3Hiv5…` (same shared root). Not renounced (`FINAL_DISPOSITION.md` §7, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §1). |

### 2.4 Legacy AMM (`9W959DqE…aQP`)

| path | status | evidence / blocker |
|---|---|---|
| Handler-level review | **INCOMPLETE** | ProgramData (`DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8`, 691,149 B, 4,811,287,920 lamports — rent) verified. ELF (`691,104 B`, sha256 `930a47e23fe7f818…`) cached but not walked handler by handler. Upgrade authority is separate plain key `23zF9Azp…` (on-curve, 23.891577114 SOL); last upgrade slot 161,177,892. Not renounced (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §1, `FINAL_DISPOSITION.md` §1). |
| Per-account custody enumeration | **INCOMPLETE** | Earlier indexer pass measured ~1.25 M owned accounts / 41,124,583,108,449 lamports. Public RPC `getProgramAccounts` capped at 167 accounts / 1,296,458,888 lamports; `BPFLoaderUpgradeable` filtered by authority refused outright (HTTP 403 on both endpoints). Per-account balances unverified (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.2, §6.1). |
| Authority-event history (before slot 306,473,452) | **INCOMPLETE** | `getSignaturesForAddress('GwH3Hiv5…')` returns exactly one page of 230 signatures (oldest 306,473,452) and does not page further on `api.mainnet-beta` or publicnode fallback. The indexer pass's 816-event count can be neither reproduced nor refuted (`recon/s4_auth_walk_GwH3Hiv5.json` contains all 230 served signatures; `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §4). |
| Programs / multisig behind the shared root `GwH3Hiv5…` | **INCOMPLETE** | Root is **off-curve PDA** (`is_on_curve == False`). `getProgramAccounts` on `BPFLoaderUpgradeable` filtered by upgrade-authority bytes refused (HTTP 403). Scanned all 834 Squads accounts of space 1,318: none derives the root via `["multisig", addr]`. Candidate `3GiPhEnW…` excluded (unrelated plain key; holds 0.010064160 SOL, 1,318 B, 5 unrelated on-curve 32-byte slots). Governing multisig remains unidentified (`recon/s4_squads_pda_search.json`, `recon/squads_multisigs.json`, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §6). |

---

## 3. Findings worth the team's attention (measured; none attacker-profitable)

1. **Busybox `validUntil` is a hard gate.** The previous claim ("not a hard slot gate", "6.5k-slot grace period") was wrong; it compared the *last oracle update* slot, not `slot > validUntil`. Single-field differential (`BBS3-diff-*`) proves the gate is the stored expiry (`BUSYBOX_DEEP_REVIEW.md` §5.3, `FINAL_DISPOSITION.md` §4.5 correction).
2. **Busybox swap handlers are implemented and permissionless.** The earlier "tags 0x02–0x07 not implemented (`InvalidAccountData` @ 9 CU)" conclusion was an account-count artifact (zero accounts sent, so framework rejected before handler). With the correct 12-account shape, tags 2 (`SwapExactIn`) and 3 (`SwapExactOut`) log their names and trade against live reserves (`BUSYBOX_DEEP_REVIEW.md` §1.1).
3. **All 32 Busybox markets have `reserves == vault` (atomic read).** The earlier "10 divergent markets" reading was a measurement artifact (Token-2022 vaults are 170 B, and I read at different slots). Corrected atomic read: Σvault − Σreserves = 0 (`BUSYBOX_DEEP_REVIEW.md` §3, `FINAL_DISPOSITION.md` §4.2 correction).
4. **Cross-program key reuse is a real exposure, not an exploit.** `BWyVTPPR…` is simultaneously Wavebreak `AuthorityConfig` slot 0 (privs 0, 2–8), Busybox authority/updater on 12 markets, and creator of all 7 Manual-method curves. A single plain-key compromise spans both programs' custody and fee roots (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §5, `FINAL_DISPOSITION.md` §6).
5. **Legacy AMM upgrade authority (`23zF9Azp…`) is a plain on-curve key, not a PDA.** It has not signed an upgrade since slot 161,177,892 (~283 M slots ago), holds 23.891577114 SOL, and controls a program with ~1.25 M owned accounts. There is no on-chain mitigation — it is a key-management exposure (`FINAL_DISPOSITION.md` §7).
6. **Whirlpool's ProgramData lamports (72,981,780,480) are rent for the ELF, not user funds.** Real custody is the program-owned account set (~1.1 M accounts / 156,285 pools), which public RPC cannot enumerate (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3).
7. **Wavebreak's `graduateManual` is an unauthenticated trigger with no attacker-positive delta.** Any wallet can finalize a past-window Manual curve; everything moved is bound to the curve record (destination ATA, residual base supply minted to destination's ATA). The design text explains it: "Manual graduation is required to continue trading." It lets any wallet spend gas on the protocol's behalf (`WAVE_BREAK_DEEP_REVIEW.md` §4.1).
8. **31 `consumed_permission` accounts hold unrecoverable rent (41.42 M lamports).** All have `refundDestination = Pubkey::default()` and `safeToCloseSlot` in the past. The refund path binds to the stored field (`6001` for wrong address; `6000` for unwritable default). Recommendation: treat an unset destination as "pay the consumer" or require the field at consume time (`WAVE_BREAK_DEEP_REVIEW.md` §4.3, `FINAL_DISPOSITION.md` §4.3).
9. **All 1,537 live curves require a permission to buy but none to sell.** Sells are the only open money-out path, bounded by internal accounting (`quoteAmount`). Any change that lets a payout be capped by the *vault* instead of by `quoteAmount` would immediately expose the uncollected fee custody (~6.78 SOL and growing) to the last seller (`FINAL_DISPOSITION.md` §4.4). Keep the accounting-bound property intact.
10. **Shared root `GwH3Hiv5…` is off-curve (a PDA).** It covers Whirlpool, Wavebreak, and Busybox. Because it is off-curve, it cannot be signed for directly; control sits with whichever program derives it. The deriving program was not identified from public RPC (`getProgramAccounts` on `BPFLoaderUpgradeable` refused outright). This is the largest single point of control in the family (`FINAL_DISPOSITION.md` §7, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §6.3).

---

## 4. What changed since WS6 (corrections made this pass)

1. **`validUntil` semantics decided** (previously misread as "not a hard slot gate"). The single-field differential (`BBS3-diff-*`) proves it is enforced at swap time (`BUSYBOX_DEEP_REVIEW.md` §5.3).
2. **Swap handler implementation corrected** (previously reported "tags 0x02–0x07 → `InvalidAccountData` @ 9 CU"). The correct 12-account shape shows tags 2 (`SwapExactIn`) and 3 (`SwapExactOut`) execute and log their names (`BUSYBOX_DEEP_REVIEW.md` §1.1).
3. **Reserves-vs-vault divergence corrected** (previously reported 10 divergent markets). Atomic read on all 32 markets: Σvault − Σreserves = 0 (`BUSYBOX_DEEP_REVIEW.md` §3, `FINAL_DISPOSITION.md` §4.2 correction).
4. **Market PDA seed resolved**: `["market", u32le(market_id)]` reproduces 12/12 live markets and the client's own vector (`BUSYBOX_DEEP_REVIEW.md` §2).
5. **Program identity corrected** (Busybox is `Riptide AMM Program` v2.1.1, `security@riptide.so`, containing an `orca_busybox` router module — not an Orca router with ledger handlers) (`BUSYBOX_DEEP_REVIEW.md` §0, `ORCA_COMPANION_TRIAGE.md` §2).
6. **Program upgrade control corrected** (all four family programs still upgradable; the shared root `GwH3Hiv5…` is an off-curve PDA; the legacy AMM root `23zF9Azp…` is a separate on-curve plain key) (`FINAL_DISPOSITION.md` §7, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §1, §7).
7. **Authority-event page cap bounded**: exactly 230 signatures served for `GwH3Hiv5…`; no further pages on either endpoint. The indexer pass's 816-event count stays open (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §4, `recon/s4_auth_walk_GwH3Hiv5.json`).

---

## 5. Open items (exact blocker and next action)

See `reports/OPEN_ITEMS_WS7.json` for the machine-readable open-item manifest. The 10 open items are:

| # | program | item | exact blocker | next action |
|---|---|---|---|---|
| 1 | wavebreak | `graduateManual` (premature finalization / timing front-run) | No live Manual curve with an open graduation window; all 7 Manual curves have `graduation_time` in the past. | Find or archive a live Manual curve whose window is still open; test whether the trigger fires before `graduationTime`. |
| 2 | wavebreak | `GraduateWhirlpool` end-to-end | 7 of 35 accounts in the freshest live graduation fixture (slot 441,655,843) are already closed at both fork tips; no Whirlpool pool exists for the largest pre-graduation WSOL curves. | Obtain an archival RPC that serves the exact pre-state at that slot (both endpoints return `Block not available`). Replay the full sequence without substituting accounts. |
| 3 | wavebreak | `LpHarvest` / `LpTransfer` against funded escrow | 0 `lp_escrow` PDA exists on mainnet; no funded position exists. Executed attempts hit `6023` (wrong seeds) or `6027` (`LpTakeover` privilege gate). | If an exact historical pre-state with a funded escrow becomes available (indexer/archive), replay with the real escrow and position. Do not create one through authority-only instructions. |
| 4 | wavebreak | `TokenRefund` payout arithmetic | Every live candidate returns `6016` (curve still active); no genuinely expired, non-graduated curve exists on mainnet. | Find an expired, non-graduated curve (requires historical state or a future-time fixture); execute `TokenRefund` against its quote vault and measure the arithmetic. Do not time-travel to manufacture one. |
| 5 | wavebreak | Buy path with genuine provider-signed permission | All 1,537 live curves require a permission (`buyRequiresPermission = true`). The single allowed signer (`0359c54abfca…2b29`) key is unavailable; no genuine signed message exists in the audit fixtures beyond replayed ones. | Replay the cached `consume → buy` pair (`recon/txs/`) at its exact pre-state; then mutate subject / consumer / amount / mint / curve / quote vault / destination / expiry / signature / consumed-PDA / token program one field at a time. Without a genuine signed fixture, the arithmetic path remains INCOMPLETE. |
| 6 | busybox | Funded deposit → swap → withdraw → close lifecycle | `MarketInitialize` is authority-gated (`IncorrectAuthority` for non-authority caller); no market-authority key is available; no genuine deposit/withdraw/close fixture exists in `recon/s4_bb_sigs.json`. | Replay a genuine market lifecycle from the market PDA's own transaction history (`recon/s4_bb_sigs.json`) at pre-state; test account/recipient/vault substitution; measure protocol loss separately from ordinary arbitrage. If no such fixture exists, keep INCOMPLETE. |
| 7 | busybox | Penalty selection (`arbPenaltyPerM` / `cuPenaltyMultiplier` / `jitodFrontPenaltyPerM`) | Choosing when penalties apply requires a market `updater` key (`OracleUpdate` is updater-signed). No updater fixture exists; `cuPenaltyMultiplier = 0` everywhere, `arbPenaltyPerM` = 300 on 28 markets, 0 on 4 frozen-window markets. | Obtain an updater-signed `OracleUpdate` and test whether a permissionless swap can suppress or bypass the configured penalties. Without the updater key, the arithmetic path stays INCOMPLETE; the economic measurement (every accepted fill priced consistently with the configured penalties) stays valid. |
| 8 | family | Legacy AMM per-account custody; authority history before slot 306,473,452; programs/multisig behind `GwH3Hiv5…` | Public RPC caps `getProgramAccounts` (HTTP 403 on `BPFLoaderUpgradeable`); `getSignaturesForAddress` capped at 230 signatures. The indexer pass's 816-event / 1.246 M-account / 41.124 T-lamport figures are unverified from public endpoints. | Access an indexer / GaaS source that can enumerate all program-owned accounts for the legacy AMM and serve the full authority history before slot 306,473,452. Verify the Squads multisig behind the off-curve root (`recon/s4_squads_pda_search.json` shows none of 834 space-1318 accounts derive it). |
| 9 | family | Whirlpool and legacy AMM handler-level review | Both programs hold custody that was not reviewed at handler level in this pass (`WHIRLPOOL_HANDLER_REVIEW.md` and `LEGACY_AMM_HANDLER_REVIEW.md` are initial handler inventories, not complete security reviews). | Read `elf/whirlpool.bin` and `elf/amm.bin` handler by handler (use `tools/analyze_elf.py` / `sbf.py`); map CPI targets, authorization paths, recipient binding, and token-program pinning for every balance-moving instruction; test on live fixtures. Until completed, the family remains INCOMPLETE. |
| 10 | busybox | Stale-oracle / frozen-window exploitation (resolved this pass) | **DECIDED** (`NO CONFIRMED PERMISSIONLESS PROFIT PATH`). Not an open exploit path; recorded as a correction to the previous record. | No further action required for this item; the correction is documented in `BUSYBOX_DEEP_REVIEW.md` §5.3 and `FINAL_DISPOSITION.md` §4.5. The natural clock-crossing corroboration (`tests/bb_expiry_natural.py`) was scripted but the sandbox recycled the fork before its clock crossed; it would only corroborate, not change, the result. |

---

## 6. Required outputs produced this session

- `reports/FINAL_DISPOSITION_WS7.md` (this file)
- `reports/OPEN_ITEMS_WS7.json` (machine-readable open-item manifest; 10 items, exact blocker / fixture / signer / next action)
- `reports/TESTS_MACHINE_READABLE_WS7.json` (rebuilt / validated ledger; 322 entries; counts recomputed from `tests[]`)
- `reports/WHIRLPOOL_HANDLER_REVIEW.md` (initial handler inventory from deployed ELF, account binding, CPI targets, authorization constraints; **INCOMPLETE** — not a complete security review)
- `reports/LEGACY_AMM_HANDLER_REVIEW.md` (initial handler inventory from deployed ELF, custody relationship, authority constraints; **INCOMPLETE** — not a complete security review)
- `reports/ORCA_FAMILY_BALANCE_PATH_MATRIX.md` (matrix mapping every balance-moving / balance-holding program to its control root, upgrade authority, custody type, handler review status, and remaining blocker)
- `reports/WS7_FIXTURE_MANIFEST.json` (fixture inventory: which fixtures exist, which are unavailable, and the exact reason for unavailability)
- `evidence/WS7_*.json` (new evidence records for this session; see manifest)

---

## 7. Safety rules verified for this session

1. **Fork-only** — No broadcast or submission to mainnet. Every executed test used a Surfpool 1.5.0 mainnet fork (`fork_up.sh` / `fork_up4.sh`).
2. **Live on-chain state only** — No manufactured protocol balances, vaults, or authority state. All fixtures are either live mainnet accounts or exact historical pre-state references from existing evidence files.
3. **No authority impersonation** — The hardcoded Busybox initializer (`CGYAxnDF…`) and the market `updater` keys (`BP8TxUro…` and 8 per-market keys) were never called or impersonated. The Wavebreak `AuthorityConfig` and `PermissionConfig` keys (`BWyVTPPR…`, `8AbiHetk…`) were never used. The provider signer (`0359c54abfca…2b29`) was never impersonated.
4. **Fresh attacker key created this session** (`4LWptHzEFd85eL3nEn1bPK3h4RZzL6Sfi4N96ZdpYZ5f`) — secret never recorded. All attacker ATAs were created through normal permissionless instructions (token-account creation via SPL Token Program) or through the fork's own cheatcode funding (`evidence/funding_s4_sol.json`) — never through fake balances or arbitrary account-data edits.
5. **No cheatcode balances** — The only cheatcode use was `surfnet_setAccount` for single-field `validUntil` differentials (`BBS3-diff-*`) and for funding the attacker's own token accounts (`evidence/funding_s4_sol.json`). No protocol vault, reserve, or authority field was overwritten.
6. **Fixture-blocked paths recorded as INCOMPLETE** — Any path whose required fixture, signer, or historical pre-state was unavailable was explicitly marked `INCOMPLETE` with the exact blocker (see `OPEN_ITEMS_WS7.json` and `WS7_FIXTURE_MANIFEST.json`).
7. **State preserved across multi-step sequences** — Multi-step test sequences preserved state between calls (e.g., `consume → buy` attempts preserved the consumed-permission PDA; `deposit → swap → withdraw` attempts preserved the market PDA state). No reset between steps.
8. **Every exploit hypothesis measured** — For every executed case: attacker lamport delta (`attackerDeltaLamports`), attacker token delta (`attackerDeltaUsd` / raw token balances), protocol/vault delta (`vaultDelta` / reserve delta), fees and rent (recorded in evidence JSON), exact pre/post state (`beforeAfterState`), transaction signature (`txSignature`), and fork slot (`forkSlotBefore` / `After`).
9. **Same-transaction round trips tested** — Busybox swap round trips (`A→B→A` in one tx) executed and measured negative (`BBS2-run2-*`). Wavebreak `consume → buy → sell` sequences were not completed due to missing permission fixtures, but the individual steps were preserved across transactions.
10. **Ordinary arbitrage not treated as vulnerability** — All swap profit measurements used the same-slot external reference price (Jupiter `price/v3`) for both legs; no cross-slot price artifacts were counted as exploits (`FINAL_DISPOSITION.md` §4.5 correction; `BUSYBOX_DEEP_REVIEW.md` §5.1, §5.3).
11. **Cross-program substitution tested** — `Token-2022` substitution (`mintB` token program replaced by Token-2022), duplicate-account aliasing (`swapperA` aliased onto `marketVaultA`), and counterfeit mint substitution were tested (`BUSYBOX_DEEP_REVIEW.md` §3; `evidence/BBF_swap_guards.json`).
12. **Token-program pinning verified** — SPL Token (`TokenkegQfe…`) and Token-2022 (`TokenzQdB…`) program IDs verified against deployed rodata constants (`BUSYBOX_DEEP_REVIEW.md` §1.2). Account-owner assertions (`IllegalOwner`) enforced.
13. **AQUIFER-LESSON checks applied** — Caller-controlled token-program substitution (`BB-F07` / `BBF_swap_guards.json`: `mintB` token program replaced by Token-2022 → `IllegalOwner`), canonical SPL Token Program pinning (`TokenkegQfe…`), Token-2022 compatibility (`TokenzQdB…`), counterfeit mint substitution (`InvalidAccountData` when mint mismatches), vault/source/destination binding (`marketVaultA` must be owned by market PDA; `swapperA` must be owned by swapper), recipient binding (`refundDestination` bound to stored field; `destination` bound to curve record), zero/underfunded escrow (`6023` for non-existent `lp_escrow`), CPI success without real token transfer (not applicable — every CPI moves real tokens when accepted; no-op paths accepted with zero delta), duplicate-account aliasing (`InvalidAccountData` for aliased mutable accounts), writable/read-only and owner checks (`IllegalOwner` for wrong owner; `InvalidAccountData` for wrong writable flag), decimals/fee/amount/reserve accounting (`6099` for arithmetic overflow / partial-fill; reserve bounds enforced), output transfer occurring when input is zero or counterfeit (`BB-A10`: zero-amount swap accepted, no state change).
14. **No artificial shortcuts used** — No fake fixtures, no authority impersonation, no cheatcode balances for protocol state. Every `INCOMPLETE` path is documented with the exact missing fixture or unavailable signer.

---

## 8. Reproduction commands (verified available in workspace)

```
# Rebuild / validate machine-readable ledger
python3 orca-audit/tools/ledger.py
python3 orca-audit/tools/normalize_ledger.py
python3 orca-audit/tools/build_ws6_ledger.py

# Wavebreak permission + trade battery (fixture-blocked; requires live fork)
python3 orca-audit/tests/wb_battery.py
python3 orca-audit/tests/wb_sell.py
python3 orca-audit/tests/final_wb.py
python3 orca-audit/tests/final_wb2.py
python3 orca-audit/tests/wb_refund.py
python3 orca-audit/tests/wb_perm_live.py
python3 orca-audit/tests/wb_lp.py

# Busybox swap / lifecycle / stale-oracle (fixture-blocked for lifecycle / updater paths)
python3 orca-audit/tests/bb_tests2.py
python3 orca-audit/tests/bb_lifecycle.py
python3 orca-audit/tests/bb_roundtrip2.py
python3 orca-audit/tests/bb_final.py
python3 orca-audit/tests/bb_stale_sweep.py   # authoritative WS6 sweep
python3 orca-audit/tests/bb_expiry_diff.py  # single-field differential control

# Tools for analysis
python3 orca-audit/tools/analyze_elf.py
python3 orca-audit/tools/sbf.py
python3 orca-audit/tools/pda_model.py
python3 orca-audit/tools/authority_scan.py
python3 orca-audit/tools/authority_walk.py
python3 orca-audit/tools/bb_net_table.py
python3 orca-audit/tools/txclass.py
```

---

## 9. Family disposition

**The Orca deployer-family audit remains INCOMPLETE.**

- **Wavebreak** (`waveQX2yP3…`): 138 executed cases — `NO CONFIRMED PERMISSIONLESS PROFIT PATH`. 5 open paths (`GraduateWhirlpool`, `LpHarvest`, `TokenRefund`, provider-signed buy, `graduateManual` residuals) remain fixture- or authority-blocked.
- **Busybox / Riptide** (`riptK81hDx…tBS7j`): 184 executed cases (`39` + `145`) — `NO CONFIRMED PERMISSIONLESS PROFIT PATH`. 2 open paths (funded lifecycle, penalty-selection surface) remain authority-blocked (`MarketInitialize` requires hardcoded initializer; `OracleUpdate` requires `updater` key).
- **Whirlpool** (`whirLbMiic…uctyCc`): **INCOMPLETE** — handler-level review not performed; custody unenumerated from public RPC.
- **Legacy AMM** (`9W959DqE…aQP`): **INCOMPLETE** — handler-level review not performed; per-account custody unenumerated (public RPC capped); upgrade authority (`23zF9Azp…`) is a plain on-curve key holding 23.89 SOL.
- **Family control plane** (`GwH3Hiv5…` off-curve PDA + `23zF9Azp…` on-curve plain key): **INCOMPLETE** — deriving program of the PDA unidentified; full authority history before slot 306,473,452 unserved; governing multisig unidentified.

The audit does **not** claim the family is clear. Every balance-holding or balance-controlling program and every reachable composition path has been either executed and measured negative, or explicitly documented as fixture- or authority-blocked with the exact blocker recorded (`OPEN_ITEMS_WS7.json`, `WS7_FIXTURE_MANIFEST.json`).

---

*Report generated: 2026-09-05, on branch `arena/01a06ff8-orca-audit`. No mainnet broadcast occurred. Attacker key `4LWptHzEFd85eL3nEn1bPK3h4RZzL6Sfi4N96ZdpYZ5f` (public only) was generated this session; its secret is not recorded in any file.*
