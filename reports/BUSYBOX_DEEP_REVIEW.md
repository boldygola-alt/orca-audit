# Busybox / Riptide AMM deep review (defensive, fork-only)

Program `riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j`
Reviewed 2026-09-04 against the deployed ELF, live market state, and a state-preserving Surfpool
mainnet fork (fork slot 444,277,192 for the later batches; 444,209,4xx–444,226,xxx for the earlier
ones). No mainnet broadcast.

## 0. What this program actually is (identity, rule 2)

| item | value |
|---|---|
| program | `riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j` |
| ProgramData | `4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu`, 1,803,788,400 lamports |
| upgrade slot / lock | 440,010,891 / locked |
| upgrade authority | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` (same key as Whirlpool + Wavebreak) |
| deployed ELF | 258,992 B, sha256 `32a8a8f75662cfdc8d29abe4bf6826c9c027a4b9222d544f46285762c661ab86` — **byte-identical to the earlier pass**, so prior offsets stay valid |
| embedded SECURITY.TXT | name **"Riptide AMM Program"**, version **2.1.1**, project `https://riptide.so`, contact `security@riptide.so` |
| matching client | crate `riptide-amm` **2.1.1** (published 2026-07-20) — version-matched to the deployed build, used for layouts only, then verified against live state |
| module evidence in the binary | `solana-program/src/routers/orca_busybox.rs`, `src/penalty/{cu,arb}.rs`, `src/math/oracle/{amm,book,flat,skew,spread}.rs`, `src/math/transfer_fee.rs` |

So this is Riptide's oracle-priced AMM that contains an "Orca busybox" router module — not an Orca
router program with ledger handlers. That distinction changes the review, so it is stated up front.

## 1. Handler set, from the deployed binary and from executed probes

Instruction-name table in `.rodata` (`.text` = 0x120 + 0x38808), enum order == wire tag:

```
0 ProgramVersion   1 OracleUpdate   2 SwapExactIn   3 SwapExactOut
4-7 ReservedSwapX/Y/Z/A
8 MarketInitialize  9 MarketUpdate  10 MarketDeposit  11 MarketWithdraw  12 MarketClose
13-15 ReservedMarketX/Y/Z
```

Executed tag sweep against a live market with a *plausible* account shape (`evidence/BB_tagsweep.json`),
which is the honest way to separate "reserved" from "unreachable because of a setup artifact":

| tag | log emitted by the deployed program | outcome |
|---|---|---|
| 0 | `ProgramVersion` | ok |
| 1 | `OracleUpdate` | `IncorrectAuthority` when the caller is not the stored `updater` (WB/BB-A05, BB-A06) |
| 2 | `SwapExactIn` | **executes** (see §3) |
| 3 | `SwapExactOut` | **executes** (bounded by reserves, §3) |
| 4,5,6,7 | `ReservedSwapX/Y/Z/A` | `InvalidInstructionData` — declared-but-inert slots |
| 8 | `MarketInitialize` | `IncorrectAuthority`: "Account `<caller>` is not the authority" |
| 9,10,11,12 | `MarketUpdate/Deposit/Withdraw/Close` | `IncorrectAuthority` for a non-authority caller |
| 13,14,15 | `ReservedMarketX/Y/Z` | `InvalidInstructionData` — inert |

### 1.1 Correction of the earlier conclusion

The previous pass recorded "tags 0x02–0x07 → InvalidAccountData @9 CU ⇒ swap handlers not
implemented". **That was an account-count artifact** (the instructions were sent with zero accounts,
so the framework rejected them before any handler ran). With the correct 12-account shape the swap
handlers run, log their names, price against the stored oracle and move real tokens. There are,
however, genuinely **no** `RouteV2 / Route / RouteWithTokenLedger / SwapV2 / Swap2 / TransferChecked /
TransferCheckedWithFee / SetTokenLedger / Oracle` *instruction* variants anywhere in the deployed
binary (no such names in the handler table, and `getTokenLargestAccounts`-style router CPI targets are
absent) — the router logic lives in the `src/routers/orca_busybox.rs` module used by the swap path.

### 1.2 External surface

Imports: `sol_invoke_signed_c` (5 sites: `0x6268 0x7640 0x8910 0xa388 0x245f0`),
`sol_try_find_program_address` (`0x25e00`), `sol_get_sysvar` (`0x4060 0x8f10 0x219d8 0x245f0`),
`sol_keccak256`, `sol_memcmp_` (`0x36470`), `sol_set_return_data` (`0x2a98`), `sol_log_data`.
No `sol_secp256k1_recover`, no signature verification inside the program: the oracle payload is
authorized purely by the `updater` **signer** of `OracleUpdate`. Program-pinning constants in
`.rodata`: SPL Token `0x38dcb` (used by `0x25688`), Token-2022 `0x38ae8`/`0x38deb`
(`0x29ef0`, `0x6268`), ATA `0x389c8` (`0x27d08`, `0x7640`, `0xa388`), memo `0x38a28`,
instructions sysvar `0x38988`, clock `0x38ac8`, and a hardcoded authority `0x38a48` =
`CGYAxnDF1bYwmbzTtVx2pdo8xd3aviqE58WumVYRLYRH` referenced **only** by `0xa388` (the
market-initialize path, which also uses the ATA program and CPI) — i.e. market creation is gated to
one designated initializer key, which matches the executed `is not the authority` result.

## 2. Market layout and state, verified from live accounts (rule 2)

Verified layout (1,024 B, disc byte 2 = Market):
`0 disc | 1 bump | 2 cuPenaltyMultiplier | 3 maxInventoryImbalanceGuardPerCent | 4 id u32 |
8 authority | 40 updater | 72 mintA | 104 mintB | 136 sequence u64 | 144 validUntil u64 |
152 oracle[512] | 664 minSpreadGuardPerM i32 | 668 arbPenaltyPerM u32 | 672 jitodFrontPenaltyPerM u32 |
676 pad12 | 688 minOraclePriceGuard u128 | 704 maxOraclePriceGuard u128 | 720 skewCliffMin i32 |
724 skewCliffMax i32 | 728 maxAInventoryPerM u32 | 732 maxBInventoryPerM u32 | 736 reservesA u64 |
744 reservesB u64 | 752 pad272`.

Market PDA seed resolved (the earlier pass left this "unresolved"):
`find_program_address(["market", u32le(market_id)], riptK81h…)` — **12/12 live markets reproduce**,
and the v2.1.1 client's own vector (`id=1 → DmsXVUSAyKyscrjhstJG9RroQz7864WxmAStmFenWkvV`) matches.

Live inventory (`recon/busybox_markets_live.json`, `busybox_custody_atomic_fixed.json`,
`busybox_oracle_states.json`, `busybox_inventory_summary.json`; mainnet slot 444,233,360):

* 32 markets; 14 hold inventory, 18 have zero reserves; market rent total 112,253,880 lamports;
  program-owned total 256,747,447 lamports.
* **reserves vs vault: exact equality on all 32 markets** (Σvault − Σreserves = 0). My first
  comparison showed 10 markets "diverging" — that was my own artifact (Token-2022 vaults are
  170 B, and I had required 165 B) plus a non-atomic read; the corrected atomic read is 0 divergent.
* oracle payload variants in use: 0 (empty, 17 markets), 3 = OrderBook (8), 4 = AutomatedMarketMaker (7).
* custody concentration: `FefUJfaS2Vpk…` 237.4 B units A vs 4,167 units B; `9PwXMVkF…`
  64.9 B / 60.8 B; `GxGxQBvM…` 24.7 B / 46.0 B; `HxNaPy1o…` 16.6 B / 49.9 B; `6Vzx4ASR…`
  24.9 B / 25.1 B; `4AFfguVTj7…` 48.3 B / 5.4 B; `GtBJeuFzSC…` 12.4 M / 13.7 M (USDT/USDC).
* authorities: `CGYAxnDF1bYw…` 18, `2C7K3BN63M…` 6, `BWyVTPPRW7…` 6 (the same key that holds
  Wavebreak's `AuthorityConfig` slot 0 and privilege set 0,2–8 — a real cross-program relationship),
  `CYkPyQ2cdA…` 1; updaters: `BP8TxUroBDw9…` 22, plus 8 distinct per-market updater keys.
* oracle freshness at read time: 11 markets within a few slots of the current slot (actively pushed),
  3 expired by 0.8 M–29.2 M slots (`4AFfguVTj7…`, `5783KdWD…`, `CzuQmqj4…`), and several with
  `validUntil` set ~85–90 M slots in the future (deliberate frozen-price windows).

## 3. Executed swap results (fork, funded attacker, per-instruction state capture)

Swaps need only the **swapper's** signature; the market's own vaults move via PDA-signed CPI.
Account list (verified against live `marketDeposit`/`marketWithdraw` forms):
`[swapper W/S, market W, mintA W, mintB W, swapperA W, swapperB W, marketVaultA W, marketVaultB W,
tokenProgramA, tokenProgramB, memo, instructionsSysvar]`,
data `tag | amount u64 | amountIsTokenA u8 | SlippageTolerance(0 None | 1 MaxExecutionPrice u128 |
2 OtherAmountThreshold u64) | allowPartialFill u8`.

Measured (`evidence/BBR_roundtrip.json`, `BBP_swap_profit.json`, `BBA_auth_sweep.json`,
`BBS_stale_oracle.json`, `BB_tagsweep.json`):

| case | result |
|---|---|
| 10 USDT → USDC on `GtBJeuFzSC…` (fresh oracle) | **executed**: −10,000,000 A / +9,984,965 B; reserves +10,000,000 A, −9,984,965 B; round-trip net −10,000,000 A ⇒ swapper pays the spread, takes nothing out |
| second and third identical leg | `6099` "Partial fill is not allowed" (reserves exhausted on the far side) |
| exact-OUT asking the whole opposite vault | `6099`, or the token program's `insufficient funds` when the request exceeded reserves |
| zero-amount swap | accepted, no state change (no-op path, log "Hammerhead hunting") |
| `MaxExecutionPrice` set to an impossible bound | `6099` |
| duplicate mutable account (swapperA aliased onto marketVaultA) | `InvalidAccountData` "Token account … has wrong owner" |
| token-program substitution (mintA under Token-2022 while the mint is SPL) | `IllegalOwner` "Account … is not owned by TokenzQ…" |
| swap on a market whose stored oracle is empty (variant 0) | `InvalidAccountData` "Oracle data is invalid" |
| swap on a market whose **stored `validUntil` is in the past** (29.2 M slots) | `InvalidAccountData` "Oracle data is invalid" — **`validUntil` IS enforced at swap time** (see §5: the earlier "6.5k-slot-stale oracle traded" reading compared the *last update* slot, not `slot > validUntil`) |
| `OracleUpdate` signed by a non-updater, incl. a replay of the current `sequence` | `IncorrectAuthority` |
| `MarketDeposit/Withdraw/Update/Close` by a non-authority | `IncorrectAuthority` "Account … is not the authority" |
| `MarketInitialize` by the attacker (own id, own mints, correct shape) | `IncorrectAuthority` — creation is gated to the hardcoded initializer (§1.2) |

## 4. Status

* **`SwapExactIn` / `SwapExactOut`: NO CONFIRMED PERMISSIONLESS PROFIT PATH.** Permissionless and
  live, but every executed variant was value-neutral or value-negative for the caller; payouts are
  bounded by stored reserves, reserves equal the vaults exactly on all 32 markets, oracle data is
  only writable by the per-market `updater`, and account/program pinning plus duplicate-account
  aliasing are rejected.
* **`MarketDeposit/Withdraw/Update/Close/Initialize`: NO CONFIRMED PERMISSIONLESS PROFIT PATH**
  (authority-gated; `close` additionally requires zero reserves — "Cannot close market with non-zero
  reserves" is in the deployed rodata and the earlier pass measured the successful zero-reserve
  variant paying the *authority*, never the caller).
* **`OracleUpdate`: NO CONFIRMED PERMISSIONLESS PROFIT PATH** (single signer binding to
  `market.updater`; no in-program signature scheme to attack; sequence replay rejected).
* **Reserved tags 4–7, 13–15: NO CONFIRMED PERMISSIONLESS PROFIT PATH** — declared slots that return
  `InvalidInstructionData` with their handler name logged, i.e. unreachable inert code, verified from
  the deployed binary rather than inferred from an IDL.
* **INCOMPLETE** (do not read as clear):
  1. *legitimate funded deposit → swap → withdraw → close accounting*: unmeasurable, because market
     creation is itself authority-gated and no market authority key is available; we refused to
     call owner functions or fabricate the state.
  2. *penalty bypass*: whether `arbPenaltyPerM`, `cuPenaltyMultiplier` and `jitodFrontPenaltyPerM`
     can be *dodged* (as opposed to merely paid) still needs a controlled oracle push, i.e. a market
     `updater` key. What is now measured is the economic consequence of trading against any of these
     markets' stored prices: nothing (§5).
  3. ~~`validUntil` semantics~~ **resolved this pass**: the stored `validUntil` is a hard swap-time
     gate, measured by a single-field differential on two markets (§5.3). The previous claim in this
     file (and in `FINAL_DISPOSITION.md` §4.5) that it was "not a slot gate" was wrong and is
     corrected here.
  4. ~~markets with frozen windows~~ **resolved this pass**: the four `validUntil` ~85–90 M-ahead
     markets with real inventory were swept in both directions at 1 %/5 %/25 % of reserves against an
     external reference price — no material gain (§5.2).

## 5. WS6 — stale-oracle, frozen-window and penalty sweep (this pass)

Method.  One fresh, unprivileged keypair; the Surfpool fork's copy of live mainnet state (no oracle,
vault, reserve or authority field was written for any probe below). For every funded market we executed
`SwapExactIn` in **both directions** at 1 %/5 %/25 % of stored reserves plus a composed **round trip in a
single transaction** (exact-in then exact-out), and valued *both legs* of every fill with an independent
external reference price (Jupiter `price/v3`) captured at the same scan, so a "profit" cannot be an
artifact of pricing the two sides at different times. Every swap uses the exact deployed 12-account shape.
Attack inputs existed only as fork-cheatcode funding of our own token accounts (14 ATAs), recorded in
`evidence/funding_s4_sol.json` and never counted as a gain.

Executed: **145 cases** — 139 swap probes (65 in the authoritative run: 53 accepted,
12 rejected; 74 in the superseded earlier run) plus 6 single-field differential controls
(`evidence/BBS2_stale_sweep.json` = authoritative run, `evidence/BBS2_stale_sweep_parsed.json`
= the earlier run of the same probe set, kept and flagged "(superseded)"; per-case net USD in
`evidence/BBS2_net_deltas.json`, ledger ids `BBS2-run2-*` / `BBS2-run1-*`).

### 5.1 32 markets inventoried, 14 funded, every funded one traded

| market | oracle variant | stored state at execution | result |
|---|---|---|---|
| `9PwXMVkFzW…` | 3 OrderBook | price 1.0141307, `validUntil` 1,050 slots ahead of the fork clock | accepted; actor net **−$1.38 … +$0.02** |
| `CNp3etjEmW…` | 3 OrderBook | live updater, window ~35 slots | accepted; actor net **−$11.50 … $0.00** |
| `GxGxQBvMQ7…` | 3 OrderBook | live | accepted; **−$34.32 … +$0.48** |
| `G9pQE63etk…` | 3 OrderBook | live | accepted; **−$0.75 … +$11.06** (largest positive of the pass, 0.39 % of a $2,892 leg) |
| `9Bc7tyaZft…`, `HxNaPy1oYA…`, `HpGbZwwQ66…` | 3 OrderBook | live | accepted; all ≤ +$1.33 |
| `6Vzx4ASRjU…`, `8hbdkPt2CU…`, `GtBJeuFzSC…` | 4 AutomatedMarketMaker, `validUntil` 84–90 M slots ahead (frozen window) | real inventory | accepted; **−$8.42 … +$1.57** (the +$1.57 is the 2 bp USDT/USDC reference difference, not a protocol leak) |
| `FefUJfaS2V…` | 4 | `reservesB = 3,546` (dust side) | rejected custom 6099 — reserves cap the payout |
| `CzuQmqj4dS…` | 3, `validUntil` **29,236,225 slots in the past** | non-degenerate book (9 bid + 9 ask levels, 999,995 per-m) | **rejected** "Oracle data is invalid" |
| `4AFfguVTj7…`, `5783KdWDm8…` | 0 Empty | — | rejected "Oracle data is invalid" (no liquidity, not expiry) |

Across the 43 executions of the authoritative run whose two legs both carry a same-slot reference
price, the actor was net-positive in 15 of them, max **$11.06**, and the
**sum of all positive outcomes is $19.01** while every same-transaction round trip cost money (−1,377,931 USDC = −$1.38 on
`9PwXMVkFzW` at 25 % in the authoritative run, −1,421,578 USDC in the superseded earlier run; −$0.35 to
−$0.91 on the other LST markets at 1 %). That is the
signature of a market that charges the spread, not of an extractable accounting error.

### 5.2 The penalties are being applied, and no fresh key realized value from them

Every accepted fill's effective price sat between the oracle mid and the reference by the configured
tolerances; the only rejections seen were `6099` (max-execution-price / partial-fill), custom `1`
(arithmetic bound when the request exceeded the far side) and the oracle gate. `cuPenaltyMultiplier = 0`
and `maxA/maxB = 0` on all 32 markets, so those two knobs are inert in the deployed configuration.
Conclusion for this surface: **NO CONFIRMED PERMISSIONLESS PROFIT PATH.**

### 5.3 `validUntil` is a hard gate — measured by a single-field differential

`Oracle data is invalid` is ambiguous: `riptide-amm-math` returns the same error both when the 512-byte
payload fails to deserialize and when it yields no liquidity (`OracleData::Empty`), so a rejected expired
market proves nothing on its own. Decoded `CzuQmqj4dS…`'s payload first: variant 3, price 1.2747305 q64.64,
`Exponential(100)` spacing, 9 bid and 9 ask levels summing to 999,995 per-m — a perfectly well-formed,
non-degenerate book (`recon/s4_bb_oracle_decode.json`). Then, on the fork only, exactly one `u64` was
rewritten and restored (`evidence/BBS3_expiry_diff.json`, ids `BBS3-diff-01…07`):

| probe | market | `validUntil` vs fork slot | outcome |
|---|---|---|---|
| 1 baseline | `CzuQmqj4dS` | expired by 29.2 M slots | `InvalidAccountData` — "Oracle data is invalid" |
| 2 same tx, `validUntil := slot+5000` | `CzuQmqj4dS` | valid | **`ArithmeticOverflow`** — the oracle step was *passed*, failure moved to the book walk |
| 3 restore original bytes | `CzuQmqj4dS` | expired | back to "Oracle data is invalid" ⇒ probe 2's change is attributable to that one field |
| 4a control | `9PwXMVkFzW` (funded, live) | valid | executed |
| 4b same instruction, `validUntil := slot−10` | `9PwXMVkFzW` | expired | **rejected** "Oracle data is invalid" |
| 4c restore | `9PwXMVkFzW` | valid | executed |

So the deployed swap handler **does** enforce the market's stored expiry, which is why the
"frozen window" markets are safe to leave open: their `validUntil` is deliberately far ahead and their
price is the updater's own choice. **This corrects the previous record** (this file's §3 table and
`FINAL_DISPOSITION.md` §4.5), which said the opposite; that claim came from `evidence/BBP_swap_profit.json`
case "BB-P03 … STALE-oracle market `9Bc7tyaZft` → executed", where "stale" was measured as *slots since the
last oracle update*, while that market's `validUntil` was in fact still ~39 slots in the future — the swap
was inside the window, exactly as the gate predicts.

*Not completed:* the purely natural confirmation (send the identical instruction after the **fork clock**
passes an untouched market's `validUntil`) was scripted (`tests/bb_expiry_natural.py`) but the fork was
recycled by the sandbox before its clock crossed the slot; it would only corroborate, not change, 5.3.

### 5.4 What the deployed binary's rodata says about the guard set

`elf/busybox.bin` (258,992 B, sha256 `32a8a8f75662cfdc…`, byte-identical to ProgramData `4RhNxb6VAhj9…`)
contains, as strings: the handler enum `ProgramVersion OracleUpdate SwapExactIn SwapExactOut ReservedSwapX
ReservedSwapY ReservedSwapZ ReservedSwapA MarketUpdate MarketDeposit MarketWithdraw MarketClose
ReservedMarketX ReservedMarketY ReservedMarketZ`; module paths `src/penalty/cu.rs`, `src/penalty/arb.rs`,
`src/math/oracle/amm.rs`, `src/math/oracle/mod.rs`, `src/routers/orca_busybox.rs`; and messages "Oracle data
is invalid", "Cannot close market with non-zero reserves: reserves_a=…, reserves_b=…", "Partial fill is not
allowed", "Slippage threshold exceeded", "Attempt to fill more than specified", "BPS exceeds 10000", "Amount
exceeds max u128/u64/u32/i32". It does **not** contain any of the published `math::guards` error texts
("oracle expired", "inventory imbalance", "A/B-side inventory cap exceeded", "spread below minimum", "oracle
price below/above maximum"). Read together with 5.3: the shipped program enforces freshness with its own
check, and the *spread floor / inventory-imbalance / oracle-price* guards named in the market struct
The *configured* guard values, read from the deployed accounts rather than from an IDL, are:
`maxInventoryImbalanceGuardPerCent = 100` on all 32 markets, `minSpreadGuardPerM` ∈ {0 ×18, −500 ×2,
−1000 ×3, −2500 ×8, −5000 ×1}, `maxAInventoryPerM`/`maxBInventoryPerM` = 0 (disabled) on 31 of 32,
`arbPenaltyPerM` = 300 on 28 and 0 on 4 (the four frozen-window AMM markets), `cuPenaltyMultiplier` = 0 everywhere. No guard error text is in
the binary and no rejection we could provoke looked like a guard: every rejection was the oracle gate,
`6099` (slippage / partial fill) or custom `1` (arithmetic bound). **Consequence for LPs:** the stored
guard fields behave as advisory metadata that the swap path does not enforce; what is enforced is the
window (`validUntil`), the reserve bound, the per-fill slippage bound and the partial-fill flag.
