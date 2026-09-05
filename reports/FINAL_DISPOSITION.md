# Final disposition — Orca program family (Wavebreak · Busybox/Riptide · Whirlpool · legacy AMM)

Defensive, fork-only re-audit, completed 2026-09-04. Nothing was broadcast to mainnet; no key,
token, seed or wallet private material is recorded in any file of this audit (the attacker keypair
was generated this session and only its public address appears).

Machine-readable per-test ledger: `reports/TESTS_MACHINE_READABLE.json` — **316 entries**
(177 from the first pass + 145 from the WS6 Busybox sweep) and 10 open items. Flags across all entries: 146 executed successfully, 157 executed and were denied by the program, 13 were not executed (fixture- or authority-blocked) — 309 of the 322 entries carry a real fork transaction signature. `counts` in that file is now the authority for every number quoted
in prose, and it records why the earlier documents disagreed (the ledger held 177 entries while its stale
`statusCounts` block still read 178 + 8; the 8 INCOMPLETE paths were items in `openItems`, never entries in
`tests`). Evidence files under `orca-audit/evidence/`.

## 1. Dispositions

| scope | status | basis |
|---|---|---|
| **Wavebreak** `waveQX2yP3…srXTF` — 31 handlers, permission layer, trade/refund/graduation/LP paths | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | 138 executed fork cases; every money path either privilege-gated (`6027`, with the required privilege named in the log), state-gated (`6013/6016/6019`), permission-gated (`6018/6002/6003/6004/6001`), or accepted with a *measured* zero/negative caller delta |
| **Wavebreak** `GraduateWhirlpool` end-to-end (LP escrow + position custody) | **INCOMPLETE** | live fixture unusable: 7 of 35 accounts closed at both fork tips; derived-pool attempts terminate on `6022/6023` account checks, not on an authorization decision |
| **Wavebreak** `LpHarvest` / `LpTransfer` on funded escrow; `TokenRefund` payout arithmetic; buy-path arithmetic with a provider-signed permission | **INCOMPLETE** | 0 live `lp_escrow`/positions exist; no live curve reaches the refund-eligible state (`6016` on every candidate); all 1,537 curves set `buyRequiresPermission=true`, so buy arithmetic needs the off-chain signer's key |
| **Busybox / Riptide AMM** `riptK81hDx…tBS7j` — swap, market, oracle handlers, plus the WS6 stale-oracle/frozen-window/penalty sweep | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | 184 executed cases (39 + 145): swaps are **live and permissionless** (correcting the earlier "unimplemented" conclusion) yet every variant was value-neutral/negative; reserves == vault on all 32 markets; deposit/withdraw/update/close/initialize authority-gated; oracle write bound to `updater`; reserved tags inert |
| **Busybox** stale-oracle and frozen-window exploitation by permissionless swaps | **NO CONFIRMED PERMISSIONLESS PROFIT PATH** | 132 swap probes over every funded market (14), both directions, 1 %/5 %/25 % of reserves, plus same-transaction round trips, valued against an external reference at the same scan: 15 of 133 executions were net-positive for a fresh key, max **$11.06** (0.39 % of that $2,892 leg), sum of all positives **$19.01**, every round trip negative. The stored `validUntil` is enforced at swap time (single-field differential, §3.8) |
| **Busybox** legitimate funded deposit→swap→withdraw→close accounting; *penalty-bypass* selection | **INCOMPLETE** | market creation is itself gated to a hardcoded initializer (rodata `0x38a48` = `CGYAxnDF…`), and choosing when penalties apply needs a market `updater` key; neither was called or impersonated |
| **Whirlpool** `whirLbMiic…uctyCc` | **INCOMPLETE** (not reviewed at handler level in this pass) | its ProgramData holds 72,981,780,480 lamports of **rent** for a 10,485,715-byte ELF (not user funds); real custody is the program-owned account set (indexer pass: 1,106,108 accounts / 156,285 pools), and Whirlpool is the counterparty of Wavebreak's graduation CPI |
| **Legacy AMM** `9W959DqE…aQP` | **INCOMPLETE** (control plane dormant but **not renounced** — upgrade authority still `Some(23zF9Azp…)`, an on-curve plain key; custody not enumerated) | last upgrade slot 161,177,892; 2,377 txs/24 h of *trade* activity; per-account balances of its ~1.25 M owned accounts not enumerated (public RPC caps `getProgramAccounts`) |
| **Deployer family as a whole** | **INCOMPLETE** | balance-holding family programs (Whirlpool, legacy AMM) remain unreviewed at handler level, and the Wavebreak/Busybox items above are fixture- or authority-blocked |

## 2. Why the family cannot be marked clear

Rule: the family stays INCOMPLETE while any balance-holding or balance-controlling program is
unreviewed or fixture-blocked. Both conditions hold:

1. Whirlpool and the legacy AMM were not reviewed at handler level in this pass.
2. Five Wavebreak/Busybox paths are fixture- or authority-blocked rather than decided
   (`GraduateWhirlpool` end-to-end, LP escrow `LpHarvest`/`LpTransfer`, `TokenRefund` payout arithmetic,
   the provider-signed buy arithmetic, and Busybox's funded lifecycle + penalty-selection surface). The
   stale-oracle/frozen-window question that used to sit in that list is now decided (§4.5). We
   deliberately did not substitute cheatcode or impersonation-based shortcuts to turn any of them into
   "clean" results.

## 3. Corrections this pass makes to the previous record

1. **Busybox swap handlers are implemented and permissionless.** The earlier "tags 0x02–0x07 not
   implemented (`InvalidAccountData` @ 9 CU)" conclusion came from sending the tags with zero
   accounts. With the correct 12-account shape the deployed v2.1.1 program logs `Instruction:
   SwapExactIn/SwapExactOut` and trades against live reserves. Only tags 4–7 and 13–15 are inert
   reserved slots (`InvalidInstructionData`).
2. **The shared upgrade authority covers three programs, not four.** The legacy AMM's authority is
   `23zF9Az…`; `GwH3Hiv5…` owns Whirlpool, Wavebreak and Busybox.
3. **Wavebreak custody divergence is fully explained.** The +6.784577154 SOL of vault-over-accounting
   across 685 curves is unclaimed protocol/creator fee custody: a fee sweep drove one curve's
   divergence from +506,349,347 to exactly 0. It is not extractable by trading (measured: payout
   29,347 ≤ accounting release 29,644 and 1,002,638,546 ≤ 1,012,766,209) and `collectFees` credits
   only the bound privilege-1 fee authority.
4. **Busybox reserves-vs-vault divergence is zero.** The earlier "-22.5 B unbacked reserves" figure and
   this pass's first "10 divergent markets" reading were both measurement artifacts (Token-2022
   vaults are 170 bytes, and the two sides were read at different slots). Read atomically on mainnet,
   Σvault − Σreserves = 0 on all 32 markets.
5. **Busybox market PDA seed resolved:** `["market", u32le(marketId)]`, reproducing 12/12 live markets
   and the client's own vector (previously recorded as "seeds unresolved").
6. **Busybox is Riptide's AMM program** (SECURITY.TXT name "Riptide AMM Program" v2.1.1,
   `security@riptide.so`) containing an `orca_busybox` router module — not an Orca router with
   ledger handlers.
7. **The three programs under `GwH3Hiv5…` are still upgradable — they are not renounced.**
   Reading the four ProgramData accounts directly: version 3, `option` byte `0x01` (authority *present*)
   and `upgradeAuthority = GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` for Whirlpool (last upgrade slot
   440,170,207), Wavebreak (365,746,180) and Busybox/Riptide (440,010,891); `23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG`
   for the legacy AMM (161,177,892) — `recon/s4_program_upgrade_control.json`. An earlier note in this
   engagement described the first two as "locked"; that was a misreading of the *last upgrade slot* as a
   lock event, and it is corrected here. Two further facts: the shared root key is **off-curve**
   (`is_on_curve = False`), i.e. it is a PDA and cannot be signed for directly, whereas the legacy AMM's
   authority is an on-curve plain key holding 23.8916 SOL. Neither root could be tied to a specific Squads
   multisig from public RPC (see `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md`).
8. **The Busybox `validUntil` "grace period" was an artifact of the metric, and the earlier LST profit
   numbers were an artifact of the reference price.** `evidence/BBP_swap_profit.json` "BB-P03 … STALE
   market `9Bc7tyaZft` executed" measured staleness as *slots since the last oracle update* while that
   market's `validUntil` was still ~39 slots in the future — inside the window. Likewise the interim
   "+$1.29 / +$6.41 / +$30.75 on `9PwXMVkFzW`" figures came from valuing the two legs at reference prices
   captured ~1,000 slots apart; re-valuing both legs at one same-scan reference turns the same trades into
   **−$1.38 … +$0.02**. Both were re-measured this pass (`BBS2-*`, `BBS3-*`).
9. **Legacy-AMM per-account custody and the full authority history are not obtainable from the public
   RPCs available here.** `getProgramAccounts` on `BPFLoaderUpgradeable` is refused outright (HTTP 403 on
   both api.mainnet-beta and the publicnode fallback), so "every program currently under the root" cannot
   be enumerated by authority; `getSignaturesForAddress` for `GwH3Hiv5…` returns exactly one page of 230
   signatures ending at slot 306,473,452 and does not page further, so the 816-event figure from the
   indexer-based pass is neither reproduced nor refuted here — it stays open. A targeted search of the 834
   Squads accounts of space 1,318 found no account whose `["multisig", addr]` PDA equals the root, and the
   1,318-byte candidate's five owner-like slots are unrelated keys, so it is excluded as a third party.
10. **4 previously-INCOMPLETE Wavebreak cases are now decided:** consume replay (WB-RP1: the
   subject/consumer binding rejects a replayed live message, `6001`), attacker-as-consumer with a
   real live message+signature (WB-P07/RP1: same binding), and `PermissionRefund` against 31 live
   consumed-permission accounts (WB-R01/R02/RP4/RP5: `6001` "has wrong address"; WB-R03: the stored
   destination is accepted but `6000` "is not writable"). `GraduateWhirlpool` fixture presence
   (former WB-D00) remains INCOMPLETE with the reason recorded.

## 4. Findings worth the team's attention (all measured; none attacker-profitable)

1. **`graduateManual` is an unauthenticated trigger.** Any wallet can finalize a Manual-method curve
   once its window has passed — flipping `graduated`, moving the remaining quote to the recorded
   destination and minting the residual base supply to the destination's ATA. Destination and
   recipients are bound to the curve record and the double-payout path is closed (`6015`), so the
   caller gains nothing (measured: −5,000 lamports per attempt). The binary documents the intent
   ("Manual graduation is required to continue trading"). Open questions we could not settle on live
   state: whether it also fires while the window is open (no such live curve exists), and that the
   Whirlpool graduation hosts call the "graduation conditions" check (`0x137f0`) while the manual
   core (`0x2e910`) does not.
2. **`BondingCurveCollectFees` can be triggered by anyone** (measured: attacker-signed sweep of
   520,591,863 / 677,473,335 units, beneficiary bound to the privilege-1 fee authority). Fine as a
   design choice; worth documenting, since it lets any wallet pick the sweep moment and spend gas on
   the protocol's behalf.
3. **31 live `consumed_permission` accounts hold 41,420,920 lamports that nobody can recover**,
   because `refundDestination` was stored as `Pubkey::default()`; the refund path binds the
   destination to that field and the zero address cannot be made writable. Recommend: treat an unset
   destination as "pay the consumer", or require the field at consume time.
4. **All 1,537 live curves require a permission to buy but none to sell.** Sells are therefore the
   only open money-out path, and they are bounded by internal accounting — the property that makes
   the fee excess unreachable. Keep it that way: any change that lets a payout be capped by the
   *vault* instead of by `quoteAmount` would immediately expose the (currently 6.78 SOL and growing)
   uncollected fee custody to whichever holder sells last.
5. **Busybox enforces its oracle window, and the frozen-window markets are not a money printer**
   (this supersedes the previous version of this item, which said the opposite). Measured on the fork
   with one field flipped and restored: the identical `SwapExactIn` executes while
   `slot <= market.validUntil` and is rejected with "Oracle data is invalid" once the stored expiry is
   behind the clock — on a funded live market (`9PwXMVkFzW…`, `BBS3-diff-4a/4b/4c`) and on a 29.2 M-slot
   expired market (`CzuQmqj4dS…`, whose payload we first decoded as a well-formed 9×9-level book, so the
   rejection is *not* a deserialization artifact: clearing only `validUntil` moves the failure to the
   quote math). Sweeping every funded market in both directions at three sizes against a same-slot
   external reference returned nothing exploitable: of the 65 authoritative-run probes, 15/43 valued
   executions were net-positive for a fresh key, max
   **$11.06**, all round trips negative. Note the *configuration* truth though: `maxA/maxB` inventory
   caps are 0 (disabled) on 31 of 32 markets, `minSpreadGuardPerM` is 0 on 18 of 32, and the published
   `math::guards` error texts are absent from the deployed ELF — the stored guard fields are advisory, and
   LP protection comes from the window plus the reserve bound, not from the spread/imbalance guards.
   Still open: *choosing* when `arbPenaltyPerM`/`cuPenaltyMultiplier`/`jitodFrontPenaltyPerM` apply needs a
   market `updater` key (we did not impersonate one).
6. **Cross-program key reuse:** `BWyVTPPR…` is simultaneously the Wavebreak `AuthorityConfig` slot-0
   key (privileges 0 and 2–8, i.e. able to grant itself anything), the authority/updater of 12
   Busybox markets, and the creator of all 7 Manual-method curves; `AuthorityConfig` holds only 2 of
   64 slots and the `PermissionConfig` only 1 of 3 signer slots. A single-key compromise spans both
   programs' custody and their fee/permission roots.

## 5. Reproduce

```
python3 orca-audit/tools/ledger.py            # rebuild TESTS_MACHINE_READABLE.json from evidence/
python3 orca-audit/tests/wb_battery.py        # Wavebreak permission + trade battery (fork must be up)
python3 orca-audit/tests/wb_sell.py           # Wavebreak sell path
python3 orca-audit/tests/final_wb.py          # sell/refund/graduation conservation
python3 orca-audit/tests/final_wb2.py         # fee-custody drain + graduateWhirlpool attempt
python3 orca-audit/tests/wb_refund.py         # refund/revoke against the 31 live consumed PDAs
python3 orca-audit/tests/wb_perm_live.py       # replay of a real live permission message
python3 orca-audit/tests/wb_lp.py             # LP harvest/transfer/takeover + PDA seed vectors
python3 orca-audit/tests/bb_tests2.py         # busybox swap guards
python3 orca-audit/tests/bb_lifecycle.py      # busybox marketInitialize attempt (gated)
python3 orca-audit/tests/bb_roundtrip2.py      # busybox swap round trip
python3 orca-audit/tests/bb_final.py           # busybox custody + authority sweep
python3 orca-audit/tests/bb_stale_sweep.py     # WS6: funded-market sweep, expired probes, composed round trip
python3 orca-audit/tests/bb_expiry_diff.py     # WS6: single-field validUntil differential (control)
python3 orca-audit/tools/bb_net_table.py       # WS6: net-USD table from the sweep evidence (offline)
python3 orca-audit/tools/build_ws6_ledger.py   # rebuild the WS6 ledger entries + recomputed counts
python3 orca-audit/tools/pda_model.py          # Whirlpool/Wavebreak PDA + ATA solver, self-tested
bash    orca-audit/fork_up.sh                  # Surfpool 1.5.0 mainnet fork, records its start slot
```
