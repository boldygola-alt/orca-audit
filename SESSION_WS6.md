# Session note — WS6 closed, WS1–WS5/WS7 state and how to resume

Written 2026-09-04 after the WS6 (Busybox stale-oracle / penalty) pass. This file is operator
continuity, not a deliverable; the deliverables are in `reports/`.

## What just happened (WS6)

* Harness: `tests/bb_stale_sweep.py` (stages A expired-gate, B funded both-direction size sweep at
  1/5/25 %, C composed A→B→A round trip in one tx, D natural expiry crossing), `tools/bb_net_table.py`
  (offline net-USD table), `tests/bb_expiry_diff.py` (single-field `validUntil` differential).
* Evidence: `evidence/BBS2_stale_sweep.json` (authoritative run, 66 records),
  `evidence/BBS2_stale_sweep_parsed.json` (superseded run), `evidence/BBS2_net_deltas.json`,
  `evidence/BBS3_expiry_diff.json`, `recon/s4_bb_oracle_decode.json`, `recon/s4_bb_prices.json`,
  `evidence/funding_s4_sol.json` (fee funding only — never exploit evidence).
* Ledger: `tools/build_ws6_ledger.py` then `tools/normalize_ledger.py` → 322 entries
  (177 prior + 145 WS6), `statusCounts`/`counts` recomputed from the entries.

## Findings that changed the record

1. `market.validUntil` **is** enforced by the deployed swap handler (rejected at `slot > validUntil`,
   accepted after restore — two markets, six probes). The previous claim ("not a hard slot gate",
   "400+/6.5k-slot grace period") was wrong: it compared *slots since the last oracle update*.
2. The interim "permissionless profit" on the LST markets was a reference-price artifact. With both
   legs priced at one same-scan reference: 15/43 valued executions net-positive, max **+$11.06**
   (0.39 % of a $2,892 leg), sum of positives **$19.01**, every round trip negative ⇒ no profit path.
3. The stored guard fields (`minSpreadGuardPerM`, `maxA/maxBInventoryPerM`,
   `maxInventoryImbalanceGuardPerCent`) have **no** corresponding error text in the deployed ELF and
   produced no rejections; `cuPenaltyMultiplier` is 0 on all 32 markets. Enforcement = window +
   reserves + per-fill slippage/partial-fill.
4. All four family programs are **still upgradable** (ProgramData `Option` byte `0x01`); the shared
   root `GwH3Hiv5…` is **off-curve** (a PDA), the legacy-AMM root `23zF9Azp…` is a plain key. The
   earlier "WB/BB locked at slot X" note was a misread of the last-upgrade slot.

## Environment gotchas (this sandbox)

* Between turns the sandbox recycles: installed pip packages and running processes go away, workspace
  files persist. After a resume: `pip install --quiet solders base58`, and check the fork is alive.
* Always `python3 -u` and redirect to a file; piping to `tail` hides buffered output.
* Fork funder: `--airdrop`/`-k` does **not** fund the actor; use `surfnet_setAccount` on the actor's own
  account (see `evidence/funding_s4_sol.json`). `getProgramAccounts` on `BPFLoaderUpgradeable` → HTTP
  403 on both public endpoints. `getSignaturesForAddress` caps at one 230-signature page.
* Jupiter `price/v3` needs a `user-agent` header; batches of 2 with a 1.6 s sleep work, batches of 4 → 403.

## Still open (and exactly how to close each)

1. **Natural clock-crossing corroboration** (`tests/bb_expiry_natural.py`, ready to run). Restart the
   fork (`bash orca-audit/fork_up.sh`, then `surfnet_setAccount` the actor), immediately record which
   funded market's `validUntil` the fork clock will overtake soonest, run the script. ~15 min of fork
   clock. Corroborates finding 1; does not change it.
2. **WS4 verbatim replay** of the cached consume→buy pair at its pre-state (duplicate-permission test):
   restore pre token balances from the tx meta, replay the raw message unchanged, then mutate
   subject/consumer/amount/mint/curve/quote-vault/destination/expiry/signature/consumed-PDA/token
   programs one at a time. Cached raw tx JSON lives in `recon/txs/`; `tools/txclass.py` decodes.
3. **WS5 funded lifecycle replay** — deposit/withdraw/close from a market PDA's own signature history
   (`recon/s4_bb_sigs.json`), verbatim at pre-state. If no real deposit/withdraw exists on a market we
   can reach, it stays INCOMPLETE (it is today); no authority impersonation.
4. **WS1/WS2/WS3** — fixture-blocked as recorded in `reports/OPEN_ITEMS.json` (1, 2, 3). Do not "solve"
   them by substituting absent accounts or cheatcode balances.
5. **WS7 remaining**: Whirlpool + legacy-AMM handler-level walk against `elf/whirlpool.bin`
   (sha `610b1e39…`, 10,485,715 B) and `elf/amm.bin` (sha `930a47e2…`, 691,104 B) —
   `tools/sbf.py`/`tools/analyze_elf.py`; AMM per-account custody via an indexer/uncapped source;
   authority events before slot 306,473,452; the multisig behind `GwH3Hiv5…`.
   Family disposition stays INCOMPLETE until 5 (and 2/3 if they end fixture-blocked) is resolved.
