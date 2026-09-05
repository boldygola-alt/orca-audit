
# Busybox (Riptide AMM market module) â€” fork-only defensive review (rev. 1)

**Program**: `riptK81hDxhe5pW5jSzSM9iRA8azgEgLJ4dXkPtBS7j` (reported as "Busybox", meta name "Riptide AMM Program" v2.1.1, `SECURITY.TXT` @ ELF 0x39ab4)
**ProgramData**: `4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu` (write-slot 440,010,891), upgrade authority `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` âœ… matches mandate family authority
**Build identity**: deployed ELF (extracted from PD after 45-byte header) = 258,992 B, SHA-256 `32a8a8f75662cfdc8d29abe4bf6826c9c027a4b9222d544f46285762c661ab86` â€” **byte-identical** to locally-disassembled `recon/riptK81h-elf-clean.bin` (the earlier "45 B mismatch" was the PD header, not a different build).
**Fork**: `http://127.0.0.1:8899` (Surfpool 1.5.0 / surfnet; genesis `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`, slots 444,032,xxxâ†’444,164,xxx). Execution via `sendTransaction` (Surfpool 1.5 renamed `sendRawTransaction`; simulations do **not** persist).
**Attacker**: `DP43P9KohxW4uHXGL43hpYvsdujRFf9aHqQBZ6ENwur2` (fresh local keypair; ~49,999.89 SOL before tests; no protocol assets).
Full machine-readable evidence: `reports/BUSYBOX_EVIDENCE.json`; real-form table `recon/bus_forms_real.json`; market inventory `recon/bus_market_inventory.json`.

## 1. Wire-format correction (supersedes all earlier "discriminator" analysis)

All earlier `c85776e8â€¦`-style "discriminators" were an **artifact of decoding base58 instruction data as base64**.
Deploying base58 decoding, every observed instruction decodes to `tag byte + payload` and the fork tag-printer
(`0x2a448`) matches live behavior exactly:

| Tag | Handler | Wire | Accounts (live) |
|---|---|---|---|
| 0x00 | ProgramVersion | 1B | [] |
| 0x01 | OracleUpdate | 1 + u64 slot + u64 ts + 512B oracle data (529B) | [market R, oracle EOA **signer**] |
| 0x02/0x03 | SwapExactIn/Out | â€” | **not implemented** (InvalidAccountData @9 CU) |
| 0x04â€“0x07 | ReservedSwapX/Y/Z/A | â€” | **not implemented** |
| 0x08 | MarketInitialize | 5B (tag + u32 market id) | [payer SW, market W, mintA, mintB, vaultA W, vaultB W, system, AToken, tokenA(-22) W, tokenB(-20) W] |
| 0x09 | MarketUpdate | 34B (tag+flags 0x01+32B oracle pk) or 6B (tag+flags 0x04+u32) | [authority SW, market R, system W] |
| 0x0a | MarketDeposit | 17B (tag + u64 amtA + u64 amtB) | [authority SW, market R, mintA W, mintB W, feeA R, feeB R, vaultA R, vaultB R, token W, token W, memo W] |
| 0x0b | MarketWithdraw | 17B (tag + u64 amtA + u64 amtB) | [authority SW, market R, mintA W, mintB W, recvA R, recvB R, vaultA R, vaultB R, tokenA W, tokenB W, memo W] |
| 0x0c | MarketClose | 0x0c (+12 accts) | [authority SW, market W, â€¦] |
| 0x0dâ€“0x0f | ReservedMarketX/Y/Z | â€” | **not implemented** |

`sha256(name)[:4]`-style name-prefix mapping is **refuted** (no live tag equals any prefix); the enum-name
table at 0x396e1 is a display table only.

## 2. Market state layout (from live accounts)

`0x00 version/flags Â· 0x04 u32 market id Â· 0x08 authority (32B) Â· 0x28 oracle (32B) Â· 0x48 mintA Â·
0x68 mintB Â· 0x88 u64 counter Â· 0x90 u64 lastOracleSlot Â· 0x98..0x298 512B oracle data Â·
0x298 u64 price (Q32-ish; fresh = 300Ã—2Â³Â²) Â· 0x2a0 = 100 Â· 0x2c0/0x2c8 = u64::MAX Â·
0x2e0/0x2e8 reserves A/B`.

Vaults are **ATAs of the market** (`ata(market,mint)`), owned by the market account; withdraw CPIs are
authority-signed by the program => markets are program PDAs (common-string seed brute force did not match;
seeds are non-trivial). Verified: `FSU8/7Uqwc` (CzuQ), `2iZ3v/fNKZa` (Pr8k) all owned by their market and
matched by reserves.

## 3. Inventory (mainnet read-only; slotâ‰ˆ444.17M)

32 live markets (1024 B) totaling 256,747,447 lamports; **11 funded**. Top reserves:
`FefUJfaS2Vpk` 237.4B JitoSOL-ish/1.5M WSOL Â· `9PwXMVkFzWk5` 74.2B/51.3B Â· `4AFfguVTj7sq` 48.3B/5.4B Â·
`6Vzx4ASRjUPW` 24.9B/25.2B (USDC/USDC) Â· `GxGxQBvMQ7vU` 23.3B/49.2B Â· `CNp3etjEmWP4` 17.9B/28.2B Â·
`HxNaPy1oYA8x` 17.5B/46.3B Â· `CzuQmqj4dSda` 10.9B jitoSOL `J1toso1uâ€¦`/500M WSOL.
Authorities: `CGYAxnDF1b` (majority), `2C7K3BN6`, `CYkPyQ2c`, `BWyVTPPR` (4 draft markets).
Oracles: `BP8TxUro` (shared EOA, 9.15 SOL, data len 0), `6CXqCWby` (0.56 SOL), per-market or `CGYAxnDF`.

## 4. Authorization results (fork, attacker-controlled)

| ID | Handler | Verdict | Stage / mechanism |
|---|---|---|---|
| T1 | MarketWithdraw (CzuQ, 1+1) | **DENIED** | `Account DP43P9Kâ€¦ is not the authority` â€” pre-CPI, 2729 CU; market hash & reserves unchanged |
| T1b | MarketWithdraw (exact live flags) | **DENIED** | same explicit authority log |
| T2 | MarketDeposit | **DENIED** | same (2736 CU) |
| T3b | MarketUpdate (mode 0x01) | **DENIED** | same (2520 CU); market unchanged (0x298/0x2a0/0x2e0/0x2e8 identical) |
| T4pp | OracleUpdate (529B, live shape) | **DENIED** | signer must equal market oracle (15 CU) |
| T5d | MarketClose (12 accts) | **DENIED** | same (2739 CU) |
| T8a | MarketInitialize on **existing** market (re-init / takeover) | **DENIED** | same (2541 CU); market hash unchanged |
| T11 | Withdraw recipient-substitution (authority-flagged sim) | **DENIED** | `Token account â€¦ has wrong owner` (10,764 CU) â€” recipient/vault owner binding |
| T9 | Tags 0x02â€“0x07, 0x0dâ€“0x0f, 0x10 | **DENIED** | InvalidAccountData @9 CU (reserved/unimplemented) |

Every balance-moving path attacks a fixed set of gates: (a) signer == market authority (or market oracle
for 0x01), (b) token-account owner binding per role, (c) token program owns the accounts. No path reached a
token CPI with an attacker-controlled authority; no state mutated (market hashes pre/post identical in every
case); attacker SOL unchanged (denials pre-CPI).

## 5. Coverage gaps / INCOMPLETE items

1. **Legitimate-flow accounting** (depositâ†’withdrawâ†’close conservation, fee paths, oracle-data math) â€”
   not executable: requires signing as `CGYAxnDF1b`/`2C7K3BN6`/`CYkPyQ2c` (not held; real-keys rule). Only
   non-state-changing probes were run; code review of the CPI builders (`0x9a00â€“0x9e80` deposit/withdraw,
   `0x81f0â€“0x8760` close) is the supporting evidence.
2. **Market PDA seeds** unresolved (market must be a program PDA for withdraw authority; seed discovery
   failed on common strings) â€” does not affect the authorization verdict, note only.
3. **Swap/router/TokenLedger classes** from the original mandate are **not present** in this deployment:
   the ELF contains no Whirlpool/legacy-AMM/token-ledger CPI or IDs (only system, spl-token, token-2022,
   rent, clock, AToken, Memo, IxSysvar). SwapExactIn/Out and ledger-like handlers are Reserved in code.

## 6. Status

- Busybox (this program): authorization matrix = **all privileged mutations denied** for a non-authority
  attacker; reserved handlers unimplemented; remaining gap = legitimate-flow accounting (fixture-blocked,
  INCOMPLETE) which prevents a full CLEAR.
- **Program family**: deployed as expected under `GwH3Hiv5â€¦`; per-market operator authorities are distinct
  keys (2C7K3BN6/CYkPyQ2c/BWyVTPPR) â€” flagged for the deployer-family confirmation.
- Overall Orca-family status remains **INCOMPLETE** (Wavebreak not yet disassembled/reviewed).

