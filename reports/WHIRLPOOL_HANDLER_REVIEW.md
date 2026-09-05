# Whirlpool Handler-Level Review (`whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`)

**Status: INCOMPLETE — initial handler inventory produced; complete security review pending.**

**Program identity (verified from ProgramData, not local build):**

| field | value | source |
|---|---|---|
| Program | `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` | `recon/program_identities.json` |
| ProgramData | `CtXfPzz36dH5Ws4UYKZvrQ1Xqzn42ecDW6y8NKuiN8nD` | `recon/program_identities.json` |
| ProgramData size / lamports | 10,485,760 B / 72,981,780,480 lamports | `elf/whirlpool.meta.json` |
| ELF bytes / sha256 | 10,485,715 B / `610b1e394973bd1b86de8afc983524bd21dea177e87bfae75ec289d4c350f9ae` | `elf/whirlpool.meta.json` |
| Upgrade slot / lock | 440,170,207 / locked (`byte@12 = 1`) | `recon/s4_program_upgrade_control.json` |
| Upgrade authority | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` (same shared root) | `recon/s4_program_upgrade_control.json` |
| Deployed version (embedded) | Not present in rodata (no SECURITY.TXT block) | `BUSYBOX_DEEP_REVIEW.md` §0 |

**Important clarification:** The ProgramData lamports (72,981,780,480) are **rent for the ELF** — not user funds. The actual custody is the program-owned account set (indexer pass: 1,106,108 accounts / 156,285 pools), which the capped public RPC (`getProgramAccounts` refused outright — HTTP 403 on both endpoints) cannot enumerate (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3, `FINAL_DISPOSITION.md` §3.4).

---

## 1. Handler inventory (initial — derived from deployed ELF rodata + client reference)

The deployed ELF does not contain a complete rodata string table comparable to Wavebreak or Busybox. The initial handler inventory below is reconstructed from:

- The deployed binary (`elf/whirlpool.bin`, 10,485,715 B, sha256 verified against ProgramData).
- The version-matched client reference (`whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` — no embedded version string, no SECURITY.TXT block).
- Existing recon evidence (`recon/program_identities.json`, `ORCA_COMPANION_TRIAGE.md` §1, `WAVE_BREAK_DEEP_REVIEW.md` §1).
- The fact that Whirlpool is the CPI counterparty of Wavebreak's `GraduateWhirlpool` (CPI target: `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`; the Wavebreak binary calls `sol_invoke_signed_c` at `0x1af40` and references `whirlpool_init_authority`, `whirlpool_base_vault`, `whirlpool_quote_vault`, `InitializePoolWithAdaptiveFee`, `OpenPositionWithTokenExtensions`, `LockPosition`).

### 1.1 Confirmed handlers (from binary evidence + CPI references in Wavebreak)

Based on the Wavebreak binary's rodata references and the standard Whirlpool interface:

| handler (inferred from CPI references / standard interface) | balance-moving? | CPI target? | authorization / constraint notes |
|---|---|---|---|
| `InitializePoolWithAdaptiveFee` | Yes (creates pool PDA, vaults, fee accounts) | Internal program call (not CPI) | Requires `whirlpool_init_authority` (authority check not verified at handler level — needs complete review) |
| `InitializeDynamicTickArray` | Yes (creates tick array PDA) | Internal | Requires pool PDA and correct tick spacing / fee tier |
| `OpenPositionWithTokenExtensions` | Yes (mints position NFT, creates position PDA) | Internal | Requires pool PDA, mintA, mintB, valid tick range, user signature |
| `LockPosition` | Yes (mutates position: locks it, prevents withdrawal) | Internal | Requires position NFT ownership; locks the position (irreversible without unlock — unlock not present in standard interface) |
| `Swap` / `SwapExactIn` / `SwapExactOut` (Whirlpool swap_v2, CPI'd by Wavebreak graduation and by Busybox route) | Yes (moves tokens between user ATA and pool vaults; updates reserves) | Internal; CPI'd by Wavebreak (`GraduateWhirlpool`) and Busybox (`RouteV2` / `SwapV2`) | Requires pool PDA, user token accounts, valid tick range, non-zero amount; fee applied per tick |
| `UpdateFeesAndRewards` / `CollectFees` / `CollectRewards` | Yes (moves fee/reward tokens from pool vaults to fee/reward accounts) | Internal; may be CPI'd | Requires updater/authority binding; recipient accounts bound to pool configuration |
| `ClosePosition` / `WithdrawLiquidity` | Yes (burns position NFT, returns tokens to user) | Internal | Requires position NFT ownership; calculates amount based on current tick |
| `UpdatePoolConfig` / `SetFeeTier` / `UpdateOracle` | Potentially balance-moving (updates fee parameters, which affect future fees) | Internal | Requires authority binding; not fully mapped |

### 1.2 Unknown / unverified handlers (require complete review)

- Whether any handler exists that allows redirecting fee/reward recipients to an arbitrary address (not bound to pool config).
- Whether any CPI target (`SwapV2`, `RouteV2`, `Route`, `RouteWithTokenLedger`, `TransferChecked`, `TransferCheckedWithFee`, `SetTokenLedger`) can be called with attacker-controlled accounts that bypass authorization checks.
- Whether the `LockPosition` instruction (once called via Wavebreak graduation CPI) creates an irreversible lock that prevents later withdrawal — and whether any attacker-controlled position can be substituted into the graduation CPI.
- Whether any arithmetic overflow or reserve-manipulation path exists in the swap/fee/reward math (the deployed binary is stripped; arithmetic code was not decompiled).

---

## 2. CPI account binding matters for Wavebreak graduation (`GraduateWhirlpool`)

Wavebreak's `GraduateWhirlpool` (instruction discriminator 32, `0x35240` / `0x36aa8` in deployed binary) calls `sol_invoke_signed_c` (`0x49e60`) with a CPI target `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc`. The Wavebreak binary includes rodata strings:

- `Whirlpool position must be locked`
- `whirlpool fee tier index is not in the allowed range`
- `InitializePoolWithAdaptiveFee`
- `InitializeDynamicTickArray`
- `OpenPositionWithTokenExtensions`
- `LockPosition`
- `whirlpool_init_authority`
- `whirlpool_base_vault`
- `whirlpool_quote_vault`

This means the graduation CPI creates a Whirlpool pool, opens a locked position, and binds the base/quote vaults and token badges to the pool. The exact account-substitution risks are:

| substitution risk | current evidence | status |
|---|---|---|
| Fake Whirlpool pool PDA substituted into graduation CPI | Not tested (fixture-blocked for graduation) | **INCOMPLETE** — needs complete graduation fixture replay |
| Fake `whirlpool_init_authority` substituted | Not tested | **INCOMPLETE** |
| Fake base/quote vault substituted | Not tested | **INCOMPLETE** |
| Fake token badges substituted | Not tested | **INCOMPLETE** |
| Attacker-controlled position substituted (position must be locked) | Not tested | **INCOMPLETE** |
| Recipient substitution (fee/reward accounts redirected) | Not tested | **INCOMPLETE** |

The Wavebreak `GraduateWhirlpool` handler is not reviewed at handler level either (`WAVE_BREAK_DEEP_REVIEW.md` §5 explicitly notes the asymmetry: `graduateWhirlpool`'s hosts call the graduation-conditions check `0x137f0`, while the manual core `0x2e910` does not). The complete end-to-end test (valid graduation trigger + pool + position + escrow binding + base/quote mint binding + vault/substitution + token-program substitution + repeated graduation + partial closure) remains fixture-blocked (`FINAL_DISPOSITION.md` §2.1, `OPEN_ITEMS_WS7.json` item 2).

---

## 3. Custody and authorization summary (verified facts only)

- **ProgramData is rent, not user funds**: 72,981,780,480 lamports covers the 10,485,760-byte ProgramData for a 10,485,715-byte ELF. Real custody is the program-owned account set (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3).
- **Upgrade control**: Shared root `GwH3Hiv5…` (same as Wavebreak and Busybox). The root is an **off-curve PDA** (`is_on_curve == False`). It is not a signable EOA; control sits with whichever program derives it. The deriving program was not identified (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §6.3).
- **Not renounced**: ProgramData carries `Some(authority)` with byte `0x01` (`recon/s4_program_upgrade_control.json`).
- **Whirlpool is the CPI counterparty of Wavebreak's graduation**: The graduation CPI uses `whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc` as the target; it creates a pool, opens a locked position, and binds vaults. Without a complete Whirlpool handler review, the authorization constraints on these CPI targets (what account checks the Whirlpool program performs on the pool PDA, vault PDAs, position PDA, token badges, and fee accounts) are unverified.

---

## 4. What is verified; what is not

| verified (from existing evidence) | not verified (requires complete review) |
|---|---|
| Program identity (ELF hash matched to ProgramData) | Every handler's exact account constraints (PDA seeds, owner checks, writable flags) |
| ProgramData upgrade authority (same shared root) | Every CPI target's authorization checks when called from Wavebreak graduation CPI |
| Program is upgradable, not renounced | Whether any CPI target allows redirecting fee/reward recipients |
| Program-owned custody is the account set (not ProgramData lamports) | Whether the swap math contains arithmetic overflow or reserve-manipulation paths |
| Whirlpool is the CPI target of Wavebreak graduation | Whether the locked position created by graduation prevents attacker-controlled withdrawal or redirection |
| Wavebreak's graduation CPI includes `LockPosition`, pool initialization, and vault binding | Whether any attacker-controlled account can be substituted into the CPI account list without triggering account checks |

---

## 5. Evidence references

- `elf/whirlpool.bin` (10,485,715 B, sha256 verified)
- `elf/whirlpool.meta.json` (ProgramData identity, upgrade slot, upgrade authority, ELF hash)
- `recon/program_identities.json` (program identity table)
- `recon/s4_program_upgrade_control.json` (ProgramData header layout verification for all 4 family programs)
- `recon/s4_auth_walk_GwH3Hiv5.json` (authority event history — 230 signatures served; 816-event count open)
- `ORCA_COMPANION_TRIAGE.md` §1 (Whirlpool as balance-holding / balance-controlling companion)
- `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3 (custody measurement; indexer figure unverified)
- `WAVE_BREAK_DEEP_REVIEW.md` §1 (Whirlpool instructions referenced by Wavebreak binary; `GraduateWhirlpool` CPI)
- `FINAL_DISPOSITION.md` §2.1, §3.4 (family status; Whirlpool incomplete)
- `recon/s4_squads_pda_search.json` (Squads multisig scan — none match root)

---

*This file is an initial inventory, not a complete security review. The audit remains INCOMPLETE until a complete handler-level review of Whirlpool (and Legacy AMM) is performed, all CPI targets are mapped, authorization paths are tested on live fixtures, and the family-level control plane (shared root PDA, deriving program, governing multisig) is fully resolved.*
