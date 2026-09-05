# Legacy AMM Handler and Custody Review (`9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP`)

**Status: INCOMPLETE — initial handler inventory produced; complete security review and custody enumeration pending.**

**Program identity (verified from ProgramData, not local build):**

| field | value | source |
|---|---|---|
| Program | `9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP` | `recon/program_identities.json` |
| ProgramData | `DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8` | `recon/program_identities.json` |
| ProgramData size / lamports | 691,149 B / 4,811,287,920 lamports | `elf/amm.meta.json` |
| ELF bytes / sha256 | 691,104 B / `930a47e23fe7f8185557c1b5acabf658f97ca0f4c6cdd1f0d0510a897a9322e6` | `elf/amm.meta.json` |
| Upgrade slot / lock | 161,177,892 / locked (`byte@12 = 1`) | `recon/s4_program_upgrade_control.json` |
| Upgrade authority | **`23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG`** (separate from shared root `GwH3Hiv5…`) | `recon/s4_program_upgrade_control.json` |
| Deployed version (embedded) | Not present in rodata (no SECURITY.TXT block) | `BUSYBOX_DEEP_REVIEW.md` §0, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §2 |
| Activity (last 24 h, from indexer / live RPC) | 2,377 transactions; zero owner/authority activity in last 50 transactions (dormant control plane, still-used trade path) | `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3 |

**Critical clarification:** The ProgramData lamports (4,811,287,920) are **rent for the ELF** — not user funds. Real custody is the program-owned account set (earlier indexer pass: ~1,246,422 owned accounts / 41,124,583,108,449 lamports). The public RPC (`getProgramAccounts` on `BPFLoaderUpgradeable` filtered by upgrade-authority bytes) is **refused outright** — HTTP 403 on both `api.mainnet-beta` and the publicnode fallback. This audit retrieved only 167 accounts / 1,296,458,888 lamports (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.2, §6.1).

---

## 1. Handler inventory (initial — derived from deployed ELF + standard AMM interface)

The deployed binary (`elf/amm.bin`, 691,104 B, sha256 verified) does not contain an embedded SECURITY.TXT or rodata handler name table comparable to Wavebreak or Busybox. The initial inventory below is reconstructed from:

- The deployed binary (stripped `.dynsym` only; no `.rodata` string table for handler names).
- The standard legacy AMM interface (`Swap2`, `Route`, etc.) referenced by `ORCA_COMPANION_TRIAGE.md` §2 (`riptK81hDx…tBS7j` routes into it via `Swap2` CPI).
- The account relationship (`recon/amm_custody.json` — per-account custody not enumerated; `recon/authority_events_summary.json` — 71 classified signatures for `23zF9Azp…`, including 1 upgrade/setAuthority event at slot 323,488,852).
- The fact that the legacy AMM is dormant (last upgrade 161,177,892; 2,377 trades in 24 h; zero authority activity in last 50 tx) but **not renounced**.

### 1.1 Confirmed / inferred balance-moving handlers

| handler (standard interface / CPI reference) | balance-moving? | CPI target for router? | authorization / constraint notes |
|---|---|---|---|
| `Swap2` (standard AMM swap — CPI target of Busybox router `Route` / `RouteV2`) | Yes (moves tokens between user ATA and pool vault; updates reserves; applies fees) | Yes (`riptK81hDx…tBS7j` calls it via CPI) | Requires pool PDA, user ATAs, correct mint pair; fee applied per trade; authorization bound to the pool PDA (not to an external updater) |
| `Route` / `RouteV2` / `RouteWithTokenLedger` (smart router — CPI'd by Busybox) | Potentially (routes through multiple pools; may move tokens through intermediate ATAs) | Internal to Busybox; CPI's Whirlpool and Legacy AMM | Account-substitution risk: a malicious router account list could redirect output to attacker-controlled ATAs. The Busybox router's authorization (correct 12-account shape) was tested; the Legacy AMM CPI target's authorization (when called from router) was not separately tested. |
| `Deposit` / `Withdraw` / `AddLiquidity` / `RemoveLiquidity` | Yes (creates/destroys LP tokens; updates reserves) | Not directly referenced by Wavebreak or Busybox CPI names | Requires user token accounts, pool PDA; fee/reward accounting updated |
| `InitializePool` / `InitializeMarket` | Yes (creates pool PDA, vaults, fee/reward accounts) | Not directly referenced | Requires authority (hardcoded or configured — exact authority binding not verified at handler level) |
| `SwapExactIn` / `SwapExactOut` (exact-input / exact-output variants) | Yes (same as `Swap2` but with exact amount constraints) | Not directly referenced in Wavebreak/Busybox rodata | Arithmetic bounds enforced (`6099` / `custom 1` for arithmetic overflow / reserve cap in Busybox; similar arithmetic expected here) |
| `UpdatePool` / `UpdateMarket` / `SetFee` | Potentially (updates fee parameters, reserve ratios) | Not directly referenced | Requires authority binding (not fully mapped) |

### 1.2 Unknown / unverified (require complete review)

- Whether any handler allows redirecting pool fee/reward recipients to an arbitrary address (not bound to pool config).
- Whether any CPI target (`Swap2`, `Route`) allows substituting a fake pool PDA or fake user ATA without triggering account-owner / PDA-seed checks.
- Whether the arithmetic path (reserve update, fee calculation, slippage enforcement) contains any arithmetic overflow, reserve-manipulation, or fee-redirection vulnerability.
- Whether `Deposit` / `Withdraw` can be called with an attacker-controlled pool PDA that redirects vault custody.
- Whether any authority-only function (`InitializePool`, `UpdatePool`, `SetAuthority`) can be triggered by an arbitrary caller (the `recon/authority_events_summary.json` shows authority events exist; the exact authorization binding per handler is unverified).

---

## 2. Custody relationship (verified facts only)

- **ProgramData lamports** (4,811,287,920) = rent for 691,149-byte ProgramData holding a 691,104-byte ELF. Not user funds (`FINAL_DISPOSITION.md` §3.3, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §7).
- **Real custody** = program-owned account set (`recon/amm_custody.json` shows partial measurement; full enumeration blocked by public RPC cap).
- **Earlier indexer pass** measured ~1,246,422 owned accounts / 41,124,583,108,449 lamports (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.2). This figure is **unverified** from public RPC (only 167 accounts / 1,296,458,888 lamports retrieved); it is not reproduced or refuted here.
- **Upgrade authority** (`23zF9Azp…`) is a **plain on-curve key** (not a PDA) holding 23.891577114 SOL (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §5). It has signed 1 upgrade/setAuthority event (self-rotation at slot 323,488,852) and 63 plain transfers in the 71-classified-signature window (`recon/authority_events_summary.json`). It is a single-secret exposure with no on-chain mitigation.
- **Not renounced** (`recon/s4_program_upgrade_control.json`: `version = 3`, `byte@12 = 0x01` present, `upgradeAuthority` non-default).
- **Dormant control plane** (last upgrade 161,177,892; 2,377 trades in 24 h; zero authority activity in last 50 transactions) but **still active trade path** (`ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.3).

---

## 3. Authority event classification (from available public RPC — bounded precisely)

`getSignaturesForAddress('23zF9Azp…')` returned 400 requested signatures; 71 were classified (`recon/authority_events_summary.json`):

| class | count | note |
|---|---|---|
| Program upgrade / setAuthority (`BPFLoaderUpgradeable`, incl. inner) | 1 | Self-rotation at slot 323,488,852 |
| Plain transfer / fee funding | 63 | No Squads usage |
| Bubblegum cNFT | 4 | Unrelated to family control |
| Other | 3 | Unclassified |

The full history before the earliest served slot is unavailable (public RPC does not serve older pages; no archival endpoint configured). The indexer pass's full event count (816 for `GwH3Hiv5…`; unmeasured for `23zF9Azp…`) stays open.

---

## 4. Cross-program relationships

- **Legacy AMM is the CPI target of Busybox's router** (`riptK81hDx…tBS7j`): the Busybox rodata includes `Swap2` and `Route` references (`BUSYBOX_DEEP_REVIEW.md` §0; `ORCA_COMPANION_TRIAGE.md` §2). The router CPI's authorization (correct 12-account shape, token-program pinning, duplicate-account aliasing rejected) was tested (`BUSYBOX_DEEP_REVIEW.md` §3). The Legacy AMM's authorization (when called as a CPI target from the router) was **not separately tested** — this is part of the open review.
- **Legacy AMM is NOT under the shared root `GwH3Hiv5…`**: its upgrade authority is the separate plain key `23zF9Azp…`. This is a separate control root (`FINAL_DISPOSITION.md` §7; `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §1, §5).
- **Legacy AMM holds significant custody** (~1.25 M accounts, indexer figure unverified). Without complete custody enumeration (public RPC blocked), the exact balance exposure of the legacy AMM is unverified.

---

## 5. Handler-level review gaps (explicitly unverified — must not be read as clear)

- **Every balance-moving handler's exact account constraints** (PDA seeds, writable flags, owner assertions, mint compatibility) — unverified.
- **Every CPI target authorization path** (what checks the Legacy AMM performs on pool PDA, vault PDAs, user ATAs, fee accounts when called from Busybox router) — unverified.
- **Every arithmetic path** (reserve update math, fee calculation, slippage enforcement, arithmetic overflow protection) — unverified.
- **Every recipient-binding path** (fee/reward recipient accounts, whether they can be redirected by an authority function or by a malicious CPI account list) — unverified.
- **Every position/state mutation path** (whether `InitializePool`, `UpdatePool`, or any other handler allows substituting a fake pool PDA or redirecting vault ownership) — unverified.
- **Per-account custody enumeration** (the indexer figure of ~1.25 M accounts / 41.124 T lamports is unverified; public RPC capped at 167 accounts) — unverified.

---

## 6. Evidence references

- `elf/amm.bin` (691,104 B, sha256 verified against ProgramData)
- `elf/amm.meta.json` (ProgramData identity, size, upgrade slot, upgrade authority, ELF hash)
- `recon/amm_custody.json` (partial custody measurement — not full enumeration)
- `recon/authority_events_summary.json` (71 classified signatures for `23zF9Azp…`)
- `recon/program_identities.json` (identity table for all 4 family programs)
- `recon/s4_program_upgrade_control.json` (ProgramData header verification)
- `ORCA_COMPANION_TRIAGE.md` §2 (Legacy AMM as dormant but active trade path; router CPI)
- `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §3.2, §3.3, §5 (custody; upgrade control; authority events)
- `BUSYBOX_DEEP_REVIEW.md` §0 (Legacy AMM referenced as CPI target of Busybox router)
- `FINAL_DISPOSITION.md` §2.4, §7 (Legacy AMM status; control root; upgrade authority; family disposition)

---

*This file is an initial inventory, not a complete security review. The audit remains INCOMPLETE until a complete handler-level review of the Legacy AMM (and Whirlpool) is performed, every CPI authorization path is tested on live fixtures, and the family-level control plane (shared root PDA, separate plain-key root, governing multisig) is fully resolved.*
