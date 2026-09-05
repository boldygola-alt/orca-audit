# Orca deployer-family final inventory

Snapshot 2026-09-04, read-only mainnet RPC (public endpoints, no credentials). Fork-only testing is
reported separately (`WAVE_BREAK_DEEP_REVIEW.md`, `BUSYBOX_DEEP_REVIEW.md`). This file supersedes
the "partial" inventory in `SQD_ORCA_DEPLOYER_FAMILY_INVENTORY.md` and corrects one of its claims.

## 1. Program identities (verified from ProgramData, not from any local build)

`state=3` means `ProgramData`; the 45-byte header is `u32 state | u64 upgradeSlot | u8 lockFlag |
32B upgradeAuthority | ELF`. ELF sha256 was recomputed from `elf/*.bin` (bytes 45..):

| program | address | ProgramData | upgrade slot | lock | upgrade authority | ELF bytes | ELF sha256 |
|---|---|---|---|---|---|---|---|
| Whirlpool | `whirLbMiic…uctyCc` | `CtXfPzz36dH5Ws4UYKZvrQ1Xqzn42ecDW6y8NKuiN8nD` | 440,170,207 | 1 | `GwH3Hiv5…` | 10,485,715 | `610b1e394973bd1b86de8afc983524bd21dea177e87bfae75ec289d4c350f9ae` |
| Wavebreak | `waveQX2yP3…srXTF` | `nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs` | 365,746,180 | 1 | `GwH3Hiv5…` | 500,448 | `8cd60d772f1d8a97a6f879c545e2827914c1d285c0edca22148ac231f21e9742` |
| Busybox/Riptide | `riptK81hDx…tBS7j` | `4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu` | 440,010,891 | 1 | `GwH3Hiv5…` | 258,992 | `32a8a8f75662cfdc8d29abe4bf6826c9c027a4b9222d544f46285762c661ab86` |
| Legacy AMM | `9W959DqEETiGZocYWCQPaJ6sBmUzgfxXfqGeTEdp3aQP` | `DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8` | 161,177,892 | 1 | **`23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG`** | 691,104 | `930a47e23fe7f8185557c1b5acabf658f97ca0f4c6cdd1f0d0510a897a9322e6` |

**Correction to the earlier pass:** the shared authority `GwH3Hiv5…` covers **three** programs, not
four. The legacy AMM's upgrade authority is `23zF9Az…`, a *separate* key. The family therefore has
two control roots, and the AMM's authority has not been under `GwH3Hiv5…` since at least slot
161,177,892 (its last upgrade). ProgramData lamports: Whirlpool 72,981,780,480 · Wavebreak
3,484,322,160 · AMM 4,811,287,920 · Busybox 1,803,788,400.

## 2. Embedded provenance strings (from the deployed ELFs)

| program | SECURITY.TXT |
|---|---|
| Wavebreak | name "Orca Wavebreak Program", version **1.1.5**, author team@orca.so, repo `github.com/orca-so/wavebreak`, Immunefi policy, `audit "Offside.ai and Anza (Dec 2024 - Jan 2025)"` |
| Busybox | name **"Riptide AMM Program"**, version **2.1.1**, project `https://riptide.so`, contact `security@riptide.so`, audit Trail of Bits (July 2023) |
| Whirlpool / AMM | no SECURITY.TXT block in the deployed ELF |

Version-matched clients used for wire formats only, then verified against live state:
`@orca-so/wavebreak` npm 1.1.5 + `orca_wavebreak` crate 1.1.5; `riptide-amm` 2.1.1 (+
`riptide-amm-math` 2.1.1). Every PDA seed recomputed from the deployed program id reproduces the
clients' own unit-test vectors (`bonding_curve`, `mint_config`, `permission_config`, `lp_escrow`,
`consumed_permission`, and busybox `["market", u32le id]` on 12/12 live markets). The
`orca-so/wavebreak` GitHub repo returns 404 to the API, so **no** source was treated as ground truth.

## 3. Program-owned custody

### 3.1 Wavebreak (fully enumerated this pass — 1,572 accounts)

| item | value |
|---|---|
| bonding curves | 1,537 records (2,048 B, disc 2) + 1 MintConfig (2,048 B, disc 6) |
| program-owned lamports | 23,395,853,334 (23.396 SOL) |
| quote-vault custody | every one of the 1,537 curves has a live quote vault; Σ vault units **241,206,239,109** vs Σ `quoteAmount` accounting **283,450,712,406** (token units of each curve's own quote mint — 1,528 WSOL, 7 USDC, 2 other — so not a pure SOL figure) |
| per-curve divergence | 685 curves hold more in the vault than accounting, total **+6,784,577,154 units** (median 3,000,000; max 854,042,768); 1 curve holds less than accounting by 49,029,050,451 units — the single graduated curve, whose quote left the vault at graduation |
| nature of the excess | unclaimed protocol/creator fees — proven: an attacker-signer `BondingCurveCollectFees` on `DbRKfbUmxd…` moved 520,591,863 units to the privilege-1 fee authority and drove that curve's divergence to **exactly 0** (`recon/wb_fee_reconciliation.json`) |
| base custody | no curve holds base in a vault (pre-graduation supply is minted to buyers and burned on sell); 0 curves with base-vault > accounting |
| permission state | 1 `PermissionConfig` (consumer = the program itself, exactly one allowed signer `0359c54abfca…2b29`, slots 2–3 zero); 31 `consumed_permission` accounts (41,420,920 lamports, all `refundDestination = Pubkey::default()`, all past `safeToCloseSlot`) → rent unrecoverable by anyone |
| `AuthorityConfig` | 64 slots, 2 used: `BWyVTPPR…` privs {0,2,3,4,5,6,7,8}, `8AbiHetk…` priv {1}. `maxBuyAmount` default 1e16, `graduationTarget` 85 SOL, `graduationReward` 1e8, create/buy require permission (bitmap all-ones), sell does not |
| LP escrow | **0** positions; no `lp_escrow` PDA exists on mainnet |
| per-curve state | all 1,537 curves: `buyRequiresPermission = true`, `sellRequiresPermission = false`; 1530 have `graduation_time = 0`, 7 are past their window; 7 carry a Manual graduation method (all created by `BWyVTPPR…`) |

### 3.2 Busybox / Riptide (fully enumerated — 32 markets)

32 markets, 14 with inventory, 18 zero-reserve; market rent 112,253,880 lamports; total program-owned
256,747,447 lamports. **Σvault − Σreserves = 0** (atomic read, mainnet slot 444,233,360).
Authorities: `CGYAxnDF…` 18, `2C7K3BN63M…` 6, `BWyVTPPR…` 6, `CYkPyQ2cdA…` 1. Updaters:
`BP8TxUro…` 22 + 8 per-market keys. Oracle freshness: 11 fresh, 3 expired (up to 29.2 M slots), 4 with
frozen windows ~85–90 M slots ahead. Largest: `FefUJfaS2Vpk…` 237,375,794,984 units A / 4,167 B;
`9PwXMVkF…` 64,894,349,076 / 60,831,700,081.

### 3.3 Legacy AMM and Whirlpool

Whirlpool: 742,447 program-owned accounts measured through the indexer in the earlier pass; the free
RPC cannot enumerate them. Its custody is the usual vault/fee-tower set and is **not** re-derived in
this pass. Legacy AMM: earlier pass measured 1,246,422 program-owned accounts holding
41,124,583,108,449 lamports (41,124.58 SOL), with per-account balances **not** enumerated
(INCOMPLETE); this pass could only retrieve 167 accounts / 1,296,458,888 lamports before the public
endpoint capped `getProgramAccounts`. Activity: Whirlpool 25,591 txs/24 h; AMM 2,377 txs/24 h and
zero owner/authority activity in the last 50 txs (dormant control plane, still-used trade path).

## 4. Control-plane events for the two authority keys (read-only)

Method: `getSignaturesForAddress` + parallel `getTransaction`, classified by the programs each
transaction touches (`tools/authority_scan.py`, raw per-tx records in `recon/authority_events/`,
aggregate `recon/authority_events_classes.json`).

`GwH3Hiv5…` — `getSignaturesForAddress` yields **230** signatures and no more: a `limit: 1000`
request returns one page of 230 (newest 440,170,207, oldest 306,473,452) and the `before` cursor
returns nothing further on api.mainnet-beta or the publicnode fallback. The indexer-based pass
counted **816** events for this key; that figure can be neither reproduced nor refuted from the
public endpoints available here, so the history before slot 306,473,452 stays open. This pass
fetched and classified **all 230** that are served (`tools/authority_walk.py` →
`recon/s4_auth_walk_GwH3Hiv5.json`: 149 BPFLoader/Squads instruction events, 734 distinct
account-owners touched; the per-transaction `jsonParsed` account lists for BPFLoader instructions
came back empty, so no ProgramData inventory could be rebuilt from history either). 102 of them were
classified by class:

| class | count |
|---|---|
| program upgrade / setAuthority (BPFLoaderUpgradeable, incl. inner) | 10 |
| Squads multisig operations (`SQDS4ep6…`) | 11 |
| plain transfer / fee funding | 76 |
| Bubblegum cNFT | 2 |
| other | 3 |

The `setAuthority` targets seen in this window: `8xtBvp5VS4vyZYfGnykooVyWVsPNSA4A9z62s7RwCX46` (×2),
`BWyVTPPRW7A5kpHM3tNgPhRz6JekR9sL8iFx2o4X1w9C` (×2), `r21Gamwd9DtyjHeGywsneoQYR39C1VDwrw7tWxHAwh6`,
`94kZD71sbTKhqhcvY9D9Ra5BsLzKRZgznbBbQpBWmKrT` — i.e. authority rotation across the family is
ongoing and lands on `BWyVTPPR…`, which is simultaneously the Wavebreak `AuthorityConfig` slot-0
privileged key and the authority/updater on 12 Busybox markets.

`23zF9Az…` (AMM authority) — 71 of 400 requested signatures classified: 1 program
upgrade/setAuthority (self-rotation at slot 323,488,852), 63 plain transfers, 4 Bubblegum, 3 other.
No Squads usage on this key.

## 5. Key roles (existence and account type only; no keys are recorded anywhere in this audit)

| key | role |
|---|---|
| `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` | upgrade authority for Whirlpool + Wavebreak + Busybox. **Off-curve** (`is_on_curve() == False`) ⇒ a program-derived address, **not** an EOA: nothing can sign for it directly; control sits with whichever program derives it. Owns a space-0 account with 4,875,689,434 lamports. The deriving program could not be identified from public RPC (§6.3) |
| `23zF9Azpe9CN4iPeTsQndD1mQpcb5Gz1qFREL5gPTZvG` | legacy AMM upgrade authority; plain EOA, 23,891,577,114 lamports |
| `BWyVTPPRW7A5kpHM3tNgPhRz6JekR9sL8iFx2o4X1w9C` | Wavebreak `AuthorityConfig` slot 0 (privs 0,2–8); Busybox market authority/updater on 12 markets; creator of all 7 Manual-method curves; plain EOA |
| `8AbiHetkXXjkbUJe9XBLEaaGWvkJQbakJ746WQbi6Qor` | Wavebreak `AuthorityConfig` slot 1 (ReceiveProtocolFees) — the fee-claim destination |
| `CGYAxnDF1bYwmbzTtVx2pdo8xd3aviqE58WumVYRLYRH` | hardcoded in the Busybox ELF (`0x38a48`, referenced only by the market-initialize path `0xa388`) = market initializer authority |
| `BP8TxUroBDw97JWmc9bfg9bs8PoE6MA71SSihhBNUJR4` | Busybox `updater` (oracle pusher) on 22 markets |
| `FEDMRB62snymMLV75sdBCCeEfDM4EVdp3xBXrMSTA2FS` | creator of the one graduated curve (`Ec5jrDHt…`) |
| `SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf` | Squads program (29 of the root's 149 recent control-plane events involve it; a second Squads-generation id `DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL` appears 53×). The one candidate related account, `3GiPhEnWforYgzGtnaAJ2G7MQMs5SNAyYwVN84VaQaHV` (1,318 B, 10,064,160 lamports), does **not** decode with any layout available here; its five on-curve 32-byte slots (`2NfC7wE7…`, `8xqdLe2K…`, `BgV5ocPw…`, `F1FSHAbR…`, `HNeMErwp…`) are unrelated plain accounts, and no `["multisig", addr]` PDA of any of the 834 Squads accounts of that size equals the root. It is therefore **excluded as an unrelated third party**; the multisig behind the root stays **INCOMPLETE** |

## 6. Open items in this inventory

1. Legacy AMM per-account custody enumeration (needs an indexer/GaaS, not the capped public RPC).
2. Authority history for `GwH3Hiv5…` before slot 306,473,452: the public RPC caps
   `getSignaturesForAddress` at one 230-signature page, so the indexer pass's 816-event count is
   unverified (all 230 that *are* served were fetched and classified this pass).
3. Which multisig (if any) sits behind the off-curve root `GwH3Hiv5…`. Blocked twice over: the
   Squads account layouts available here do not parse the candidate, and the only exhaustive
   alternative — `getProgramAccounts` on `BPFLoaderUpgradeable` filtered on the authority bytes at
   ProgramData offset 13 — is refused by both public endpoints (HTTP 403). So *"every program
   currently under the root"* and *"no additional value-moving program under either root"* are both
   unestablished. The account-level facts that **are** measured sit in §7.
4. Whirlpool and legacy-AMM handler-level review (both hold custody; this is why the family
   disposition in `FINAL_DISPOSITION.md` cannot be better than INCOMPLETE).

## 7. Program / ProgramData verification and upgrade control (this pass, read-only mainnet)

Each program was resolved to its ProgramData, which was then read in full and sha256-matched to the
cached ELF, so every handler-level claim in these reports is about the **deployed** binary. Header
layout used: `u32 version`, `u64 slot`, `Option` flag byte at offset 12, 32-byte upgrade authority at
13, ELF buffer from 45. Direct read recorded in `recon/s4_program_upgrade_control.json`; ELF hashes in
`elf/*.meta.json`.

| program | ProgramData | ProgramData size / lamports | ELF bytes | ELF sha256 (first 16 hex) | last upgrade slot | authority byte | upgrade authority |
|---|---|---|---|---|---|---|---|
| Whirlpool `whirLbMiic…uctyCc` | `CtXfPzz36dH5Ws4UYKZvrQ1Xqzn42ecDW6y8NKuiN8nD` | 10,485,760 / 72,981,780,480 | 10,485,715 | `610b1e394973bd1b` | 440,170,207 | `0x01` present | `GwH3Hiv5…` |
| Wavebreak `waveQX2yP3…srXTF` | `nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs` | 500,493 / 3,484,322,160 | 500,448 | `8cd60d772f1d8a97` | 365,746,180 | `0x01` present | `GwH3Hiv5…` |
| Busybox/Riptide `riptK81hDx…tBS7j` | `4RhNxb6VAhj9EMsnmyxz8giXsuaMcnjCUKxPtUvhBeRu` | 259,037 / 1,803,788,400 | 258,992 | `32a8a8f75662cfdc` | 440,010,891 | `0x01` present | `GwH3Hiv5…` |
| legacy AMM `9W959DqE…aQP` | `DrrJDyBzyuyYAzkkjd6Vu9ZzaDLsKRf4RPXyRE7Uk2A8` | 691,149 / 4,811,287,920 | 691,104 | `930a47e23fe7f818` | 161,177,892 | `0x01` present | `23zF9Azp…` |

* **None of the four is renounced.** Every ProgramData still carries `Some(authority)`, so all four
  programs remain replaceable by their authority. An earlier note in this engagement described
  Whirlpool/Wavebreak/Busybox as "locked" at those slots — a misreading of the *last upgrade slot* as
  a lock event, corrected here.
* **The ProgramData lamports above are rent deposits for the ELF, not user funds.** Real custody is the
  program-owned account set (indexer pass: Whirlpool 1,106,108 accounts / 156,285 pools; legacy AMM
  ~1.25 M accounts / 41,124,583,108,449 lamports), which the capped public RPC cannot enumerate.
* The shared root `GwH3Hiv5…` is **off-curve**, i.e. a PDA: whoever derives it can upgrade Whirlpool,
  Wavebreak and Busybox in one signature. This is the largest single point of control found in the
  family. It is a governance/key-custody exposure, not a permissionless exploit: no handler in any of
  the four programs lets a caller reach it (verified for Wavebreak and Busybox by executed cases; the
  Whirlpool/AMM handler walk is §6.4).
* The legacy AMM root `23zF9Azp…` is an **on-curve plain key** holding 23,891,577,114 lamports — a
  single secret, not a PDA, so its custody question is a key-management question with no on-chain
  mitigation. It has not signed an upgrade since slot 161,177,892 (≈283 M slots ago).
* Deployed-binary ground truth for the two launch-platform programs was extracted from the ELFs
  rather than an IDL. Busybox rodata carries the 13-variant handler enum (`ProgramVersion`,
  `OracleUpdate`, `SwapExactIn`, `SwapExactOut`, four `ReservedSwap*`, `MarketUpdate`,
  `MarketDeposit`, `MarketWithdraw`, `MarketClose`, three `ReservedMarket*`), the `orca_busybox`
  router path, the `penalty/cu.rs` + `penalty/arb.rs` + `math/oracle/{amm,mod}.rs` module paths, and
  the messages "Oracle data is invalid", "Cannot close market with non-zero reserves…", "Partial fill
  is not allowed", "Slippage threshold exceeded", "BPS exceeds 10000"; it carries **none** of the
  published `math::guards` error texts (see `BUSYBOX_DEEP_REVIEW.md` §5.4).
