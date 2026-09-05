# Wavebreak deep review (defensive, fork-only)

> **Family context, updated by the WS6 pass (2026-09-04).** Two neighbouring facts changed: (1)
> Wavebreak's ProgramData `nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs` still carries `Some(GwH3Hiv5…)`, so the program is **not**
> renounced/locked, and that root is an **off-curve PDA**, not a keypair
> (`recon/s4_program_upgrade_control.json`, `ORCA_DEPLOYER_FAMILY_FINAL_INVENTORY.md` §7); (2) the
> Busybox oracle-window claim next door was inverted by measurement — `market.validUntil` **is**
> enforced at swap time (`BUSYBOX_DEEP_REVIEW.md` §5.3). Both matter to this report only as context:
> Wavebreak shares no state and no PDA namespace with Busybox's markets, and no Wavebreak handler can
> reach the root. Nothing here changed: 138 executed Wavebreak cases remain **NO CONFIRMED
> PERMISSIONLESS PROFIT PATH**, with `GraduateWhirlpool`, the LP-escrow paths, `TokenRefund` payout
> arithmetic and the provider-signed buy arithmetic still **INCOMPLETE** for fixture reasons.

Program `waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF`
Reviewed 2026-09-04 against the **deployed** ELF, mainnet live state, and a state-preserving
Surfpool mainnet fork. Nothing was broadcast to mainnet.

## 0. Identity (rule 2)

| item | value |
|---|---|
| program | `waveQX2yP3H1pVU8djGvEHmYg8uamQ84AuyGtpsrXTF` (owner BPFLoaderUpgradeable, data 45 B) |
| ProgramData | `nEuknUvGZK5UVyq3Tf18tcpNtC7dmjPMirrry66SkAs`, 3,484,322,160 lamports |
| upgrade slot / lock | 365,746,180 / locked (byte@12 = 1) |
| upgrade authority | `GwH3Hiv5mACLX3ufTw1pFsrhSPon5tdw252DBs4Rx4PV` |
| deployed ELF | 500,448 B, sha256 `8cd60d772f1d8a97a6f879c545e2827914c1d285c0edca22148ac231f21e9742` (`elf/wavebreak.bin`) |
| embedded SECURITY.TXT | name "Orca Wavebreak Program", **version 1.1.5** |
| client used for wire formats | npm `@orca-so/wavebreak@1.1.5` + crate `orca_wavebreak@1.1.5` (version-matched) |
| forks used | slot 444,204,588 (tests WB-R/WBC/WBS/WBD/WBG) and slot 444,277,192 (tests WB-F/WBL/WBV/WBFEE) |

The ELF is stripped (`.dynsym` only, 2 local funcs); everything below is keyed to file offsets in
`elf/wavebreak.bin` (`.text` 0x120–0x6a7d8). Client codegen was used only for *interface* facts
(discriminators, account order, borsh layouts) and those facts were then verified against live
state: e.g. the seed sets recomputed from the program id reproduce the client's own unit-test
vectors exactly — `bonding_curve→umyTygGGkyBw4oCxxKRPrkFCAFg1bL7DqSHwtgfKoh3`,
`mint_config→4UUnyGNdumaALFL21mFwocZvLuoqFeBrszJkkET3LJJH`,
`permission_config→GBriG7QANWP33M5diRdCUruEXcWmu3YCo8kAjEJDEUA9`,
`lp_escrow→DKX4hTCVRzu9nLJJvmtxiKU2wBLUyQby5k6cMDgNsSz2` (see `evidence/WBL_lp.json`).

## 1. Handler inventory recovered from the deployed binary

`.rodata` contains the complete instruction-name table (`0x6b9e6`–`0x6be53`), giving 31 implemented
variants plus explicit reserved slots. Enum order == the 1-byte wire discriminator:

```
0..6   PermissionConsumeTopLevel, PermissionConsumeCpi, PermissionConfigInitialize,
       PermissionConfigUpdate, PermissionConfigClose, ReservedPermissionA, PermissionRefund
8..12  TokenBuyExactIn, TokenBuyExactOut, TokenSellExactIn, TokenSellExactOut, TokenRefund
       (+ReservedTokenY/Z/A at 13-15)
16..18 AuthorityConfigInitialize, AuthorityConfigGrant, AuthorityConfigRevoke (+5 reserved)
24..26 MintConfigInitialize, MintConfigClose, MintConfigUpdate (+5 reserved)
32,33  GraduateWhirlpool, GraduateManual (+6 reserved)
40..42 CreateLockedlaunch, CreateLaunch, CreatePresale (+4 reserved)
48..51 BondingCurveInitialize, BondingCurveCollectFees, BondingCurveGraduate, BondingCurveClose
56..58 LpHarvest, LpTransfer, LpTakeover (+5 reserved)
```

**Scope correction:** `InitializePoolWithAdaptiveFee`, `InitializeDynamicTickArray`,
`OpenPositionWithTokenExtensions` and `LockPosition` do **not** exist in Wavebreak. They are
Whirlpool instructions reached through Wavebreak's graduation CPI; the deployed binary proves it
(no such names anywhere in the handler table, and `whirLbMi…` appears only as a CPI target).

External surface actually imported (`sol_invoke_signed_c` = 11 sites:
`0x16e68 0x17a00 0x1a1f8 0x1a938 0x1af40 0x1b968 0x1c120 0x1c9a0 0x1cf98 0x1d608 0x49e60`;
`sol_secp256k1_recover` = 1 site `0x4ae10`; `sol_get_processed_sibling_instruction` = 1 site
`0x48d18`; `sol_try_find_program_address` = 1 site `0xb668`). All balance movement therefore goes
through CPI; there is no lamport-direct path and no transfer-hook / revocation surface, so the
audit is sink-first by construction: the CPI sites, the PDA-seed verifier, and the fee/escrow
writers.

## 2. Guard chain, offset by offset

| concern | deployed code | verdict |
|---|---|---|
| permission signature | `0x15ff8` ("Permission signature is invalid") → `0x4ae10` (secp256k1 recover) | present; attacker-signed message rejected (`6004`), see WB-P02/P05/P06, WB-RP2/RP3 |
| allowed signer set | `0x15c50` (" is not one of the allowed signers"); live config holds exactly one key `0359c54abfca…2b29` (`recon/wb_permission_config.json`) | present; only 3 slots, all pinned by `PermissionConfigUpdate` (privilege 6) |
| consumer/subject binding | `0x15850` (" does not match permission consumer") | **enforced before** any vault touch: WB-P07, WB-RP1 (log names both pubkeys) |
| expiry | `0x15f38`: `0x603c8` (clock) then `slot > [msg+0x60]` else `6003` | present; live-expired permission rejected (WB-RP1 shows the binding hit first) |
| one-consume-per-transaction | `0x14838` ("Second PermissionConsumeTopLevel instruction found at index N"), `0x14378` (CPI detection), `0x15040` ("Could not find a matching PermissionConsume instruction") walking `0x48d18` (sibling-instruction iterator) | present: WB-P09 → `6025`; WB-C01 buy without consume → `6018` |
| replay protection | consumed-permission PDA = `find_program_address(["consumed_permission", sig[0:32], sig[32:64]])` (`0xb668` seed verifier) | present: a signature can only ever be spent into one address; already-spent live PDAs are absent because refunds close them |
| refund destination | `0x28930` → `0x16540` (`slot > safeToCloseSlot`, else `6002`) then `[r9+0x58] == [r2+0x68]` address binding | **enforced**: WB-R01/R02/RP4/RP5 → `6001` "has wrong address"; WB-R03 shows the only accepted destination is the *stored* one and it is unwritable (`6000`) |
| privilege gate | `authority_config` 64×(pubkey,16-byte bitmap), 2 populated slots (`BWyVTPPR…` privs 0,2-8; `8AbiHetk…` priv 1) — `recon/wb_authority_config.json` | enforced on every config/authority/close handler: `6027` (WB-RP8, WB-G04, WB-F05, WB-FEE2, WB-L02 – the log even names the required privilege number) |
| token-account / PDA pinning | `0xb088` "has wrong address", `0xb668` "has wrong seeds", owner checks in `0x28930` | enforced: WB-C05a/b/c/d, WB-S08, WB-V01/V02, WB-L01/L03 |
| trade bounds | `0x168c0` ("Input results in a partial fill which is explicitly disallowed"), `0x165f8` ("Swap results in an amount above the graduation target"), `0x2d6b8` ("Base amount is not zero") | enforced: WB-C01b (max u64 → `6025`), WB-S07, WB-R4, WB-G13 (`6019`) |
| graduated/expired state | `0x137f0` ("Token has not met graduation conditions"), `0x13be8` ("Bonding curve has not expired…") | enforced: WB-F02, WB-R2, WB-RF1 (`6019`/`6016`) |

## 3. Custody vs accounting (measured, all 1,537 live curves)

From `getProgramAccounts` (read-only mainnet) + per-curve vault derivation
(`recon/wb_curves.json`, `recon/wb_custody_full.json`):

* 1,537 bonding-curve records, all `buyRequiresPermission = true`, all
  `sellRequiresPermission = false`; 1 curve already graduated.
* quote-vault custody **241,206,239,109 units** across all 1,537 curves vs internal accounting
  **283,450,712,406 units** (units of each curve's own quote mint: 1,528 WSOL, 7 USDC, 2 other).
  685 curves hold *more* in the vault than accounting says, total **+6,784,577,154 units**
  (median 3,000,000; max 854,042,768) — 0.68% of custody.
* **The divergence is exactly the unclaimed protocol/creator fee, not a leak.** Fork measurement:
  curve `DbRKfbUmxd…` diverged by +506,349,347; a `BondingCurveCollectFees` call brought
  vault and accounting to **exact equality** (`recon/wb_fee_reconciliation.json`):
  vault 857,068,319 == quoteAmount 857,068,319.
* base side: no curve has base-vault > accounting (1,076 curves show vault 0 < accounting because
  pre-graduation supply is minted to buyers, not custodied).
* program-owned lamports 23.396 SOL (1,572 accounts), of which **31 `consumed_permission`
  accounts (41.42M lamports) are permanently stuck** — see §4.3.

## 4. Findings and measured denials

### 4.1 `graduateManual` is an unauthenticated trigger — measured, destination-bound, no gain

`graduateManual` (disc 33) has **no** privilege check (its account list carries no
`authority_config`) and **no** creator signature requirement. Five executed calls from the fresh
attacker key against live curves owned by third parties all succeeded:

```
7pjREHYMKCou (quote 11,560,648 vs target 1,677,572,460,000 - target NOT met)
  curve method[1].graduated   0 -> 1
  curve quote vault           11,860,354 -> 6,080,030   (-5,780,324)
  destination quote ATA      100,335,379 -> 106,115,703 (+5,780,324)
  curve baseAmount           229,735,341 -> 287,538,580 (+57,803,239, minted)
  base mint supply           +57,803,239  (to the destination's base ATA)
  attacker                    -5,000 lamports (fee) and -2,039,280 when it paid ATA rent
```

Status: **NO CONFIRMED PERMISSIONLESS PROFIT PATH**, because everything the instruction moves is
bound to the curve record: `destination` must equal the stored one (WB-G01: attacker supplied as
destination → `6001` "has wrong address"), and the quote/base recipients are the destination's
own seed-derived ATAs. The deployed binary explains why the trigger is open:
`"Launch is expired but the token did not meet the graduation conditions. Manual graduation is
required to continue trading."` — finalization is a public good anyone may pay for. Repeated
finalization is rejected (`6015`, WB-T4b/WB-R3b), so the escrow cannot be paid twice.

Two residuals we could **not** decide on live state (both left as open, not cleared):

1. *Premature finalization.* Whether the trigger also works while a Manual curve's launch window is
   open. All 7 live Manual curves have `graduation_time` in the past (355–361M slots), so there is
   no fixture; note `graduateWhirlpool`'s hosts (`0x35240`, `0x36aa8`) *do* call the
   `Token has not met graduation conditions` check at `0x137f0`, whereas the manual core `0x2e910`
   does not - the asymmetry is visible in the binary even though it is not reachable on today's state.
2. *Timing front-running.* Any wallet may choose the finalization moment, ahead of the creator.
   Measured impact: none on the attacker's balance; the state flip is irreversible.

Also measured, for the record: after finalization a holder's normal exits are `6019`
(`Token has met graduation conditions and is ready to be graduated`) and `TokenRefund` is `6016` —
but the same pair of gates fires *before* our call too (WB-Gate on `B9wBisgXnZ`, `GPa2k37Asm`), so
the graduation did **not** create the lock-out; the closed launch window did. We are explicitly not
claiming a lock-out finding.

### 4.2 Observation — anyone may trigger `BondingCurveCollectFees` (disc 49)

Measured (WB-FEE1, `evidence/WBZ_final3.json`): with the attacker as the only signer and the real
fee-authority ATA supplied, the call **succeeded** and moved 677,473,335 units from
`6n8MPRJ81G…`'s vault to `2SDVckjAEx7…` (the privilege-1 fee authority). Re-attacking the same
curve on `DbRKfbUmxd…` reconciled its whole +506,349,347 divergence to zero.
The beneficiary is bound (`feeAuthority` must hold privilege 1 → otherwise `6027` "does not have
required privilege 1", `evidence/WBFEE_collect.json`; the ATA itself is seed-bound → `6023` in
WB-G05). So this is a permissionless *trigger* with a bound recipient: no theft path, but it lets
any wallet spend gas to sweep fees at a chosen moment.

### 4.3 Observation — 31 live `consumed_permission` accounts hold unrecoverable rent

All 31 have `safeToCloseSlot` far in the past (338–343M) and `refundDestination = Pubkey::default()`
(41,420,920 lamports). The refund path binds the destination to that stored field, so nobody can
recover them (WB-R01/R02 `6001`; WB-R03 `6000` "is not writable" when the stored value itself is
used). Not exploitable, but it is stranded state: an unset destination should be treated as
"refund to the consumer" (or the field must be required at consume time).

### 4.4 Cleared paths (executed, this session)

`NO CONFIRMED PERMISSIONLESS PROFIT PATH` for: `PermissionConsumeTopLevel` (WB-P01…P10, WB-RP1…3),
`PermissionConsumeCpi` as top level (`6006`, WB-P08), `PermissionRevoke` (WB-RP7 `6023`),
`PermissionRefund` (WB-R01…R06, WB-RP4…6), `TokenBuyExactIn/Out` (WB-C01, WB-C01b, WB-P10,
WB-C02, WB-C05a…d), `TokenSellExactIn/Out` incl. drain attempts (WB-S01…S13, WB-DR*, WB-T1/T2,
WB-R1/R1b/R4), `TokenRefund` gate (WB-RF1, WB-G03/G12), `MintConfig*`/`PermissionConfig*`/
`AuthorityConfig*` (WB-RP8, `6027`), `BondingCurveClose` (WB-F05, WB-G04),
`BondingCurveCollectFees` (WB-FEE2 `6027`, WB-G05 `6023`), `LpTransfer`/`LpHarvest`/`LpTakeover`
(WB-L01…L03), third-party-token-account burn via `baseAta` (WB-V01/V02 `6023`), and the
fee-custody sweep hypothesis (§3). 171 executed cases in total; every one denied, or accepted with
zero attacker-positive delta (`reports/TESTS_MACHINE_READABLE.json`).

## 5. Explicitly not concluded

* `GraduateWhirlpool` end-to-end (escrow/LP custody binding): **INCOMPLETE**. The freshest live
  graduation tx (slot 441,655,843, 35 accounts) has 7 accounts already closed at both fork tips,
  and no Whirlpool pool exists for the largest pre-graduation WSOL curves, so my attempts ended on
  `6022`/`6023` account checks rather than on an authorization decision. Not to be read as clear.
* `TokenRefund` payout *arithmetic* on a genuinely expired, non-graduated curve: **INCOMPLETE** —
  no live curve reaches that state (all candidates `6016`), and time-travel would not change the
  supply accounting.
* Whether `graduateManual` can be triggered *before* `graduationTime` on a Manual curve: not
  reachable on live state (all 7 Manual curves are past their window), so untested.
* Whirlpool itself (reached via the graduation CPI) and the legacy AMM: out of scope here and
  unreviewed, which is why the family disposition stays INCOMPLETE.
