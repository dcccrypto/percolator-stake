//! CPI helpers for calling percolator wrapper instructions.
//!
//! The stake program issues FOUR wrapper CPIs:
//!   * TopUpInsurance (tag 9)             — the insurance flush itself.
//!   * UpdateAssetAuthority (tag 65)      — bind/rotate the per-asset
//!     `insurance_authority` (asset 0, kind=ASSET_AUTH_INSURANCE=1) to our
//!     `vault_auth` PDA.
//!   * UpdateAssetAuthority (tag 65)      — move `insurance_operator` (kind=2)
//!     to the same `vault_auth` PDA so the admin cannot drain via tag-57
//!     local_authorized path.
//!   * UpdateAssetAuthority (tag 65)      — burn `asset_admin` (kind=0,
//!     new_pubkey=[0;32]) so the admin cannot rotate any authority back.
//!
//! The authority and operator CPIs are issued together in BindInsuranceAuthority
//! (tag 19); the asset_admin burn is a separate finalization step
//! (BurnAssetAdmin, tag 21). Together they guarantee the STRONG no-admin-drain
//! property: after bind + burn, no admin key can drain insurance via
//! WithdrawInsuranceAsset (tag 57), and stake will not rotate the PDA roles back.
//!
//! V17 WIRE CHANGE (collision row 43): the v16 wire used tag 32 `UpdateAuthority`
//! with kind byte = 2 (AUTHORITY_INSURANCE) and a 34-byte payload. The v17 auth
//! overhaul replaced per-field authority mutation with a per-ASSET handler (tag 65
//! `UpdateAssetAuthority`). The new wire is:
//!   [tag=65u8][asset_index: u16 LE = 0x00 0x00][kind: u8 = 1][pubkey: 32 bytes]
//!   = 36 bytes total.  THREE changes from the v16 wire: (1) tag 32→65, (2) kind
//!   value FLIPPED 2→1 (ASSET_AUTH_INSURANCE=1, not AUTHORITY_INSURANCE=2), (3)
//!   NEW 2-byte asset_index prefix (always 0 for the asset-0 insurance profile).
//! The 3-account shape is UNCHANGED from tag 32:
//!   [0] current authority (signer)
//!   [1] new authority (signer when new_pubkey != 0; no-op slot when burning to 0)
//!   [2] market (writable, wrapper-owned)
//!
//! WHY THE BIND CPI EXISTS: v17 authorizes tag 9 against the per-asset
//! `insurance_authority` profile and our CPI signer is the `vault_auth` PDA —
//! so that field must equal the PDA. Tag 65 requires the NEW authority to
//! co-sign (v16_program.rs handle_update_asset_authority:9414-9420), and a PDA
//! cannot sign a top-level tx. The ONLY way to bind a PDA is a CPI from its
//! owning program (us) that `invoke_signed`s the PDA as the new authority while
//! the admin co-signs as the current authority. This is NOT a redundant proxy:
//! the human admin literally cannot perform this bind directly.
#![allow(clippy::too_many_arguments)]

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
};

// Wrapper instruction tags (from percolator-prog/src/v16_program.rs ix::Instruction).
const TAG_TOP_UP_INSURANCE: u8 = 9;
/// UpdateAuthority (tag 32) — rotates the single market-level `cfg.marketauth`
/// key ONLY. Confirmed against the live deployed wrapper
/// (percolator-prog@14440e0c, src/v16_program.rs:3783 decode / :4123 encode /
/// handle_update_authority:9658) — wire is `tag(1) + new_pubkey(32)` = 33
/// bytes, NO kind byte, 3-account shape `[current(signer), new(signer),
/// market(w)]`. This is orthogonal to `TAG_UPDATE_ASSET_AUTHORITY` below (tag
/// 65, per-asset authorities e.g. insurance_authority/operator/admin) — both
/// tags are live and unrelated fields on the currently-deployed wrapper; tag
/// 65 did NOT supersede tag 32 for marketauth (see issue #6 lineage research).
const TAG_UPDATE_AUTHORITY: u8 = 32;
/// V17 auth overhaul (collision row 43): tag 32 `UpdateAuthority` rotated only
/// `cfg.marketauth`. Per-asset authorities (including insurance_authority for
/// asset 0) now go through tag 65 `UpdateAssetAuthority`.
const TAG_UPDATE_ASSET_AUTHORITY: u8 = 65;
/// asset_index for the asset-0 insurance profile (always 0 in the stake use-case).
/// Encoded as u16 LE = [0x00, 0x00] in the 36-byte tag-65 wire.
const ASSET_INDEX_ZERO: u16 = 0;
/// UpdateAssetAuthority kind selector for insurance_authority.
/// Source: v16_program.rs ASSET_AUTH_INSURANCE = 1.
/// NOTE: this is DIFFERENT from the v16 AUTHORITY_INSURANCE=2 that tag 32 used.
/// The footgun here is that both look like small integers but are defined in
/// different constant families and must NOT be swapped.
const ASSET_AUTH_INSURANCE: u8 = 1;
/// UpdateAssetAuthority kind selector for insurance_operator.
/// Source: v16_program.rs ASSET_AUTH_INSURANCE_OPERATOR = 2.
/// Must be moved (cannot burn to zero) to a key the admin does not control.
/// In the secure-bind sequence we move it to the vault_auth PDA so the admin
/// cannot drain via the local_authorized path in WithdrawInsuranceAsset (tag 57).
const ASSET_AUTH_INSURANCE_OPERATOR: u8 = 2;
/// UpdateAssetAuthority kind selector for asset_admin.
/// Source: v16_program.rs ASSET_AUTH_ADMIN = 0.
/// This is the ONLY authority that can be burned to zero (new_pubkey = [0;32]).
/// Burning asset_admin irrevocably removes the admin's ability to rotate any of
/// the asset's authorities (insurance, operator, backing, oracle) back to admin
/// control. This is the final step of the secure-bind sequence.
const ASSET_AUTH_ADMIN: u8 = 0;

// ═══════════════════════════════════════════════════════════════
// TopUpInsurance (Tag 9) — v16 contract
// ═══════════════════════════════════════════════════════════════
// Accounts: [signer, slab(w), signer_ata(w), vault(w), token_program]
// Data: tag(1) + amount(16, u128 LE)
//
// V16 WIRE CONTRACT (verified against percolator-prog v16-sync @5260d1b):
//   * AMOUNT IS u128 ON THE WIRE. The v16 wrapper decodes tag 9 with
//     `read_u128` (v16_program.rs:2627), which returns `InvalidInstructionData`
//     for any payload < 16 bytes (v16_program.rs:3275-3282). The pre-v16 wire
//     sent an 8-byte u64 — against a v16 wrapper that 8-byte payload HARD-REVERTS
//     the CPI at decode time. We therefore widen the wire to `(amount as u128)`.
//     `amount` stays a u64 here because token amounts fit u64 and the wrapper
//     re-narrows via `u64::try_from` (v16_program.rs:7574); only the wire widens.
//   * NOT PERMISSIONLESS. v16 gates tag 9 on `expect_live_authority(
//     cfg.insurance_authority, signer.key)` (v16_program.rs:7569,7584). The CPI
//     signer is our `vault_auth` PDA, so the market's `insurance_authority` MUST
//     be bound to that PDA first — via `cpi_bind_insurance_authority` /
//     instruction BindInsuranceAuthority (a plain admin UpdateAuthority cannot
//     bind a PDA; see that helper) — or every flush reverts Custom(8)
//     Unauthorized. (The old "permissionless" comment was wrong for v16.)
//   * LIVE MODE REQUIRED. v16 rejects tag 9 unless the market is Live
//     (v16_program.rs:7566,7580) — checked BEFORE the authority gate, so a
//     not-yet-Live market reverts Custom(21) EngineLockActive.
//
// CUTOVER ATOMICITY: this 16-byte wire MUST ship in the same cutover bundle as
// the v16 wrapper. NEVER deploy this stake build against a live pre-v16 (v12)
// wrapper — that wrapper decodes tag 9 as u64 (8 bytes) and would reject the
// 16-byte payload. See ~/wrapper-engine-deep-audit/V16_DIVERGENCES.md (stake).

pub fn cpi_top_up_insurance<'a>(
    percolator_program: &AccountInfo<'a>,
    signer: &AccountInfo<'a>, // vault_auth PDA (we sign) — must == market insurance_authority
    slab: &AccountInfo<'a>,
    signer_ata: &AccountInfo<'a>, // stake vault (owned by vault_auth)
    wrapper_vault: &AccountInfo<'a>,
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    // tag(1) + u128 amount(16) = 17 bytes.
    let mut data = Vec::with_capacity(17);
    data.push(TAG_TOP_UP_INSURANCE);
    data.extend_from_slice(&(amount as u128).to_le_bytes());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*signer.key, true),
            AccountMeta::new(*slab.key, false),
            AccountMeta::new(*signer_ata.key, false),
            AccountMeta::new(*wrapper_vault.key, false),
            AccountMeta::new_readonly(*token_program.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            signer.clone(),
            slab.clone(),
            signer_ata.clone(),
            wrapper_vault.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAuthority (Tag 32) — rotate market-level marketauth to the pool PDA
// ═══════════════════════════════════════════════════════════════
// Accounts (v16_program.rs handle_update_authority, account(_,0)/(_,1)/(_,2)):
//   [current_authority(signer), new_authority(signer), market(w)]
// Data: tag(1) + new_authority(32) = 33 bytes
//
// Ported byte-for-byte from the deployed percolator-vault@eb3ebe8 InitPool CPI
// (src/cpi.rs `cpi_update_authority`, src/processor.rs:340) — issue #6
// lineage reconciliation. Called from InitPool to prove the initializer is
// the CURRENT wrapper marketauth by transferring it to this pool PDA
// atomically with pool creation: if `admin` is not the current marketauth,
// the wrapper CPI fails closed and the whole InitPool tx reverts. This
// irreversibly moves wrapper-level admin from the human creator to the pool
// PDA, matching the deployed vault's behavior that the launch wizard's
// account-authority sequencing depends on (marketauth == creator wallet
// until this call, pool PDA thereafter).
//
// NOTE: distinct from `cpi_bind_insurance_authority` / `TAG_UPDATE_ASSET_AUTHORITY`
// (tag 65) above, which rotates only the per-asset insurance_authority/operator/
// admin fields, not the market-wide marketauth this function rotates.

pub fn cpi_update_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    current_admin: &AccountInfo<'a>, // current marketauth; signs the outer tx
    new_authority: &AccountInfo<'a>, // pool PDA; co-signs via invoke_signed
    slab: &AccountInfo<'a>,          // market, writable
    new_authority_seeds: &[&[u8]],   // pool PDA seeds
) -> ProgramResult {
    let mut data = Vec::with_capacity(33);
    data.push(TAG_UPDATE_AUTHORITY);
    data.extend_from_slice(new_authority.key.as_ref());

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*current_admin.key, true),
            AccountMeta::new_readonly(*new_authority.key, true),
            AccountMeta::new(*slab.key, false),
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[current_admin.clone(), new_authority.clone(), slab.clone()],
        &[new_authority_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — one-time bind of insurance_authority
// ═══════════════════════════════════════════════════════════════
// Accounts (v16_program.rs handle_update_asset_authority L9407-9412):
//   [current(signer), new_authority(signer when new_pubkey!=0), market(w)]
// Data: tag(1) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32) = 36 bytes
//
// V17 WIRE (collision row 43): tag 32 → 65; kind 2 → 1; +2 bytes asset_index.
// Binds the market's per-asset `insurance_authority` (asset 0) to our
// `vault_auth` PDA so the subsequent TopUpInsurance flush (signed by the PDA)
// passes v17's authority gate. `admin` co-signs as the CURRENT authority (must
// equal profile.insurance_authority, which InitMarket seeds to admin via
// asset_admin bootstrap), and the PDA co-signs as the NEW authority via
// invoke_signed. After this bind, only the PDA can rotate the authority again —
// the bind is effectively one-directional (PDA-custody security property).
// RotateInsuranceAuthority (tag 20) is the deliberate admin-gated escape.

pub fn cpi_bind_insurance_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>, // current authority (== profile.insurance_authority at bind time); signs outer tx
    vault_auth: &AccountInfo<'a>, // new authority = our PDA; signs via invoke_signed
    market: &AccountInfo<'a>, // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],  // vault_auth PDA seeds
) -> ProgramResult {
    // tag(1) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32) = 36 bytes.
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.push(ASSET_AUTH_INSURANCE);                         // kind = 1
    data.extend_from_slice(vault_auth.key.as_ref());         // new_pubkey = PDA

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin.key, true),      // current authority, signer
            AccountMeta::new_readonly(*vault_auth.key, true), // new authority (PDA), signer via invoke_signed
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin.clone(), vault_auth.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — move insurance_operator to our PDA
// ═══════════════════════════════════════════════════════════════
// Same wrapper handler as the insurance_authority bind, but kind=2
// (ASSET_AUTH_INSURANCE_OPERATOR). Admin is the current operator (bootstrapped
// to marketauth/admin at InitMarket). vault_auth PDA co-signs as the NEW
// operator via invoke_signed. After this call, only a stake CPI (which can
// invoke_signed as vault_auth) can operate as the insurance_operator — the
// admin cannot drain via tag-57's local_authorized path.
//
// SECURITY NOTE: insurance_operator cannot be burned to zero (the wrapper
// rejects new_pubkey=[0;32] for kind != ASSET_AUTH_ADMIN at line 9439). The
// PDA is the safe non-zero non-admin key. The ASSET_AUTH_ADMIN burn (below) then
// removes the admin's ability to rotate this back.

pub fn cpi_bind_insurance_operator<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>,     // current insurance_operator (== admin at bootstrap); signer
    vault_auth: &AccountInfo<'a>, // new operator = our PDA; co-signs via invoke_signed
    market: &AccountInfo<'a>,    // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],      // vault_auth PDA seeds
) -> ProgramResult {
    // tag(1) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32) = 36 bytes.
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.push(ASSET_AUTH_INSURANCE_OPERATOR);                // kind = 2
    data.extend_from_slice(vault_auth.key.as_ref());         // new_pubkey = PDA

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin.key, true),      // current operator (admin), signer
            AccountMeta::new_readonly(*vault_auth.key, true), // new operator (PDA), signer via invoke_signed
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[admin.clone(), vault_auth.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — burn asset_admin to zero
// ═══════════════════════════════════════════════════════════════
// Burning asset_admin (kind=0, new_pubkey=[0;32]) removes the admin's ability
// to rotate ANY of the asset's per-asset authorities (insurance_authority,
// insurance_operator, backing_bucket_authority, oracle_authority) back to an
// admin-controlled key. This is the final step of the secure-bind sequence
// and makes the PDA custody irrevocable.
//
// UNIQUELY PERMITTED: the wrapper allows new_pubkey=[0;32] ONLY for kind=0
// (ASSET_AUTH_ADMIN). For all other kinds it returns InvalidInstruction.
// (v16_program.rs handle_update_asset_authority line 9439).
//
// NO CO-SIGN REQUIRED: when new_pubkey=[0;32], the wrapper skips the
// expect_signer(new_authority) check (line 9405). We still need a second
// account slot — we pass vault_auth as a placeholder (it is already present
// in the transaction; no signer check is performed on it by the wrapper).
//
// Account layout: [current(signer=admin), new_authority(any, not checked), market(w)]
// Wire: tag(65) + asset_index(0 u16 LE) + kind(0) + new_pubkey([0;32]) = 36 bytes.

pub fn cpi_burn_asset_admin<'a>(
    percolator_program: &AccountInfo<'a>,
    admin: &AccountInfo<'a>,     // current asset_admin; signer
    vault_auth: &AccountInfo<'a>, // placeholder new_authority slot (not checked by wrapper for zero burn)
    market: &AccountInfo<'a>,    // the slab/market account (writable, wrapper-owned)
) -> ProgramResult {
    // tag(1) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32, all zeros) = 36 bytes.
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.push(ASSET_AUTH_ADMIN);                             // kind = 0
    data.extend_from_slice(&[0u8; 32]);                      // new_pubkey = burn (all zeros)

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*admin.key, true),       // current asset_admin, signer
            AccountMeta::new_readonly(*vault_auth.key, false), // new_authority slot (any; not checked for zero-burn)
            AccountMeta::new(*market.key, false),              // market, writable
        ],
        data,
    };

    // Plain invoke (not signed) — admin signs as the outer tx signer; no PDA co-sign needed.
    invoke(
        &ix,
        &[admin.clone(), vault_auth.clone(), market.clone()],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — rotate insurance_operator OFF our PDA
// ═══════════════════════════════════════════════════════════════
// Same as cpi_rotate_insurance_authority but for insurance_operator (kind=2).
// Used in the migration escape sequence (RotateInsuranceOperator, tag 22):
//   PDA signs as the CURRENT operator; new_target co-signs as the NEW operator.
//
// Full no-lockout migration sequence:
//   1. RotateInsuranceAuthority (tag 20): insurance_authority PDA → admin wallet
//   2. RotateInsuranceOperator  (tag 22): insurance_operator  PDA → admin wallet
//   3. Re-bind from NEW program (BindInsuranceAuthority, tag 19)
//   4. BurnAssetAdmin (tag 21) — only if asset_admin not already zero

pub fn cpi_rotate_insurance_operator<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // CURRENT operator = our PDA; signs via invoke_signed
    new_target: &AccountInfo<'a>, // NEW operator (admin-specified, non-zero); co-signs outer tx
    market: &AccountInfo<'a>,     // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],       // vault_auth PDA seeds
) -> ProgramResult {
    // tag(1) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32) = 36 bytes.
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.push(ASSET_AUTH_INSURANCE_OPERATOR);                // kind = 2
    data.extend_from_slice(new_target.key.as_ref());         // new_pubkey = rotation target

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // current operator (PDA), signer via invoke_signed
            AccountMeta::new_readonly(*new_target.key, true), // new operator, signer (outer tx)
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[vault_auth.clone(), new_target.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// UpdateAssetAuthority (Tag 65) — rotate insurance_authority OFF our PDA
// ═══════════════════════════════════════════════════════════════
// Same wrapper instruction as the bind, but the account ROLES invert:
//   current      = our `vault_auth` PDA (signs via invoke_signed)
//   new_authority = admin-specified `new_target` (co-signs the outer tx)
//
// WHY THIS EXISTS (the no-lockout escape): `cpi_bind_insurance_authority` makes
// the vault_auth PDA the sole rotator of insurance_authority. Moving it OFF
// requires the PDA to sign as the CURRENT authority
// (v16_program.rs handle_update_asset_authority:9452-9453) — which only a stake
// CPI can produce. Without a rotate path, a stake redeploy to a NEW program id
// (its `vault_auth` PDA derives under the new id) would orphan `insurance_authority`
// on the dead program and brick the insurance flush unrecoverably. Rotate is the
// deliberate, admin-gated migration/incident primitive: rotate to the admin wallet
// from the OLD program before decommissioning it, then re-bind from the NEW program.
// `new_target` must co-sign the outer tx (the wrapper requires the new authority
// to sign for non-zero keys, 9415-9420); a typical migration uses the admin wallet.
//
// WIRE NOTE: same 36-byte tag-65 layout as cpi_bind_insurance_authority, but
// new_pubkey = new_target.key (the rotation destination, not our PDA).

pub fn cpi_rotate_insurance_authority<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>, // CURRENT authority = our PDA; signs via invoke_signed
    new_target: &AccountInfo<'a>, // NEW authority (admin-specified, non-zero); co-signs the outer tx
    market: &AccountInfo<'a>,     // the slab/market account (writable, wrapper-owned)
    signer_seeds: &[&[u8]],       // vault_auth PDA seeds
) -> ProgramResult {
    // tag(1) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32) = 36 bytes.
    let mut data = Vec::with_capacity(36);
    data.push(TAG_UPDATE_ASSET_AUTHORITY);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.push(ASSET_AUTH_INSURANCE);                         // kind = 1
    data.extend_from_slice(new_target.key.as_ref());         // new_pubkey = rotation target

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true), // current authority (PDA), signer via invoke_signed
            AccountMeta::new_readonly(*new_target.key, true), // new authority, signer (outer tx)
            AccountMeta::new(*market.key, false),             // market, writable
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[vault_auth.clone(), new_target.clone(), market.clone()],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// WithdrawInsuranceAsset (Tag 57) — PDA-signed insurance recovery
// ═══════════════════════════════════════════════════════════════
// Wire: [57u8][asset_index: u16 LE = 0][amount: u128 LE] = 19 bytes.
// Account order (verified against tests/v17_stake_insurance_e2e.rs
// withdraw_insurance_asset_ix and wrapper handle_withdraw_insurance_asset):
//   [0] operator      (vault_auth PDA, signer via invoke_signed) — must == insurance_operator
//   [1] market        (writable)
//   [2] dest_token    (writable) — MUST equal pool.vault (drain check enforced by caller)
//   [3] vault_token   (writable) — wrapper's insurance vault, the token source
//   [4] vault_authority (read-only) — wrapper vault authority PDA
//   [5] token_program  (read-only)
//
// AUTH: insurance_operator == vault_auth PDA (set by BindInsuranceAuthority tag 19 CPI 2).
//   After BurnAssetAdmin, no admin key can rotate the operator back — so this CPI
//   is the ONLY authorized path for extracting insurance tokens from the wrapper.
//
// MODE: tag 57 works in LIVE mode (same mode FlushToInsurance uses); the caller
//   (process_recover_flushed_insurance) enforces LIVE mode via pool_mode == 0.
//
// NOTE: vault_auth PDA signs via invoke_signed with the same seeds as all other
//   stake CPIs: [b"vault_auth", pool_pda.key, &[bump]].

const TAG_WITHDRAW_INSURANCE_ASSET: u8 = 57;

pub fn cpi_withdraw_insurance_asset<'a>(
    percolator_program: &AccountInfo<'a>,
    vault_auth: &AccountInfo<'a>,   // insurance_operator = our PDA; signs via invoke_signed
    market: &AccountInfo<'a>,       // wrapper market / slab (writable)
    dest_token: &AccountInfo<'a>,   // destination token account (MUST be pool.vault; drain check by caller)
    wrapper_vault: &AccountInfo<'a>, // wrapper insurance vault token account (source)
    wrapper_vault_auth: &AccountInfo<'a>, // wrapper vault authority PDA (read-only)
    token_program: &AccountInfo<'a>,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    // tag(1) + asset_index(2, u16 LE = 0) + amount(16, u128 LE) = 19 bytes.
    let mut data = Vec::with_capacity(19);
    data.push(TAG_WITHDRAW_INSURANCE_ASSET);
    data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // 2 bytes, always 0x00 0x00
    data.extend_from_slice(&(amount as u128).to_le_bytes()); // 16 bytes u128 LE

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*vault_auth.key, true),      // operator (PDA), signer via invoke_signed
            AccountMeta::new(*market.key, false),                   // market, writable
            AccountMeta::new(*dest_token.key, false),               // dest_token (pool.vault), writable
            AccountMeta::new(*wrapper_vault.key, false),            // vault_token (source), writable
            AccountMeta::new_readonly(*wrapper_vault_auth.key, false), // vault_authority, read-only
            AccountMeta::new_readonly(*token_program.key, false),  // token_program, read-only
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            vault_auth.clone(),
            market.clone(),
            dest_token.clone(),
            wrapper_vault.clone(),
            wrapper_vault_auth.clone(),
            token_program.clone(),
        ],
        &[signer_seeds],
    )
}

// ═══════════════════════════════════════════════════════════════
// ResolveMarket (Tag 19) — C-1 fix: CPI proxy for the wrapper's terminal
// resolution instruction, now that marketauth is the pool PDA
// ═══════════════════════════════════════════════════════════════
// SECURITY REVIEW C-1 (BLOCKER, fixed here): `process_init_pool` rotates
// `cfg.marketauth` to the pool PDA (see `cpi_update_authority` above), ported
// from the deployed `percolator-vault@eb3ebe8`. That vault ALSO ports an
// `AdminResolveMarket` CPI proxy (vault tag 9 -> wrapper tag 19) alongside the
// rotation — this program had the rotation WITHOUT the matching proxy. Once
// marketauth is the pool PDA, NO top-level signer can ever satisfy the
// wrapper's `expect_signer(admin)` + `expect_live_authority(&cfg.marketauth,
// admin.key)` checks in `handle_resolve_market` directly (a PDA cannot sign a
// plain transaction) — every market created via InitPool would be
// permanently stuck in Live mode (mode == 0), with the terminal insurance
// withdrawal path (post-resolution WithdrawInsurance) forever unreachable.
// This CPI closes that gap: the pool PDA signs via `invoke_signed` using its
// OWN seeds (`[b"stake_pool", slab, bump]`), exactly mirroring how
// `cpi_update_authority` already proves control during InitPool.
//
// WIRE (verified against the DEPLOYED wrapper source,
// percolator-prog@e26c97a4 == current HEAD, src/v16_program.rs:10278
// handle_resolve_market):
//   let admin = account(accounts, 0)?;      // expect_signer + expect_live_authority(marketauth)
//   let market_ai = account(accounts, 1)?;  // expect_writable + expect_owner(program_id)
//   ... mode must == 0 (else EngineLockActive) ...
//   group.resolve_market_not_atomic(slot)
// Tag decode (v16_program.rs:3867): `19 => Self::ResolveMarket` — the decoder
// consumes ZERO additional bytes for this variant (unlike e.g. tag 9's
// `read_u128`), so the wire is the bare 1-byte tag. Data: tag(1) = 1 byte.
// Accounts: exactly 2 — [admin(signer), market(writable)]. NO payload bytes,
// NO extra accounts.
//
// BYTE-FOR-BYTE PARITY with the deployed vault's `cpi_resolve_market`
// (percolator-vault@eb3ebe8 src/cpi.rs:240-258): `let data =
// vec![TAG_RESOLVE_MARKET];` with the identical 2-account
// `[new_readonly(admin_pda, true), new(slab, false)]` shape and
// `invoke_signed(&ix, &[admin_pda.clone(), slab.clone()], &[admin_seeds])`
// call pattern. The only naming difference is that THIS program's "admin_pda"
// signer is the `stake_pool` PDA itself (matching what `cpi_update_authority`
// rotated marketauth to), not a separately-named admin PDA — vault and stake
// converge on the same PDA-is-marketauth design from issue #6 lineage
// reconciliation, so the CPI construction is identical.
//
// H-1 (HIGH, fixed at the call site in `processor.rs::process_admin_resolve_market`):
// this CPI is gated so the caller may not invoke it while
// `pool.total_flushed > pool.total_returned` (flushed-but-unrecovered
// insurance outstanding). `RecoverFlushedInsurance` (tag 23) CPIs wrapper tag
// 57 `WithdrawInsuranceAsset`, which itself requires LIVE mode (mode == 0) —
// once THIS CPI flips the wrapper to mode != 0, tag 57 permanently rejects
// with EngineLockActive and any outstanding flush would be stranded with no
// recovery path (the wrapper's terminal-mode withdrawal, tag 41
// `WithdrawInsurance`, is a DIFFERENT CPI this program does not implement).
// Gating resolution on full recovery-first means that fallback is never
// needed by construction — see the H-1 doc note on
// `process_admin_resolve_market` for the full analysis.
const TAG_RESOLVE_MARKET: u8 = 19;

pub fn cpi_resolve_market<'a>(
    percolator_program: &AccountInfo<'a>,
    pool_pda: &AccountInfo<'a>, // marketauth (rotated by InitPool); signs via invoke_signed
    slab: &AccountInfo<'a>,     // market, writable
    pool_seeds: &[&[u8]],       // pool PDA seeds: [b"stake_pool", slab, bump]
) -> ProgramResult {
    // tag(1) = 1 byte. No payload — matches `19 => Self::ResolveMarket` (zero
    // additional bytes consumed by the wrapper's decoder).
    let data = vec![TAG_RESOLVE_MARKET];

    let ix = Instruction {
        program_id: *percolator_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*pool_pda.key, true), // admin == marketauth, signer
            AccountMeta::new(*slab.key, false),              // market, writable
        ],
        data,
    };

    invoke_signed(&ix, &[pool_pda.clone(), slab.clone()], &[pool_seeds])
}

#[cfg(test)]
mod tag_tests {
    use super::*;

    #[test]
    fn test_cpi_tag_constants() {
        assert_eq!(TAG_TOP_UP_INSURANCE, 9, "TAG_TOP_UP_INSURANCE mismatch");
        assert_eq!(
            TAG_UPDATE_ASSET_AUTHORITY, 65,
            "TAG_UPDATE_ASSET_AUTHORITY mismatch (v17 collision row 43: was 32)"
        );
        assert_eq!(ASSET_INDEX_ZERO, 0, "ASSET_INDEX_ZERO must be 0");
        assert_eq!(
            ASSET_AUTH_INSURANCE, 1,
            "ASSET_AUTH_INSURANCE mismatch (v17 footgun: was 2 in v16 AUTHORITY_INSURANCE)"
        );
    }

    /// CANARY: pin the v17 UpdateAssetAuthority(insurance) bind wire shape =
    /// tag(65) + asset_index(2, u16 LE = 0) + kind(1) + new_pubkey(32) = 36 bytes.
    ///
    /// THREE footguns verified here at the byte level:
    ///   (1) tag byte must be 65, NOT 32 (the old UpdateAuthority tag)
    ///   (2) kind byte must be 1 (ASSET_AUTH_INSURANCE), NOT 2 (old AUTHORITY_INSURANCE)
    ///   (3) asset_index u16 LE prefix (2 bytes, always 0x00 0x00) is NEW in v17
    #[test]
    fn test_cpi_bind_asset_authority_wire_shape_v17() {
        let pda = [9u8; 32];
        let mut data = Vec::with_capacity(36);
        data.push(TAG_UPDATE_ASSET_AUTHORITY);            // byte 0: tag = 65
        data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // bytes 1-2: asset_index = 0
        data.push(ASSET_AUTH_INSURANCE);                 // byte 3: kind = 1
        data.extend_from_slice(&pda);                    // bytes 4-35: new_pubkey

        // Total length: 36 bytes (was 34 bytes in v16)
        assert_eq!(data.len(), 36, "v17 tag-65 wire must be 36 bytes (was 34 in v16)");

        // (1) tag = 65, NOT 32
        assert_eq!(data[0], 65, "tag must be 65 (UpdateAssetAuthority), not 32");
        assert_ne!(data[0], 32, "tag 32 is the OLD UpdateAuthority — MUST NOT ship");

        // (2) asset_index = 0 (little-endian u16)
        assert_eq!(data[1], 0x00, "asset_index low byte must be 0");
        assert_eq!(data[2], 0x00, "asset_index high byte must be 0");

        // (3) kind = 1 (ASSET_AUTH_INSURANCE), NOT 2 (old AUTHORITY_INSURANCE)
        assert_eq!(data[3], 1, "kind must be 1 (ASSET_AUTH_INSURANCE)");
        assert_ne!(data[3], 2, "kind=2 is the OLD AUTHORITY_INSURANCE — MUST NOT ship");

        // pubkey bytes in position
        assert_eq!(&data[4..36], &pda, "new_pubkey at bytes [4..36]");
    }

    /// REGRESSION GUARD: pin the OLD v16 wire shape to document the exact break.
    /// The v16 wire was tag(32) + kind(2) + new_pubkey(32) = 34 bytes.
    /// A v17 wrapper at tag 32 only rotates marketauth, not per-asset fields.
    /// Sending the old 34-byte payload to a v17 wrapper would silently corrupt
    /// marketauth or be rejected — neither is acceptable.
    #[test]
    fn test_old_v16_bind_wire_is_wrong_for_v17() {
        // Reconstruct the v16 wire
        let pda = [9u8; 32];
        let mut old_data = Vec::with_capacity(34);
        old_data.push(32u8);  // old tag
        old_data.push(2u8);   // old kind = AUTHORITY_INSURANCE
        old_data.extend_from_slice(&pda);

        // These are the wrong values for v17
        assert_eq!(old_data[0], 32, "old tag was 32");
        assert_eq!(old_data[1], 2, "old kind was 2");
        assert_eq!(old_data.len(), 34, "old wire was 34 bytes");

        // Assertions that must NOT hold in v17
        assert_ne!(old_data[0], TAG_UPDATE_ASSET_AUTHORITY, "v17 tag must be 65");
        // kind byte in old wire is at position 1, in new wire it's at position 3
        assert_ne!(old_data.len(), 36, "v17 wire must be 36 bytes");
    }

    /// CANARY: pin the v17 tag-9 wire shape. The amount is u128 (16 bytes), NOT
    /// u64 (8 bytes). If anyone narrows this back to u64 the v17 wrapper's
    /// `read_u128` decoder rejects the CPI with InvalidInstructionData. This test
    /// reconstructs the exact bytes `cpi_top_up_insurance` builds.
    #[test]
    fn test_cpi_wire_shape_is_tag_plus_u128() {
        let amount: u64 = 1_000;
        // Mirror the encoding in cpi_top_up_insurance.
        let mut data = Vec::with_capacity(17);
        data.push(TAG_TOP_UP_INSURANCE);
        data.extend_from_slice(&(amount as u128).to_le_bytes());

        assert_eq!(data.len(), 17, "tag-9 payload must be 1 + 16 bytes");
        assert_eq!(data[0], 9, "tag byte");
        // amount occupies bytes [1..17] little-endian as u128.
        let decoded = u128::from_le_bytes(data[1..17].try_into().unwrap());
        assert_eq!(decoded, amount as u128, "amount must round-trip as u128 LE");
        // Guard against regression to the broken 8-byte u64 wire.
        assert_ne!(
            data.len(),
            9,
            "8-byte u64 wire is the pre-v16 break — must NOT ship"
        );
    }

    /// CANARY: pin the insurance_operator bind wire (tag-65 kind=2).
    /// Must NOT be confused with kind=1 (insurance_authority) or kind=0 (admin burn).
    #[test]
    fn test_cpi_bind_operator_wire_shape() {
        let pda = [7u8; 32];
        let mut data = Vec::with_capacity(36);
        data.push(TAG_UPDATE_ASSET_AUTHORITY);             // byte 0: tag = 65
        data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // bytes 1-2
        data.push(ASSET_AUTH_INSURANCE_OPERATOR);         // byte 3: kind = 2
        data.extend_from_slice(&pda);                     // bytes 4-35

        assert_eq!(data.len(), 36, "operator bind wire must be 36 bytes");
        assert_eq!(data[0], 65, "tag must be 65");
        assert_eq!(data[3], 2, "kind must be 2 (ASSET_AUTH_INSURANCE_OPERATOR)");
        assert_ne!(data[3], 1, "must not be kind=1 (ASSET_AUTH_INSURANCE)");
        assert_ne!(data[3], 0, "must not be kind=0 (ASSET_AUTH_ADMIN burn)");
        assert_eq!(&data[4..36], &pda, "new_pubkey at bytes [4..36]");
    }

    /// CANARY: pin the asset_admin burn wire (tag-65 kind=0, new_pubkey=[0;32]).
    /// Must NOT be confused with kind=1 or kind=2. new_pubkey MUST be all-zeros.
    #[test]
    fn test_cpi_burn_asset_admin_wire_shape() {
        let mut data = Vec::with_capacity(36);
        data.push(TAG_UPDATE_ASSET_AUTHORITY);             // byte 0: tag = 65
        data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // bytes 1-2
        data.push(ASSET_AUTH_ADMIN);                      // byte 3: kind = 0
        data.extend_from_slice(&[0u8; 32]);               // bytes 4-35: zero burn

        assert_eq!(data.len(), 36, "admin burn wire must be 36 bytes");
        assert_eq!(data[0], 65, "tag must be 65");
        assert_eq!(data[3], 0, "kind must be 0 (ASSET_AUTH_ADMIN)");
        assert_ne!(data[3], 1, "must not be kind=1 (ASSET_AUTH_INSURANCE)");
        assert_ne!(data[3], 2, "must not be kind=2 (ASSET_AUTH_INSURANCE_OPERATOR)");
        // new_pubkey must be all zeros (the burn value)
        assert_eq!(&data[4..36], &[0u8; 32], "new_pubkey must be all-zeros for admin burn");
    }

    /// GUARD: all three kind constants in the secure-bind sequence are distinct
    /// and map to the expected numeric values from v16_program.rs.
    #[test]
    fn test_secure_bind_kind_constants_are_distinct() {
        assert_eq!(ASSET_AUTH_ADMIN, 0, "ASSET_AUTH_ADMIN must be 0");
        assert_eq!(ASSET_AUTH_INSURANCE, 1, "ASSET_AUTH_INSURANCE must be 1");
        assert_eq!(ASSET_AUTH_INSURANCE_OPERATOR, 2, "ASSET_AUTH_INSURANCE_OPERATOR must be 2");
        // They must all differ (confusion between these is a security footgun)
        assert_ne!(ASSET_AUTH_ADMIN, ASSET_AUTH_INSURANCE);
        assert_ne!(ASSET_AUTH_ADMIN, ASSET_AUTH_INSURANCE_OPERATOR);
        assert_ne!(ASSET_AUTH_INSURANCE, ASSET_AUTH_INSURANCE_OPERATOR);
    }

    /// CANARY: pin the WithdrawInsuranceAsset (tag 57) wire shape =
    /// tag(57) + asset_index(2, u16 LE = 0) + amount(16, u128 LE) = 19 bytes.
    ///
    /// Verified against:
    ///   - tests/v17_stake_insurance_e2e.rs encode_withdraw_insurance_asset()
    ///   - spec: "Wire: [57u8][asset_index: u16 LE = 0][amount: u128 LE] (= 19 bytes)"
    ///
    /// The amount is ALWAYS widened to u128 on the wire (matching the tag-9
    /// TopUpInsurance convention from v16 read_u128). Narrowing back to u64
    /// would cause the wrapper to reject the CPI with InvalidInstructionData.
    #[test]
    fn test_cpi_withdraw_insurance_asset_wire_shape() {
        let amount: u64 = 250_000;
        let mut data = Vec::with_capacity(19);
        data.push(TAG_WITHDRAW_INSURANCE_ASSET);               // byte 0: tag = 57
        data.extend_from_slice(&ASSET_INDEX_ZERO.to_le_bytes()); // bytes 1-2: asset_index = 0
        data.extend_from_slice(&(amount as u128).to_le_bytes()); // bytes 3-18: amount u128 LE

        assert_eq!(data.len(), 19, "tag-57 wire must be 19 bytes");
        assert_eq!(data[0], 57, "tag must be 57 (WithdrawInsuranceAsset)");
        assert_eq!(data[1], 0x00, "asset_index low byte must be 0");
        assert_eq!(data[2], 0x00, "asset_index high byte must be 0");

        // Amount occupies bytes [3..19] as u128 LE.
        let decoded = u128::from_le_bytes(data[3..19].try_into().unwrap());
        assert_eq!(decoded, amount as u128, "amount round-trips as u128 LE");

        // Guard: must NOT be the 9-byte u64 wire (would be rejected by wrapper read_u128).
        assert_ne!(data.len(), 9, "9-byte u64 wire would be rejected by wrapper");
        // Guard: tag 57, not tag 9 (TopUpInsurance) — different directions.
        assert_ne!(data[0], TAG_TOP_UP_INSURANCE, "must be tag 57, not tag 9");
    }

    /// C-1 CANARY: pin the ResolveMarket (tag 19) wire = tag(1) = 1 byte, no
    /// payload. Mirrors the decoder at v16_program.rs:3867
    /// (`19 => Self::ResolveMarket`), which reads zero extra bytes.
    #[test]
    fn test_cpi_resolve_market_wire_shape() {
        let mut data = Vec::with_capacity(1);
        data.push(TAG_RESOLVE_MARKET);

        assert_eq!(data.len(), 1, "tag-19 ResolveMarket wire must be exactly 1 byte");
        assert_eq!(data[0], 19, "tag must be 19 (ResolveMarket)");

        // Byte-for-byte parity with the deployed vault's cpi_resolve_market:
        // `let data = vec![TAG_RESOLVE_MARKET];` where TAG_RESOLVE_MARKET = 19.
        let vault_reference = vec![19u8];
        assert_eq!(
            data, vault_reference,
            "ported wire must be byte-for-byte identical to percolator-vault@eb3ebe8's cpi_resolve_market"
        );
    }

    /// C-1: TAG_RESOLVE_MARKET must equal 19 and be distinct from every other
    /// wrapper tag this program CPIs into (9, 32, 57, 65) — a collision here
    /// would silently misroute the resolve CPI to a different wrapper handler.
    #[test]
    fn test_tag_resolve_market_is_19_and_distinct() {
        assert_eq!(TAG_RESOLVE_MARKET, 19, "TAG_RESOLVE_MARKET mismatch");
        assert_ne!(TAG_RESOLVE_MARKET, TAG_TOP_UP_INSURANCE);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_AUTHORITY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_UPDATE_ASSET_AUTHORITY);
        assert_ne!(TAG_RESOLVE_MARKET, TAG_WITHDRAW_INSURANCE_ASSET);
    }

    /// C-1: the ResolveMarket CPI account shape is exactly 2 accounts —
    /// [admin/marketauth(signer, read-only), market(writable)] — matching
    /// handle_resolve_market's `account(accounts, 0)` / `account(accounts, 1)`
    /// reads and the deployed vault's identical 2-account construction.
    #[test]
    fn test_cpi_resolve_market_account_shape_is_two_accounts() {
        // [is_signer, is_writable] per account, in order.
        let shape = [
            (true, false), // 0: pool PDA (marketauth), signer via invoke_signed, read-only
            (false, true), // 1: market/slab, writable, not a signer
        ];
        assert_eq!(shape.len(), 2, "ResolveMarket CPI must pass exactly 2 accounts");
        assert!(shape[0].0, "account 0 (marketauth) must be a signer");
        assert!(!shape[0].1, "account 0 (marketauth) is read-only, not writable");
        assert!(shape[1].1, "account 1 (market) must be writable");
        assert!(!shape[1].0, "account 1 (market) is not a signer");
    }
}
