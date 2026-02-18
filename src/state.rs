use bytemuck::{Pod, Zeroable};
use solana_program::pubkey::Pubkey;

/// Stake pool state — one per slab (market).
/// PDA seeds: [b"stake_pool", slab_pubkey]
///
/// This PDA serves dual purpose:
/// 1. Holds the pool state (deposits, LP supply, config)
/// 2. Its pubkey becomes the ADMIN of the wrapper slab (via TransferAdmin)
///
/// The wrapper reads header.admin to authorize admin operations.
/// Since header.admin == this PDA's pubkey, the stake program can
/// invoke_signed any admin instruction on the wrapper.
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct StakePool {
    /// Whether the pool is initialized (1 = yes, 0 = no)
    pub is_initialized: u8,

    /// Bump seed for the pool PDA
    pub bump: u8,

    /// Bump seed for the vault authority PDA
    pub vault_authority_bump: u8,

    /// Whether wrapper admin has been transferred to this PDA (1 = yes)
    pub admin_transferred: u8,

    /// Padding for alignment
    pub _padding: [u8; 4],

    /// The slab (market) this pool manages
    pub slab: [u8; 32],

    /// Pool creator/admin (can update config, trigger admin CPI)
    pub admin: [u8; 32],

    /// Collateral mint (must match slab's collateral mint)
    pub collateral_mint: [u8; 32],

    /// LP token mint (owned by vault_authority PDA)
    pub lp_mint: [u8; 32],

    /// Vault holding deposited collateral buffer (owned by vault_authority PDA)
    /// Users deposit here; FlushToInsurance moves funds to wrapper insurance
    pub vault: [u8; 32],

    /// Total collateral deposited by users (lifetime, in base token units)
    pub total_deposited: u64,

    /// Total LP tokens in circulation
    pub total_lp_supply: u64,

    /// Cooldown period in slots before withdrawal is allowed
    pub cooldown_slots: u64,

    /// Maximum total deposit cap (0 = uncapped)
    pub deposit_cap: u64,

    /// Total collateral flushed to percolator insurance fund via CPI
    /// Tracks how much has been moved from stake vault → wrapper insurance
    pub total_flushed: u64,

    /// Total collateral returned from insurance (via WithdrawInsurance after resolution)
    pub total_returned: u64,

    /// Total withdrawn by users (lifetime, in base token units)
    pub total_withdrawn: u64,

    /// Percolator wrapper program ID (for CPI)
    pub percolator_program: [u8; 32],

    /// Reserved for future use
    pub _reserved: [u8; 96],
}

/// Size of StakePool in bytes
pub const STAKE_POOL_SIZE: usize = core::mem::size_of::<StakePool>();

/// Per-depositor state — tracks cooldown and LP amount per user.
/// PDA seeds: [b"stake_deposit", pool_pda, user_pubkey]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct StakeDeposit {
    /// Whether this record is initialized
    pub is_initialized: u8,

    /// Bump seed for the deposit PDA
    pub bump: u8,

    /// Padding
    pub _padding: [u8; 6],

    /// The stake pool this deposit belongs to
    pub pool: [u8; 32],

    /// The user who deposited
    pub user: [u8; 32],

    /// Slot of last deposit (cooldown starts from here)
    pub last_deposit_slot: u64,

    /// Total LP tokens held by this user (tracked for cooldown enforcement)
    pub lp_amount: u64,

    /// Reserved for future use
    pub _reserved: [u8; 64],
}

/// Size of StakeDeposit in bytes
pub const STAKE_DEPOSIT_SIZE: usize = core::mem::size_of::<StakeDeposit>();

impl StakePool {
    pub fn slab_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.slab)
    }

    pub fn admin_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.admin)
    }

    pub fn collateral_mint_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.collateral_mint)
    }

    pub fn lp_mint_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.lp_mint)
    }

    pub fn vault_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.vault)
    }

    pub fn percolator_program_pubkey(&self) -> Pubkey {
        Pubkey::new_from_array(self.percolator_program)
    }

    /// Total pool value = deposited - withdrawn.
    /// (Flushed doesn't reduce value — those funds are still owned by LP holders, just in insurance.)
    pub fn total_pool_value(&self) -> Option<u64> {
        crate::math::pool_value(self.total_deposited, self.total_withdrawn)
    }

    /// Calculate LP tokens for a deposit amount.
    /// Delegates to pure math module (Kani-verified).
    pub fn calc_lp_for_deposit(&self, amount: u64) -> Option<u64> {
        let pv = self.total_pool_value().unwrap_or(0);
        crate::math::calc_lp_for_deposit(self.total_lp_supply, pv, amount)
    }

    /// Calculate collateral for burning LP tokens.
    /// Delegates to pure math module (Kani-verified).
    /// NOTE: Actual withdrawal limited by vault balance (buffer).
    pub fn calc_collateral_for_withdraw(&self, lp_amount: u64) -> Option<u64> {
        let pv = self.total_pool_value()?;
        crate::math::calc_collateral_for_withdraw(self.total_lp_supply, pv, lp_amount)
    }
}

/// Derive the stake pool PDA for a given slab.
/// This PDA also becomes the wrapper admin after TransferAdmin.
pub fn derive_pool_pda(program_id: &Pubkey, slab: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"stake_pool", slab.as_ref()], program_id)
}

/// Derive the vault authority PDA for a given pool.
/// Controls: LP mint authority + vault token account authority.
pub fn derive_vault_authority(program_id: &Pubkey, pool: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault_auth", pool.as_ref()], program_id)
}

/// Derive the per-user deposit PDA.
pub fn derive_deposit_pda(program_id: &Pubkey, pool: &Pubkey, user: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"stake_deposit", pool.as_ref(), user.as_ref()], program_id)
}
