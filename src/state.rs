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

    /// Total pool value = deposited - withdrawn - flushed + returned.
    ///
    /// This equals the actual vault balance and reflects what LP holders can withdraw.
    /// - Flushed tokens leave the vault (moved to wrapper insurance).
    /// - Returned tokens come back to vault (withdrawn from insurance after resolution).
    ///
    /// IMPORTANT: Do NOT use `deposited - withdrawn + returned` — that double-counts
    /// because returned tokens are already in the vault, and deposited conceptually
    /// includes the flushed amount. Missing `-flushed` causes phantom inflation
    /// that makes the pool insolvent after any flush+return cycle.
    pub fn total_pool_value(&self) -> Option<u64> {
        self.total_deposited
            .checked_sub(self.total_withdrawn)?
            .checked_sub(self.total_flushed)?
            .checked_add(self.total_returned)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_pool_size() {
        // Ensure struct is packed correctly (no surprise padding)
        assert_eq!(STAKE_POOL_SIZE, std::mem::size_of::<StakePool>());
        // Check expected size: 1+1+1+1+4 + 5*32 + 7*8 + 32 + 96 = 8 + 160 + 56 + 32 + 96 = 352
        assert_eq!(STAKE_POOL_SIZE, 352);
    }

    #[test]
    fn test_stake_deposit_size() {
        assert_eq!(STAKE_DEPOSIT_SIZE, std::mem::size_of::<StakeDeposit>());
        // 1+1+6 + 2*32 + 2*8 + 64 = 8 + 64 + 16 + 64 = 152
        assert_eq!(STAKE_DEPOSIT_SIZE, 152);
    }

    #[test]
    fn test_pool_value_normal() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 1000;
        pool.total_withdrawn = 300;
        pool.total_flushed = 0;
        pool.total_returned = 0;
        assert_eq!(pool.total_pool_value(), Some(700));
    }

    #[test]
    fn test_pool_value_with_flush() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 1000;
        pool.total_withdrawn = 0;
        pool.total_flushed = 500;
        pool.total_returned = 0;
        // Flushed reduces accessible value: 1000 - 0 - 500 + 0 = 500
        assert_eq!(pool.total_pool_value(), Some(500));
    }

    #[test]
    fn test_pool_value_with_flush_and_returns() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 1000;
        pool.total_withdrawn = 300;
        pool.total_flushed = 500;
        pool.total_returned = 200;
        // 1000 - 300 - 500 + 200 = 400
        assert_eq!(pool.total_pool_value(), Some(400));
    }

    #[test]
    fn test_pool_value_full_return_conservation() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 1000;
        pool.total_withdrawn = 0;
        pool.total_flushed = 500;
        pool.total_returned = 500;
        // Full return: 1000 - 0 - 500 + 500 = 1000 (back to original)
        assert_eq!(pool.total_pool_value(), Some(1000));
    }

    #[test]
    fn test_pool_value_overdrawn() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 100;
        pool.total_withdrawn = 200;
        assert_eq!(pool.total_pool_value(), None);
    }

    #[test]
    fn test_pool_value_overflushed() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 1000;
        pool.total_withdrawn = 0;
        pool.total_flushed = 1001;
        // Can't flush more than deposited-withdrawn → None
        assert_eq!(pool.total_pool_value(), None);
    }

    #[test]
    fn test_calc_lp_first_depositor() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 0;
        pool.total_withdrawn = 0;
        pool.total_lp_supply = 0;
        assert_eq!(pool.calc_lp_for_deposit(1000), Some(1000));
    }

    #[test]
    fn test_calc_lp_pro_rata() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 2000;
        pool.total_withdrawn = 0;
        pool.total_lp_supply = 1000;
        // deposit 500 → 500 * 1000 / 2000 = 250
        assert_eq!(pool.calc_lp_for_deposit(500), Some(250));
    }

    #[test]
    fn test_calc_collateral_proportional() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = 2000;
        pool.total_withdrawn = 0;
        pool.total_lp_supply = 1000;
        // burn 250 LP → 250 * 2000 / 1000 = 500
        assert_eq!(pool.calc_collateral_for_withdraw(250), Some(500));
    }

    #[test]
    fn test_pda_derivation_deterministic() {
        let program_id = Pubkey::new_unique();
        let slab = Pubkey::new_unique();

        let (pda1, bump1) = derive_pool_pda(&program_id, &slab);
        let (pda2, bump2) = derive_pool_pda(&program_id, &slab);
        assert_eq!(pda1, pda2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn test_pda_different_slabs_different_pdas() {
        let program_id = Pubkey::new_unique();
        let slab1 = Pubkey::new_unique();
        let slab2 = Pubkey::new_unique();

        let (pda1, _) = derive_pool_pda(&program_id, &slab1);
        let (pda2, _) = derive_pool_pda(&program_id, &slab2);
        assert_ne!(pda1, pda2);
    }

    #[test]
    fn test_vault_auth_derives_from_pool() {
        let program_id = Pubkey::new_unique();
        let slab = Pubkey::new_unique();

        let (pool_pda, _) = derive_pool_pda(&program_id, &slab);
        let (vault_auth, _) = derive_vault_authority(&program_id, &pool_pda);

        // vault_auth should be different from pool
        assert_ne!(vault_auth, pool_pda);

        // Should be deterministic
        let (vault_auth2, _) = derive_vault_authority(&program_id, &pool_pda);
        assert_eq!(vault_auth, vault_auth2);
    }

    #[test]
    fn test_deposit_pda_per_user() {
        let program_id = Pubkey::new_unique();
        let pool = Pubkey::new_unique();
        let user1 = Pubkey::new_unique();
        let user2 = Pubkey::new_unique();

        let (dep1, _) = derive_deposit_pda(&program_id, &pool, &user1);
        let (dep2, _) = derive_deposit_pda(&program_id, &pool, &user2);
        assert_ne!(dep1, dep2);
    }

    #[test]
    fn test_deposit_pda_per_pool() {
        let program_id = Pubkey::new_unique();
        let pool1 = Pubkey::new_unique();
        let pool2 = Pubkey::new_unique();
        let user = Pubkey::new_unique();

        let (dep1, _) = derive_deposit_pda(&program_id, &pool1, &user);
        let (dep2, _) = derive_deposit_pda(&program_id, &pool2, &user);
        assert_ne!(dep1, dep2);
    }

    #[test]
    fn test_pubkey_helpers() {
        let mut pool = StakePool::zeroed();
        let key = Pubkey::new_unique();
        pool.slab = key.to_bytes();
        assert_eq!(pool.slab_pubkey(), key);

        let admin = Pubkey::new_unique();
        pool.admin = admin.to_bytes();
        assert_eq!(pool.admin_pubkey(), admin);
    }

    #[test]
    fn test_pool_value_returns_overflow() {
        let mut pool = StakePool::zeroed();
        pool.total_deposited = u64::MAX;
        pool.total_withdrawn = 0;
        pool.total_flushed = 0;
        pool.total_returned = 1;
        // u64::MAX - 0 - 0 + 1 overflows → None
        assert_eq!(pool.total_pool_value(), None);
    }
}
