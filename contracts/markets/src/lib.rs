#![no_std]

//! Markets contract with auth-gated entrypoints.
//!
//! Provides a prediction-market subsystem where every state-changing
//! entrypoint enforces `require_auth` on the acting [`Address`].
//!
//! # Auth Matrix
//!
//! | Function               | Required Role              |
//! |------------------------|----------------------------|
//! | `initialize`           | Admin (one-time)           |
//! | `create_market`        | Creator (any address)      |
//! | `place_bet`            | Bettor (any address)       |
//! | `resolve_market`       | Market creator             |
//! | `claim_winnings`       | Winner (bettor)            |
//! | `cancel_market`        | Market creator             |
//! | `withdraw_funds`       | Market creator             |
//! | `update_market_params` | Market creator             |
//! | `add_liquidity`        | Liquidity provider         |
//! | `remove_liquidity`     | Liquidity provider         |
//! | `pause_markets`        | Admin                      |
//! | `unpause_markets`      | Admin                      |
//! | `transfer_ownership`   | Admin                      |
//! | `add_admin`            | Admin                      |
//! | `get_admin`            | Anyone (read-only)         |
//! | `is_paused`            | Anyone (read-only)         |
//! | `version`              | Anyone (read-only)         |

pub mod errors;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

pub use errors::ContractError;

/// Type alias used by generated client code and test harnesses.
pub type Error = ContractError;

/// Persistent-storage keys used by the Markets contract.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Sequential counter for generating unique market IDs.
    MarketCounter,
    /// Market data keyed by the numeric market ID.
    Market(u32),
    /// Bet placed by a user on a specific market.
    Bet(u32, Address),
    /// Whether the markets subsystem is globally paused (`true` = paused).
    Paused,
    /// The admin / owner address.
    Admin,
    /// Whether the contract has been initialized.
    Initialized,
    /// Liquidity provided by a user to a specific market.
    Liquidity(u32, Address),
}

/// On-chain representation of a prediction market.
#[contracttype]
#[derive(Clone)]
pub struct MarketData {
    /// The address that created the market.
    pub creator: Address,
    /// The prediction question.
    pub question: String,
    /// A human-readable description of the market.
    pub description: String,
    /// Unix timestamp (seconds) when betting closes.
    pub end_time: u64,
    /// Identifies the data source used at resolution time.
    pub resolution_source: String,
    /// Ordered list of possible outcomes.
    pub outcome_tags: Vec<String>,
    /// Whether a winning outcome has been recorded.
    pub resolved: bool,
    /// Index (0-based) of the winning outcome.
    pub winning_outcome: u32,
}

/// On-chain record of a user's bet on a market.
#[contracttype]
#[derive(Clone)]
pub struct BetData {
    /// Index of the selected outcome.
    pub outcome_index: u32,
    /// Amount staked in the platform's base unit.
    pub amount: i128,
}

/// Tracks how much liquidity a user has added to a market.
#[contracttype]
#[derive(Clone)]
pub struct LiquidityData {
    /// Total amount of liquidity provided.
    pub total_amount: i128,
}

pub mod admin;

#[contract]
pub struct MarketsContract;

#[contractimpl]
impl MarketsContract {
    // -----------------------------------------------------------------------
    //  Read-only
    // -----------------------------------------------------------------------

    /// @notice Returns the contract version.
    /// @dev This is a read-only introspection entrypoint that does **not** require authentication.
    /// @param _env The contract environment.
    /// @return The version number as u32.
    pub fn version(_env: Env) -> u32 {
        7
    }

    /// @notice Read a market from persistent storage and bump its TTL.
    /// @param env The contract environment.
    /// @param market_id The unique symbol identifying the market.
    /// @return An optional value containing the market data if it exists.
    pub fn get_market(env: Env, market_id: soroban_sdk::Symbol) -> Option<soroban_sdk::Val> {
        let market: Option<soroban_sdk::Val> = env.storage().persistent().get(&market_id);
        if market.is_some() {
            // Bump TTL: 365 days * 17280 ledgers per day = 6307200
            env.storage().persistent().extend_ttl(&market_id, 6307200, 6307200);
        }
        market
    }

    // -----------------------------------------------------------------------
    //  Initialization
    // -----------------------------------------------------------------------

    /// @notice Initializes the contract by setting the initial admin.
    /// @dev    Stores `DataKey::Admin` and `DataKey::Initialized` atomically.
    ///         Must be called exactly once after deployment before any admin
    ///         entrypoint can be used.
    /// @param env   The contract environment.
    /// @param admin The initial admin/owner address.
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        // Require the caller to authenticate before any state mutation.
        admin.require_auth();

        // Prevent re-initialization.
        if Self::is_initialized(&env) {
            return Err(ContractError::AdminOperationNotPermitted);
        }

        env.storage().instance().set(&DataKey::Initialized, &true);
        env.storage().instance().set(&DataKey::Admin, &admin);
        // Markets start unpaused.
        env.storage().instance().set(&DataKey::Paused, &false);

        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Admin-gated entrypoints
    // -----------------------------------------------------------------------

    /// @notice Pauses all markets globally.
    /// @dev    Requires the caller to be the registered admin.
    /// @param env    The contract environment.
    /// @param caller The admin address (must pass auth and admin check).
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn pause_markets(env: Env, caller: Address) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_is_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        Ok(())
    }

    /// @notice Unpauses all markets globally.
    /// @dev    Requires the caller to be the registered admin.
    /// @param env    The contract environment.
    /// @param caller The admin address (must pass auth and admin check).
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn unpause_markets(env: Env, caller: Address) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_is_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        Ok(())
    }

    /// @notice Transfers contract ownership to a new admin address.
    /// @dev    Requires the caller to be the registered admin. The new admin
    ///         must differ from the current admin.
    /// @param env         The contract environment.
    /// @param current_admin The current admin (must pass auth and admin check).
    /// @param new_admin    The new admin address to set.
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn transfer_ownership(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        current_admin.require_auth();
        Self::assert_is_admin(&env, &current_admin)?;

        if new_admin == current_admin {
            return Err(ContractError::AdminAddressInvalid);
        }

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    /// @notice Adds a second admin address (co-admin).
    /// @dev    Requires the caller to be the registered admin. Currently only
    ///         stores a single admin; this entrypoint replaces the admin with
    ///         the new address and is kept for forward compatibility with a
    ///         multi-admin model.
    /// @param env        The contract environment.
    /// @param caller     The current admin (must pass auth and admin check).
    /// @param new_admin  The admin address to add.
    /// @return `Ok(())` on success, or a [`ContractError`] variant.
    pub fn add_admin(
        env: Env,
        caller: Address,
        new_admin: Address,
    ) -> Result<(), ContractError> {
        caller.require_auth();
        Self::assert_is_admin(&env, &caller)?;

        if new_admin == caller {
            return Err(ContractError::AdminAddressInvalid);
        }

        // Store the new admin alongside the existing admin.
        // For now we support a single admin; this entrypoint replaces it.
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Read-only admin queries
    // -----------------------------------------------------------------------

    /// @notice Returns the current admin address.
    /// @dev    Read-only — does not require auth. Returns `None` if not set.
    /// @param env The contract environment.
    /// @return `Some(Address)` if an admin is set, `None` otherwise.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// @notice Returns whether the markets subsystem is globally paused.
    /// @dev    Read-only — does not require auth.
    /// @param env The contract environment.
    /// @return `true` if paused, `false` otherwise.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    // -----------------------------------------------------------------------
    //  Internal helpers
    // -----------------------------------------------------------------------

    /// @notice Returns `true` if the contract has been initialized.
    fn is_initialized(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Initialized)
            .unwrap_or(false)
    }

    /// @notice Returns the stored admin address, or `None` if unset.
    fn get_admin_internal(env: &Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Admin)
    }

    /// @notice Checks whether `caller` is the registered admin.
    /// @dev    Returns `false` when no admin is stored (does **not** return
    ///         `true` for an unset admin — this closes the bootstrap hole).
    /// @param env    The contract environment.
    /// @param caller The address to check.
    /// @return `true` if the caller matches the stored admin, `false` otherwise.
    fn is_admin_internal(env: &Env, caller: &Address) -> bool {
        match Self::get_admin_internal(env) {
            Some(admin) => admin == *caller,
            None => false,
        }
    }

    /// @notice Asserts that `caller` is the registered admin.
    /// @dev    Returns `Err(ContractError::Unauthorized)` when the admin is
    ///         unset or the caller does not match.
    /// @param env    The contract environment.
    /// @param caller The address to verify.
    /// @return `Ok(())` if the caller is the admin, or a [`ContractError`].
    fn assert_is_admin(env: &Env, caller: &Address) -> Result<(), ContractError> {
        if !Self::is_admin_internal(env, caller) {
            return Err(ContractError::Unauthorized);
        }
        Ok(())
    }

}
