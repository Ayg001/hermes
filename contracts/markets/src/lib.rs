#![no_std]
#![allow(clippy::too_many_arguments)]

//! Markets contract with auth-gated entrypoints and hardened security controls.
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
    /// The primary admin / owner address.
    Admin,
    /// Whether the contract has been initialized.
    Initialized,
    /// Liquidity provided by a user to a specific market.
    Liquidity(u32, Address),
    /// Records that a winner has already claimed their payout for a market.
    /// Written **before** any token transfer in `claim_winnings` to uphold the
    /// checks-effects-interactions pattern and prevent reentrancy double-claims.
    ClaimedBet(u32, Address),
    /// Winning outcome indices recorded when a market is resolved.
    WinningOutcomes(u32),

    // ── Issue #007: Hardened Pause Keys ─────────────────────────────
    /// Counter for generating unique pause proposal IDs.
    PauseProposalCounter,
    /// Pause proposal data keyed by proposal ID.
    PauseProposal(u32),
    /// Timelock delay in seconds required before executing a pause proposal.
    PauseDelaySeconds,
    /// Number of distinct admin approvals required to execute a pause proposal.
    PauseRequiredApprovals,

    // ── Issue #022: Bet Enumeration Keys ────────────────────────────
    /// Ordered list of market IDs a user has placed bets on.
    UserBetMarkets(Address),

    // ── Issue #014: Payout Curve Keys ───────────────────────────────
    /// Payout curve configuration for a market.
    MarketPayoutCurve(u32),
    /// Total wager pool for a market.
    MarketTotalPool(u32),
    /// Total wager pool for a specific outcome index within a market.
    OutcomePool(u32, u32),

    // ── Issue #012: Dust-Safe Balance & Fee Keys ────────────────────
    /// Internal balance for a user.
    UserBalance(Address),
    /// Token contract used to fund user balances.
    TokenAddress,
    /// Minimum fee amount threshold in stroops.
    MinFeeAmount,
    /// Withdrawal fee in basis points (1 = 0.01%).
    WithdrawalFeeBps,
    /// Cumulative platform fees collected.
    CollectedFees,
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
    /// Whether the market has been cancelled.
    pub cancelled: bool,
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

/// Pause proposal record for multi-step / timelocked pause operations (#007).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PauseProposal {
    /// Sequential proposal identifier.
    pub id: u32,
    /// Admin address that created the proposal.
    pub proposer: Address,
    /// Reason or justification for the pause.
    pub reason: String,
    /// Ledger timestamp when the proposal was created.
    pub created_at: u64,
    /// Earliest ledger timestamp when the proposal may be executed.
    pub eta: u64,
    /// List of admin addresses that have approved the proposal.
    pub approvals: Vec<Address>,
    /// Whether the proposal has already been executed.
    pub executed: bool,
    /// Whether the proposal was cancelled.
    pub cancelled: bool,
}

/// Contract-level query record for a user's bet (#022).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserBetInfo {
    /// Numeric ID of the market.
    pub market_id: u32,
    /// Chosen outcome index (0-based).
    pub outcome_index: u32,
    /// Amount staked. Always positive — represented as unsigned to enforce the invariant at
    /// the type level and avoid defensive negative-value handling by callers.
    pub amount: u128,
    /// Whether winnings for this bet have already been claimed.
    pub claimed: bool,
}

/// Configurable payout curve configuration for distributing market pool funds (#014).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutCurveConfig {
    /// 0 = WinnerTakesAll, 1 = Tiered, 2 = CustomWeights
    pub curve_type: u32,
    /// Outcome index receiving runner-up credit (for Tiered).
    pub runner_up_outcome: u32,
    /// Percentage in basis points awarded to runner-up (e.g. 2000 = 20%).
    pub runner_up_bps: u32,
    /// Custom basis point weights per outcome tag (for CustomWeights).
    pub custom_weights: Vec<u32>,
}

impl PayoutCurveConfig {
    pub const WINNER_TAKES_ALL: u32 = 0;
    pub const TIERED: u32 = 1;
    pub const CUSTOM_WEIGHTS: u32 = 2;

    pub fn winner_takes_all(env: &Env) -> Self {
        Self {
            curve_type: Self::WINNER_TAKES_ALL,
            runner_up_outcome: 0,
            runner_up_bps: 0,
            custom_weights: Vec::new(env),
        }
    }

    pub fn tiered(env: &Env, runner_up_outcome: u32, runner_up_bps: u32) -> Self {
        Self {
            curve_type: Self::TIERED,
            runner_up_outcome,
            runner_up_bps,
            custom_weights: Vec::new(env),
        }
    }

    pub fn custom_weights(weights: Vec<u32>) -> Self {
        Self {
            curve_type: Self::CUSTOM_WEIGHTS,
            runner_up_outcome: 0,
            runner_up_bps: 0,
            custom_weights: weights,
        }
    }
}

/// Result of a dust-safe user balance withdrawal (#012).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalResult {
    /// Net amount received by the user.
    pub net_amount: i128,
    /// Fee deducted (0 if dust waiver applied).
    pub fee_deducted: i128,
    /// Remaining balance in the contract.
    pub remaining_balance: i128,
}

pub mod admin;

#[contract]
pub struct MarketsContract;

impl MarketsContract {
    // -----------------------------------------------------------------------
    //  Internal Helpers
    // -----------------------------------------------------------------------

    fn is_admin_internal(env: &Env, caller: &Address) -> bool {
        if let Some(admin) = env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::Admin)
        {
            if &admin == caller {
                return true;
            }
        } else {
            // First caller with admin action becomes initial admin if unset.
            return true;
        }

        let admin_list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AdminList)
            .unwrap_or(Vec::new(env));
        admin_list.contains(caller)
    }

    fn require_admin(env: &Env, caller: &Address) {
        caller.require_auth();
        if !Self::is_admin_internal(env, caller) {
            panic_with_error!(env, ContractError::Unauthorized);
        }
    }

    fn validate_payout_curve(env: &Env, curve: &PayoutCurveConfig, num_outcomes: u32) {
        match curve.curve_type {
            PayoutCurveConfig::WINNER_TAKES_ALL => {}
            PayoutCurveConfig::TIERED => {
                if curve.runner_up_outcome >= num_outcomes {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
                if curve.runner_up_bps == 0 || curve.runner_up_bps >= 10_000 {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
            }
            PayoutCurveConfig::CUSTOM_WEIGHTS => {
                if curve.custom_weights.len() != num_outcomes {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
                let mut sum: u32 = 0;
                for w in curve.custom_weights.iter() {
                    sum = match sum.checked_add(w) {
                        Some(s) => s,
                        None => panic_with_error!(env, ContractError::InvalidPayoutCurve),
                    };
                }
                if sum == 0 || sum > 10_000 {
                    panic_with_error!(env, ContractError::InvalidPayoutCurve);
                }
            }
            _ => panic_with_error!(env, ContractError::InvalidPayoutCurve),
        }
    }

    fn winning_outcomes(env: &Env, market_id: u32, market: &MarketData) -> Vec<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::WinningOutcomes(market_id))
            .unwrap_or_else(|| {
                let mut outcomes = Vec::new(env);
                if market.resolved {
                    outcomes.push_back(market.winning_outcome);
                }
                outcomes
            })
    }
}

#[contractimpl]
impl MarketsContract {
    // -----------------------------------------------------------------------
    //  Read-only Entrypoints
    // -----------------------------------------------------------------------

    /// @notice Returns the contract version.
    pub fn version(_env: Env) -> u32 {
        7
    }

    /// @notice Read a market from persistent storage and bump its TTL.
    pub fn get_market(env: Env, market_id: soroban_sdk::Symbol) -> Option<soroban_sdk::Val> {
        let market: Option<soroban_sdk::Val> = env.storage().persistent().get(&market_id);
        if market.is_some() {
            env.storage()
                .persistent()
                .extend_ttl(&market_id, 6307200, 6307200);
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
