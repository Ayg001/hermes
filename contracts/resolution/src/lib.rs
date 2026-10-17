#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Env, IntoVal, Map, Symbol, Vec,
};

pub mod errors;

use errors::ContractError;

const COOLDOWN_TTL_LEDGERS: u32 = 535_680;
const RESOLUTION_TTL_LEDGERS: u32 = 6_307_200;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    MarketsContract,
    OracleContract,
    ResolutionCooldownSeconds,
    LastResolution(Address),
    ResolutionStatus(u32),
}

/// Status returned by resolution queries and successful resolutions.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionStatus {
    pub market_id: u32,
    pub winning_outcomes: Vec<u32>,
    pub resolved_at: u64,
    pub oracle: Address,
}

#[contract]
pub struct ResolutionContract;

impl ResolutionContract {
    fn extend_ttl(env: &Env, key: &DataKey, desired_ttl: u32) {
        let ttl = desired_ttl.min(env.storage().max_ttl());
        env.storage().persistent().extend_ttl(key, ttl, ttl);
    }

    fn require_admin(env: &Env, admin: &Address) {
        admin.require_auth();
        if env.storage().persistent().has(&DataKey::Admin) {
            Self::extend_ttl(env, &DataKey::Admin, COOLDOWN_TTL_LEDGERS);
        }
        let configured_admin: Option<Address> = env.storage().persistent().get(&DataKey::Admin);
        if configured_admin.as_ref() != Some(admin) {
            panic_with_error!(env, ContractError::Unauthorized);
        }
    }

    fn check_cooldown(env: &Env, resolver: &Address) -> Result<(), ContractError> {
        let cooldown: u64 = if env
            .storage()
            .persistent()
            .has(&DataKey::ResolutionCooldownSeconds)
        {
            Self::extend_ttl(
                env,
                &DataKey::ResolutionCooldownSeconds,
                COOLDOWN_TTL_LEDGERS,
            );
            env.storage()
                .persistent()
                .get(&DataKey::ResolutionCooldownSeconds)
                .unwrap_or(0)
        } else {
            0
        };
        let key = DataKey::LastResolution(resolver.clone());
        if let Some(last_resolution) = env.storage().persistent().get::<_, u64>(&key) {
            Self::extend_ttl(env, &key, COOLDOWN_TTL_LEDGERS);
            if cooldown > 0 && env.ledger().timestamp() < last_resolution.saturating_add(cooldown) {
                return Err(ContractError::ResolutionCooldownActive);
            }
        }
        Ok(())
    }
}

#[contractimpl]
impl ResolutionContract {
    /// Returns the contract version for the resolution subsystem.
    pub fn version(_env: Env) -> u32 {
        7
    }

    /// Initialize the administrator that configures market and oracle contracts.
    pub fn initialize(env: Env, admin: Address) -> Result<(), ContractError> {
        admin.require_auth();
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(ContractError::InvalidState);
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        Self::extend_ttl(&env, &DataKey::Admin, COOLDOWN_TTL_LEDGERS);
        Ok(())
    }

    /// Configure the contracts used to read markets and oracle results.
    pub fn set_integrations(
        env: Env,
        admin: Address,
        markets_contract: Address,
        oracle_contract: Address,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::MarketsContract, &markets_contract);
        env.storage()
            .persistent()
            .set(&DataKey::OracleContract, &oracle_contract);
        Self::extend_ttl(&env, &DataKey::MarketsContract, COOLDOWN_TTL_LEDGERS);
        Self::extend_ttl(&env, &DataKey::OracleContract, COOLDOWN_TTL_LEDGERS);
        Ok(())
    }

    /// Set the minimum time between successful resolutions by the same resolver.
    pub fn set_resolution_cooldown(
        env: Env,
        admin: Address,
        seconds: u64,
    ) -> Result<(), ContractError> {
        Self::require_admin(&env, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ResolutionCooldownSeconds, &seconds);
        Self::extend_ttl(
            &env,
            &DataKey::ResolutionCooldownSeconds,
            COOLDOWN_TTL_LEDGERS,
        );
        Ok(())
    }

    /// Resolve a market from the configured oracle's result.
    ///
    /// The oracle must expose `get_result(market_id) -> Option<Vec<u32>>`.
    /// The market contract must expose `get_market_for_resolution(market_id)`
    /// and `resolve_market_with_outcomes(resolver, market_id, outcomes)`.
    pub fn resolve_market(
        env: Env,
        resolver: Address,
        market_id: u32,
    ) -> Result<ResolutionStatus, ContractError> {
        resolver.require_auth();
        if env.storage().persistent().has(&DataKey::Admin) {
            Self::extend_ttl(&env, &DataKey::Admin, COOLDOWN_TTL_LEDGERS);
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::ResolutionStatus(market_id))
        {
            return Err(ContractError::MarketAlreadyResolved);
        }
        let markets_contract: Address = env
            .storage()
            .persistent()
            .get(&DataKey::MarketsContract)
            .ok_or(ContractError::InvalidState)?;
        Self::extend_ttl(&env, &DataKey::MarketsContract, COOLDOWN_TTL_LEDGERS);
        let oracle_contract: Address = env
            .storage()
            .persistent()
            .get(&DataKey::OracleContract)
            .ok_or(ContractError::InvalidState)?;
        Self::extend_ttl(&env, &DataKey::OracleContract, COOLDOWN_TTL_LEDGERS);

        let market = match env
            .try_invoke_contract::<Option<(Address, u64, u32, bool, bool)>, soroban_sdk::Error>(
                &markets_contract,
                &Symbol::new(&env, "get_market_for_resolution"),
                soroban_sdk::vec![&env, market_id.into()],
            ) {
            Ok(Ok(Some(market))) => market,
            Ok(Ok(None)) => return Err(ContractError::MarketNotFound),
            _ => return Err(ContractError::InvalidState),
        };
        let (market_creator, market_end_time, outcome_count, resolved, cancelled) = market;
        if resolver != market_creator {
            return Err(ContractError::Unauthorized);
        }
        if resolved {
            return Err(ContractError::MarketAlreadyResolved);
        }
        if cancelled {
            return Err(ContractError::InvalidState);
        }
        if env.ledger().timestamp() < market_end_time {
            return Err(ContractError::MarketClosed);
        }
        Self::check_cooldown(&env, &resolver)?;

        let winning_outcomes = match env
            .try_invoke_contract::<Option<Vec<u32>>, soroban_sdk::Error>(
                &oracle_contract,
                &Symbol::new(&env, "get_result"),
                soroban_sdk::vec![&env, market_id.into()],
            ) {
            Ok(Ok(Some(result))) => result,
            _ => return Err(ContractError::OracleResultNotAvailable),
        };
        if winning_outcomes.is_empty() {
            return Err(ContractError::InvalidWinningOutcomes);
        }

        if winning_outcomes.len() > outcome_count {
            return Err(ContractError::InvalidWinningOutcomes);
        }
        let mut seen = Map::<u32, bool>::new(&env);
        for outcome in winning_outcomes.iter() {
            if outcome >= outcome_count {
                return Err(ContractError::InvalidOutcome);
            }
            if seen.contains_key(outcome) {
                return Err(ContractError::InvalidWinningOutcomes);
            }
            seen.set(outcome, true);
        }

        env.invoke_contract::<()>(
            &markets_contract,
            &Symbol::new(&env, "resolve_market_with_outcomes"),
            soroban_sdk::vec![
                &env,
                resolver.clone().into_val(&env),
                market_id.into(),
                winning_outcomes.clone().into(),
            ],
        );

        let status = ResolutionStatus {
            market_id,
            winning_outcomes,
            resolved_at: env.ledger().timestamp(),
            oracle: oracle_contract,
        };
        env.storage()
            .persistent()
            .set(&DataKey::ResolutionStatus(market_id), &status);
        Self::extend_ttl(
            &env,
            &DataKey::ResolutionStatus(market_id),
            RESOLUTION_TTL_LEDGERS,
        );

        let cooldown_key = DataKey::LastResolution(resolver);
        env.storage()
            .persistent()
            .set(&cooldown_key, &status.resolved_at);
        Self::extend_ttl(&env, &cooldown_key, COOLDOWN_TTL_LEDGERS);

        Ok(status)
    }

    /// Return the recorded resolution details, if the market has been resolved.
    pub fn get_resolution_status(env: Env, market_id: u32) -> Option<ResolutionStatus> {
        let key = DataKey::ResolutionStatus(market_id);
        let status: Option<ResolutionStatus> = env.storage().persistent().get(&key);
        if status.is_some() {
            Self::extend_ttl(&env, &key, RESOLUTION_TTL_LEDGERS);
        }
        status
    }
}
