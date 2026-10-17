use markets::{MarketsContract, MarketsContractClient};
use resolution::{
    errors::ContractError, ResolutionContract, ResolutionContractClient, ResolutionStatus,
};
use soroban_sdk::{contract, contractimpl, testutils::Address as _, Address, Env, Vec};

#[contract]
struct MockOracle;

#[contractimpl]
impl MockOracle {
    pub fn set_result(env: Env, market_id: u32, result: Option<Vec<u32>>) {
        env.storage().persistent().set(&market_id, &result);
    }

    pub fn get_result(env: Env, market_id: u32) -> Option<Vec<u32>> {
        env.storage().persistent().get(&market_id)
    }
}

struct Fixture {
    env: Env,
    resolver: Address,
    admin: Address,
    resolution_id: Address,
    markets_id: Address,
    oracle_id: Address,
}

impl Fixture {
    fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let resolver = Address::generate(&env);

        let markets_id = env.register(MarketsContract, ());
        let resolution_id = env.register(ResolutionContract, ());
        let oracle_id = env.register(MockOracle, ());

        let resolution = ResolutionContractClient::new(&env, &resolution_id);
        resolution.initialize(&admin);
        resolution.set_integrations(&admin, &markets_id, &oracle_id);

        Self {
            env,
            resolver,
            admin,
            resolution_id,
            markets_id,
            oracle_id,
        }
    }

    fn resolution(&self) -> ResolutionContractClient<'_> {
        ResolutionContractClient::new(&self.env, &self.resolution_id)
    }

    fn markets(&self) -> MarketsContractClient<'_> {
        MarketsContractClient::new(&self.env, &self.markets_id)
    }

    fn create_market(&self) -> u32 {
        self.create_market_ending_at(self.env.ledger().timestamp())
    }

    fn create_market_ending_at(&self, end_time: u64) -> u32 {
        let outcomes = Vec::from_array(
            &self.env,
            [
                soroban_sdk::String::from_str(&self.env, "yes"),
                soroban_sdk::String::from_str(&self.env, "no"),
                soroban_sdk::String::from_str(&self.env, "maybe"),
            ],
        );
        self.markets().create_market(
            &self.resolver,
            &soroban_sdk::String::from_str(&self.env, "Will it happen?"),
            &soroban_sdk::String::from_str(&self.env, "Test market"),
            &end_time,
            &soroban_sdk::String::from_str(&self.env, "oracle"),
            &outcomes,
        )
    }

    fn set_oracle_result(&self, market_id: u32, result: Option<Vec<u32>>) {
        let oracle = MockOracleClient::new(&self.env, &self.oracle_id);
        oracle.set_result(&market_id, &result);
    }
}

#[test]
fn resolves_market_and_persists_status_and_all_winning_outcomes() {
    let fixture = Fixture::new();
    let market_id = fixture.create_market();
    fixture.set_oracle_result(market_id, Some(Vec::from_array(&fixture.env, [0, 2])));

    let status = fixture
        .resolution()
        .resolve_market(&fixture.resolver, &market_id);

    assert_eq!(
        status,
        ResolutionStatus {
            market_id,
            winning_outcomes: Vec::from_array(&fixture.env, [0, 2]),
            resolved_at: fixture.env.ledger().timestamp(),
            oracle: fixture.oracle_id,
        }
    );
    assert_eq!(
        fixture.resolution().get_resolution_status(&market_id),
        Some(status)
    );
    assert_eq!(
        fixture.markets().get_winning_outcomes(&market_id),
        Some(Vec::from_array(&fixture.env, [0, 2]))
    );
}

#[test]
fn rejects_missing_oracle_results() {
    let fixture = Fixture::new();
    let market_id = fixture.create_market();
    fixture.set_oracle_result(market_id, None);

    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &market_id),
        Err(Ok(ContractError::OracleResultNotAvailable))
    );
}

#[test]
fn rejects_market_that_has_not_closed() {
    let fixture = Fixture::new();
    let market_id = fixture.create_market_ending_at(fixture.env.ledger().timestamp() + 1);
    fixture.set_oracle_result(market_id, Some(Vec::from_array(&fixture.env, [0])));

    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &market_id),
        Err(Ok(ContractError::MarketClosed))
    );
}

#[test]
fn rejects_unknown_market_and_unauthorized_configuration() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &u32::MAX),
        Err(Ok(ContractError::MarketNotFound))
    );

    let unauthorized_admin = Address::generate(&fixture.env);
    assert_eq!(
        fixture.resolution().try_set_integrations(
            &unauthorized_admin,
            &fixture.markets_id,
            &fixture.oracle_id
        ),
        Err(Ok(ContractError::Unauthorized))
    );
}

#[test]
fn rejects_non_creator_resolution() {
    let fixture = Fixture::new();
    let market_id = fixture.create_market();
    let other_resolver = Address::generate(&fixture.env);

    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&other_resolver, &market_id),
        Err(Ok(ContractError::Unauthorized))
    );
}

#[test]
fn rejects_duplicate_and_out_of_range_winners() {
    let fixture = Fixture::new();
    let duplicate_market = fixture.create_market();
    fixture.set_oracle_result(
        duplicate_market,
        Some(Vec::from_array(&fixture.env, [0, 0])),
    );
    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &duplicate_market),
        Err(Ok(ContractError::InvalidWinningOutcomes))
    );

    let invalid_market = fixture.create_market();
    fixture.set_oracle_result(invalid_market, Some(Vec::from_array(&fixture.env, [3])));
    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &invalid_market),
        Err(Ok(ContractError::InvalidOutcome))
    );

    let empty_market = fixture.create_market();
    fixture.set_oracle_result(empty_market, Some(Vec::new(&fixture.env)));
    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &empty_market),
        Err(Ok(ContractError::InvalidWinningOutcomes))
    );
}

#[test]
fn enforces_cooldown_per_resolver() {
    let fixture = Fixture::new();
    fixture
        .resolution()
        .set_resolution_cooldown(&fixture.admin, &60);
    let first_market = fixture.create_market();
    fixture.set_oracle_result(first_market, Some(Vec::from_array(&fixture.env, [0])));
    fixture
        .resolution()
        .resolve_market(&fixture.resolver, &first_market);

    let second_market = fixture.create_market();
    fixture.set_oracle_result(second_market, Some(Vec::from_array(&fixture.env, [1])));
    assert_eq!(
        fixture
            .resolution()
            .try_resolve_market(&fixture.resolver, &second_market),
        Err(Ok(ContractError::ResolutionCooldownActive))
    );
}
