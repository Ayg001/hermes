# Contributing to Hermes

Thank you for contributing! This document covers the development workflow,
testing requirements, and operational scripts you need to know about.

## Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain, `wasm32v1-none` target)
- [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/install-stellar-cli)
- `sha256sum` (standard on Linux; `brew install coreutils` on macOS)

## Running Tests

```bash
cargo test --workspace
```

Auth boundary tests for individual contracts can be run with:

```bash
cargo test --test auth_boundary -- --nocapture
```

## Verifying Contract Sync

`scripts/verify_contract_sync.sh` checks that a locally-built WASM artifact
matches the bytecode currently deployed on staging and production. Run it after
any deployment, or before merging a release branch, to detect contract drift.

```bash
CONTRACT=markets \
STAGING_CONTRACT_ID=<staging-contract-id> \
PRODUCTION_CONTRACT_ID=<production-contract-id> \
./scripts/verify_contract_sync.sh
```

Pass `--help` for the full list of options:

```bash
./scripts/verify_contract_sync.sh --help
```

The script requires `cargo`, `stellar`, and `sha256sum` to be available on
your `PATH`. It builds the contract in release mode, fetches the deployed
bytecode via the Stellar CLI, and compares SHA-256 hashes. A non-zero exit
code means the deployed contract does not match the local build.

## Pull Request Guidelines

- Keep PRs focused on a single concern.
- All CI checks (tests + snapshot goldens) must pass before merge.
- Do not push directly to `main`; open a pull request instead.
- For contract changes, run `verify_contract_sync.sh` post-deploy and attach
  the output to your PR description.
