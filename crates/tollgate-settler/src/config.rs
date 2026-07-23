//! Operator configuration for the settlement worker, sourced from the environment.
//!
//! Three knobs, all REQUIRED and none defaulted: the settler moves real money on a
//! real chain, so there is no "sensible default" for the ledger it drains, the RPC
//! it talks to, or the key it signs with. A missing one is a startup error, not a
//! silently-assumed testnet.

use std::env;

use alloy::signers::local::PrivateKeySigner;

/// Postgres connection URL of the claims ledger to settle from.
const ENV_DATABASE_URL: &str = "TOLLGATE_DATABASE_URL";
/// JSON-RPC endpoint for the settlement chain.
const ENV_RPC_URL: &str = "TOLLGATE_RPC_URL";
/// Hex-encoded secp256k1 private key of the account that pays the gas.
const ENV_SIGNER_KEY: &str = "TOLLGATE_SIGNER_KEY";

/// Fully-resolved settler configuration, built once at startup.
///
/// Deliberately NOT `Debug`, for the same reason `PgClaimLedger` is not
/// (ADR-0034): every field here is a credential or carries one — the database URL
/// holds a password, the RPC URL holds an API key, and the signer holds the key
/// that can spend the operator's gas. `{cfg:?}` must be a COMPILE ERROR rather
/// than a judgement call at some future log site.
pub struct SettlerConfig {
    /// Connection URL for the claims ledger. Held only until `main` hands it to
    /// `PgClaimLedger::connect`, which never stores it.
    pub database_url: String,
    /// JSON-RPC endpoint. Held only until it is handed to
    /// [`SettlementClient::connect`](crate::chain::SettlementClient::connect),
    /// which likewise keeps the provider and not the URL.
    pub rpc_url: String,
    /// The PARSED signer — never the hex string it came from. The environment
    /// value is read, parsed, and dropped inside [`SettlerConfig::from_env`], so
    /// the raw key material exists in this process only as the opaque signer.
    pub signer: PrivateKeySigner,
}

impl SettlerConfig {
    /// Builds the configuration from the process environment.
    ///
    /// Returns `Box<dyn Error>` like every other fail-fast startup edge in the
    /// workspace (ADR-0021); nothing branches on these failures, they abort boot.
    ///
    /// # Errors
    /// Returns an error if any of `TOLLGATE_DATABASE_URL`, `TOLLGATE_RPC_URL` or
    /// `TOLLGATE_SIGNER_KEY` is unset, or if the signer key is not a valid
    /// secp256k1 private key.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let database_url = required(ENV_DATABASE_URL)?;
        let rpc_url = required(ENV_RPC_URL)?;

        // Read → parse → drop. `key` goes out of scope at the end of this
        // function and is the only place the raw hex ever lives; from here on the
        // key material is reachable only through `PrivateKeySigner`.
        let key = required(ENV_SIGNER_KEY)?;
        let signer = key.parse::<PrivateKeySigner>().map_err(|_| {
            // The parse error is DELIBERATELY dropped rather than chained: it is
            // the one error in this function whose source was constructed from
            // the secret itself, and a fixed message cannot leak what it never saw.
            format!("{ENV_SIGNER_KEY}: not a valid hex-encoded secp256k1 private key")
        })?;

        Ok(Self {
            database_url,
            rpc_url,
            signer,
        })
    }
}

/// Reads a required environment variable, naming it in the error when unset.
fn required(key: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(key).map_err(|_| format!("{key} must be set").into())
}

#[cfg(test)]
mod tests {
    use super::{SettlerConfig, ENV_DATABASE_URL, ENV_RPC_URL, ENV_SIGNER_KEY};
    use std::env;

    // Anvil's well-known account #0 key. Public by design (it is in every Ethereum
    // tutorial), so it is a test fixture and not a secret.
    const TEST_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    /// The address that key derives to — proof the signer was really parsed.
    const TEST_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    // Like the gateway's config test, every case lives in ONE `#[test]`: `from_env`
    // reads the process-global environment, so unset→set transitions must not race
    // a sibling test. The vars are removed again before returning.
    #[test]
    fn from_env_requires_every_knob_and_parses_the_signer() {
        for key in [ENV_DATABASE_URL, ENV_RPC_URL, ENV_SIGNER_KEY] {
            env::remove_var(key);
        }
        assert!(
            SettlerConfig::from_env().is_err(),
            "a settler with no configuration at all must refuse to start"
        );

        env::set_var(ENV_DATABASE_URL, "postgres://user@127.0.0.1:5432/db");
        assert!(
            SettlerConfig::from_env().is_err(),
            "the RPC URL has no default: settling against an assumed chain is unsafe"
        );

        env::set_var(ENV_RPC_URL, "https://sepolia.base.example/v1/key");
        assert!(
            SettlerConfig::from_env().is_err(),
            "the signer key has no default"
        );

        env::set_var(ENV_SIGNER_KEY, "not-a-key");
        assert!(
            SettlerConfig::from_env().is_err(),
            "a malformed signer key must fail at startup, not at the first redeem"
        );

        env::set_var(ENV_SIGNER_KEY, TEST_KEY);
        let cfg = SettlerConfig::from_env().expect("a fully configured settler must build");
        assert_eq!(cfg.database_url, "postgres://user@127.0.0.1:5432/db");
        assert_eq!(cfg.rpc_url, "https://sepolia.base.example/v1/key");
        assert_eq!(
            cfg.signer.address().to_string(),
            TEST_ADDRESS,
            "the stored signer must be the one the key derives to"
        );

        for key in [ENV_DATABASE_URL, ENV_RPC_URL, ENV_SIGNER_KEY] {
            env::remove_var(key);
        }
    }
}
