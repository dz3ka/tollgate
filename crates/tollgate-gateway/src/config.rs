//! Operator configuration for the gateway, sourced from the environment.
//!
//! Four knobs are read from the environment (`TOLLGATE_LISTEN`,
//! `TOLLGATE_UPSTREAM`, `TOLLGATE_PAY_TO`, and the optional store selector
//! `TOLLGATE_REDIS_URL`); everything else is a sensible Base Sepolia testnet
//! default folded into the [`PaymentRequirements`] every request is verified
//! against. Only env keys a code path actually reads are honoured — no
//! speculative configuration surface.

use std::env;
use std::net::SocketAddr;
use std::time::Duration;

use http::Uri;

use tollgate_core::x402::{Network, PaymentRequirements, PaymentRequirementsBuilder};

/// Address the server binds to when `TOLLGATE_LISTEN` is unset.
const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
/// Upstream base used when `TOLLGATE_UPSTREAM` is unset (plain HTTP, M3).
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:8081";
/// Recipient placeholder used when `TOLLGATE_PAY_TO` is unset. Operators MUST
/// override this in any real deployment; it is only a valid-shaped default so
/// the binary starts out of the box for local testing.
const DEFAULT_PAY_TO: &str = "0x000000000000000000000000000000000000dEaD";

/// Base Sepolia USDC (the asset payments are denominated in). This doubles as
/// the EIP-712 `verifyingContract` during verification (sourced from `asset`).
const DEFAULT_ASSET: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
/// Amount required per request, in the asset's base units (0.01 USDC @ 6 dp).
const DEFAULT_AMOUNT: &str = "10000";
/// EIP-712 domain `name`, bound into the payment signature via `extra`.
const DEFAULT_DOMAIN_NAME: &str = "USDC";
/// EIP-712 domain `version`, bound into the payment signature via `extra`.
const DEFAULT_DOMAIN_VERSION: &str = "2";
/// Gated resource advertised in the 402 challenge (informational only).
const DEFAULT_RESOURCE: &str = "http://localhost/";
/// Facilitator settle-timeout advertised in the challenge, in seconds.
const DEFAULT_MAX_TIMEOUT_SECS: u64 = 60;
/// How long the proxy waits for the upstream before returning 504.
const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Fully-resolved gateway configuration, built once at startup.
pub struct GatewayConfig {
    /// The socket the server binds and listens on.
    pub listen: SocketAddr,
    /// The fixed upstream base every accepted request is proxied to. The
    /// authority here is the ONLY authority ever dialled — request-supplied
    /// hosts are never honoured (SSRF guard).
    pub upstream: Uri,
    /// How long to wait on the upstream before returning 504 Gateway Timeout.
    pub upstream_timeout: Duration,
    /// The single payment offer every request is verified against and echoed
    /// in every 402 challenge.
    pub requirements: PaymentRequirements,
    /// Optional Redis connection URL selecting the replay store backend.
    /// `Some(url)` picks the durable, cross-instance `RedisNonceStore`
    /// (connected eagerly at startup in `server::run`); `None` keeps the
    /// in-process default. The store TTL is NOT a knob: the gate derives it per
    /// claim from each authorization's own `validBefore`, so a nonce lives
    /// exactly as long as its authorization could still be validly presented —
    /// a hand-tuned shorter TTL would silently re-open replays.
    pub redis_url: Option<String>,
}

impl GatewayConfig {
    /// Builds the configuration from the process environment, applying testnet
    /// defaults for any key that is unset.
    ///
    /// # Errors
    /// Returns an error if `TOLLGATE_LISTEN` is not a valid socket address,
    /// `TOLLGATE_UPSTREAM` is not an absolute `http://` URI (with scheme and
    /// authority), or `TOLLGATE_PAY_TO` is not a valid EVM address.
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let listen = env_or("TOLLGATE_LISTEN", DEFAULT_LISTEN)
            .parse::<SocketAddr>()
            .map_err(|e| format!("TOLLGATE_LISTEN: {e}"))?;

        let upstream: Uri = env_or("TOLLGATE_UPSTREAM", DEFAULT_UPSTREAM)
            .parse()
            .map_err(|e| format!("TOLLGATE_UPSTREAM: {e}"))?;
        // The proxy rewrites request path+query onto this base, so it must
        // carry both a scheme and an authority to dial.
        if upstream.scheme().is_none() || upstream.authority().is_none() {
            return Err(
                "TOLLGATE_UPSTREAM must be absolute with scheme and authority, e.g. http://host:port"
                    .into(),
            );
        }
        // M3 ships a plain-HTTP connector only; a TLS upstream is M6.
        if upstream.scheme_str() != Some("http") {
            return Err("TOLLGATE_UPSTREAM: only http:// upstreams are supported in M3".into());
        }

        let pay_to = env_or("TOLLGATE_PAY_TO", DEFAULT_PAY_TO)
            .parse()
            .map_err(|e| format!("TOLLGATE_PAY_TO: {e}"))?;

        // Optional and unvalidated here: an empty/malformed URL surfaces as a
        // connection failure at `RedisNonceStore::connect` in `server::run`,
        // where the eager-connect fails startup fast. `None` = in-memory store.
        let redis_url = env::var("TOLLGATE_REDIS_URL").ok();

        // The asset/amount come from constants, so parse failures here would be
        // a programming error; propagate rather than panic to keep this path
        // panic-free.
        let asset = DEFAULT_ASSET
            .parse()
            .map_err(|e| format!("default asset is invalid: {e}"))?;
        let amount = DEFAULT_AMOUNT
            .parse()
            .map_err(|e| format!("default amount is invalid: {e}"))?;

        let requirements = PaymentRequirementsBuilder::exact(
            Network::BaseSepolia,
            pay_to,
            asset,
            amount,
            DEFAULT_RESOURCE,
            DEFAULT_MAX_TIMEOUT_SECS,
        )
        // The (name, version) pair is hashed into the EIP-712 signature the
        // client produces, so the gateway and signer MUST agree on it. Chain id
        // and verifyingContract are derived from network/asset, not from here.
        .extra(serde_json::json!({
            "name": DEFAULT_DOMAIN_NAME,
            "version": DEFAULT_DOMAIN_VERSION,
        }))
        .build();

        Ok(Self {
            listen,
            upstream,
            upstream_timeout: DEFAULT_UPSTREAM_TIMEOUT,
            requirements,
            redis_url,
        })
    }
}

/// Reads `key` from the environment, falling back to `default` when unset.
fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

#[cfg(test)]
mod tests {
    use super::GatewayConfig;
    use std::env;

    // `from_env` reads the process-global environment, so both cases live in a
    // SINGLE `#[test]`: it is the only test in this binary that touches
    // `TOLLGATE_REDIS_URL`, so keeping the unset→set→unset transitions in one
    // sequential body avoids any cross-test race on the shared env. The var is
    // removed again before returning so no state leaks to sibling tests.
    #[test]
    fn redis_url_env_selects_store_backend() {
        // Unset: the default path keeps the in-memory backend (`None`).
        env::remove_var("TOLLGATE_REDIS_URL");
        let cfg = GatewayConfig::from_env().expect("defaults must build");
        assert_eq!(
            cfg.redis_url, None,
            "unset must leave the in-memory default"
        );

        // Set: `Some(url)` selects Redis; the URL is carried through verbatim.
        env::set_var("TOLLGATE_REDIS_URL", "redis://127.0.0.1:6379");
        let cfg = GatewayConfig::from_env().expect("defaults must build");
        assert_eq!(
            cfg.redis_url.as_deref(),
            Some("redis://127.0.0.1:6379"),
            "set must select the Redis backend"
        );

        // Do not leak the var to other tests in this process.
        env::remove_var("TOLLGATE_REDIS_URL");
    }
}
