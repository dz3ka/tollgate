#![forbid(unsafe_code)]
//! `tollgate-gateway` is the service binary: an axum server that gates every
//! request behind the x402 payment flow ([`tollgate_middleware::PaymentLayer`])
//! and reverse-proxies accepted requests to a fixed operator-configured
//! upstream. Configuration comes from the environment; see [`config`].

use tracing_subscriber::EnvFilter;

use tollgate_gateway::{run, GatewayConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Structured JSON logs, filtered by RUST_LOG (default: info). This is the
    // first production request path, so observability is wired from the start.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    run(GatewayConfig::from_env()?).await
}
