//! Wiring: assemble the payment gate, the reverse proxy, and the HTTP server.

use axum::Router;
use tower_http::trace::TraceLayer;

use tollgate_middleware::{
    GateConfig, InMemoryNonceStore, NonceBackend, PaymentLayer, RedisNonceStore,
};

use crate::config::GatewayConfig;
use crate::proxy::{proxy, ProxyCtx};

/// Builds the router and serves until interrupted with ctrl-c.
///
/// The request pipeline, outermost first: `TraceLayer` (structured request
/// logging) → `PaymentLayer` (x402 verification + replay guard) → the `proxy`
/// fallback. Only requests that pass the gate ever reach the proxy.
///
/// The replay-store backend is selected here from `cfg.redis_url`: `Some(url)`
/// picks Redis and connects to it EAGERLY (a dead Redis fails startup rather
/// than every request), `None` keeps the in-process store.
///
/// # Errors
/// Returns an error if the listen socket cannot be bound, the initial Redis
/// connection cannot be established, or the server loop terminates abnormally.
pub async fn run(cfg: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    // A non-sensitive label for the active backend, safe to log. The Redis URL
    // itself may carry a password, so it is NEVER logged — only this label is.
    let backend_name = if cfg.redis_url.is_some() {
        "redis"
    } else {
        "in-memory"
    };

    let store = match &cfg.redis_url {
        // Eager connect: a dead Redis at boot fails startup fast (bubbles via `?`),
        // rather than a gateway that boots green and 503s every request. The nonce
        // TTL is not fixed here — the gate derives it per claim from each
        // authorization's `validBefore` (see `PaymentGate::call`).
        Some(url) => NonceBackend::Redis(RedisNonceStore::connect(url).await?),
        // A fresh in-memory replay store for this process; every per-connection
        // clone of the gate shares it via the store's internal Arc.
        None => NonceBackend::InMemory(InMemoryNonceStore::new()),
    };

    let gate_config = GateConfig {
        requirements: cfg.requirements,
        store,
    };

    let ctx = ProxyCtx::new(cfg.upstream.clone(), cfg.upstream_timeout);

    let app = Router::new()
        .fallback(proxy)
        .layer(PaymentLayer::new(gate_config))
        .layer(TraceLayer::new_for_http())
        .with_state(ctx);

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!(
        listen = %cfg.listen,
        upstream = %cfg.upstream,
        backend = %backend_name,
        "tollgate-gateway listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// Resolves when the process receives ctrl-c, letting `axum::serve` drain
/// in-flight requests before returning.
async fn shutdown_signal() {
    if let Err(err) = tokio::signal::ctrl_c().await {
        // If the handler cannot be installed we log and return, which triggers
        // shutdown immediately rather than leaving the server unstoppable.
        tracing::error!(error = %err, "failed to install ctrl-c handler");
    }
}
