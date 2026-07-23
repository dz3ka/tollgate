//! Wiring: assemble the payment gate, the reverse proxy, and the HTTP server.

use axum::Router;
use tower_http::trace::TraceLayer;

use tollgate_middleware::{
    GateConfig, InMemoryNonceStore, NonceBackend, PaymentLayer, PgClaimLedger, RedisNonceStore,
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
/// than every request), `None` keeps the in-process store. The claims ledger is
/// selected the same way from `cfg.database_url`, and is additionally MIGRATED at
/// startup so the first paid request never races the schema.
///
/// # Errors
/// Returns an error if the listen socket cannot be bound, the initial Redis or
/// Postgres connection cannot be established, a claims-ledger migration fails, or
/// the server loop terminates abnormally.
pub async fn run(cfg: GatewayConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Non-sensitive labels for the active backends, safe to log. Both URLs may
    // carry a password, so they are NEVER logged — only these labels are.
    let backend_name = if cfg.redis_url.is_some() {
        "redis"
    } else {
        "in-memory"
    };
    let ledger_name = if cfg.database_url.is_some() {
        "postgres"
    } else {
        "none"
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

    // Eager connect AND migrate: a database that is down, unreachable, or on an
    // incompatible schema fails startup (via `?`) instead of failing closed on every
    // paid request afterwards. Running without a ledger is a supported mode
    // (local/dev), but accepted payments are then unrecoverable — worth a warning
    // line every boot.
    let ledger = if let Some(url) = &cfg.database_url {
        let ledger = PgClaimLedger::connect(url).await?;
        ledger.migrate().await?;
        Some(ledger)
    } else {
        tracing::warn!(
            "no claims ledger configured; accepted payments will NOT be recorded \
             and cannot be settled later"
        );
        None
    };

    let gate_config = GateConfig {
        requirements: cfg.requirements,
        store,
        ledger,
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
        ledger = %ledger_name,
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
