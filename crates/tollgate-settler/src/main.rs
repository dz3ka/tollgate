#![forbid(unsafe_code)]
//! `tollgate-settler` is the settlement worker binary: it redeems the payment
//! claims the gateway recorded against the token contract on-chain. Configuration
//! comes from the environment; see [`tollgate_settler::config`].

use std::process::ExitCode;

use tracing_subscriber::EnvFilter;

use tollgate_settler::SettlerConfig;

/// Starts the worker and turns any startup fault into an exit code.
///
/// It returns [`ExitCode`], NOT `Result`, and that is a security property rather
/// than a style choice. `Termination` for `Result` prints the error with `{:?}`,
/// which walks straight past this workspace's deliberately fixed `Display` impls
/// into the `Debug` of whatever is boxed underneath — for a transport fault that is
/// `reqwest::Error`, whose `Debug` prints the full RPC URL. Real endpoints carry an
/// API key in that URL, so a DNS blip or a 401 would spill the operator's credential
/// into journald (ADR-0034).
///
/// So the error is reported here, through `Display` only, and the source chain is
/// deliberately NOT walked: every link below the top is third-party and none of them
/// promise a redacted rendering. What is lost is detail an operator can recover by
/// raising `RUST_LOG` — which is itself only safe because of what [`env_filter`]
/// keeps switched off there.
#[tokio::main]
async fn main() -> ExitCode {
    // Same observability seam as the gateway: structured JSON, filtered by
    // RUST_LOG, default info (ADR-0020).
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(env_filter())
        .init();

    match start().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "settlement worker failed to start");
            ExitCode::FAILURE
        }
    }
}

/// alloy's HTTP transport. It opens a span per request — `ReqwestTransport`, and its
/// hyper twin — with the FULL endpoint as a `url` field, API key and all. Nothing in
/// this workspace logs that URL; the transport does, and every event emitted anywhere
/// beneath it (reqwest's, hyper's, ours) inherits the span and prints it.
const RPC_TRANSPORT_TARGET: &str = "alloy_transport_http";

/// The log filter: `RUST_LOG` if it is set and parses, `info` otherwise — with
/// alloy's transport spans silenced unless the operator asks for them BY NAME.
///
/// The silencing is a credential control, not noise reduction (ADR-0034). Every error
/// this crate can print has a fixed, URL-free `Display`, but `RUST_LOG=debug` — the
/// exact escalation the doc above recommends — enables third-party targets we do not
/// write, and [`RPC_TRANSPORT_TARGET`] is one of them. An operator debugging a stuck
/// settlement would otherwise paste their own API key into a ticket.
///
/// It is an override rather than a hard block because a stuck transport is a real
/// thing to have to debug: `RUST_LOG=alloy_transport_http=debug` still works. Naming
/// the target is then a deliberate act rather than a side effect of asking for detail.
/// The directive is added only when the operator did not mention that target at all,
/// so it can never overrule a choice they made explicitly.
fn env_filter() -> EnvFilter {
    let requested = std::env::var("RUST_LOG").unwrap_or_default();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if requested.contains(RPC_TRANSPORT_TARGET) {
        filter
    } else {
        filter.add_directive(
            format!("{RPC_TRANSPORT_TARGET}=off")
                .parse()
                .expect("a constant directive parses"),
        )
    }
}

/// Reads the environment and hands off to the library.
///
/// Split from `main` only so the `?` operator is available above the one place that
/// is allowed to format an error.
async fn start() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = SettlerConfig::from_env()?;

    // Everything else — eager ledger and RPC connects, the sweep loop, graceful
    // shutdown — lives in the library, so the whole worker is reachable from a test
    // without a process. `main` only reads the environment and starts logging.
    tollgate_settler::run(cfg).await
}
