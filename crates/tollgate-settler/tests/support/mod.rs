//! Shared harness for the hermetic sweep test: a throwaway Postgres, a claim
//! fixture, a connected [`SettlementClient`] pointed at the fake chain, and a log
//! capture.
//!
//! Everything here goes through the settler's PRODUCTION seams — the ledger URL and
//! the RPC URL — so the test never reaches inside the crate for a shortcut.

pub mod rpc_fake;

use std::sync::{Arc, Mutex, OnceLock};

use alloy::signers::local::PrivateKeySigner;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;
use tracing_subscriber::fmt::MakeWriter;

use tollgate_core::x402::Network;
use tollgate_ledger::{Claim, PgClaimLedger};

use rpc_fake::FakeChain;

/// Postgres' port inside the container; the module publishes it on an ephemeral
/// host port.
const PG_PORT: u16 = 5432;

/// The sweep's fixed "now". Every fixture's `validBefore` is expressed relative to
/// it, so no test depends on wall-clock time.
pub const NOW: u64 = 1_700_000_000;

/// Anvil's well-known account #0 key — public by design, so it is a fixture rather
/// than a secret. It signs the settlement transactions the fake receives.
const SETTLER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

// The claim fixture's parties and amount. `rpc_fake` reads them too: the settler now
// checks the ERC-20 `Transfer` inside the redeeming transaction against the claim, so
// the fake's canned receipt and the claim below have to describe the SAME payment
// unless a test deliberately makes them differ.
pub const PAYER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const PAYEE: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const ASSET: &str = "0xcccccccccccccccccccccccccccccccccccccccc";
pub const VALUE: u64 = 10_000;

/// Starts a Postgres container with the claims schema applied and returns it beside
/// the ledger. The handle MUST outlive the test — dropping it removes the container.
///
/// One container per test, like every other container-backed suite in the workspace:
/// `ContainerAsync`'s Drop hands cleanup back to the runtime that started it, so a
/// shared `static` would be dropped by a foreign runtime.
pub async fn start_migrated_ledger() -> (ContainerAsync<Postgres>, PgClaimLedger) {
    let container = Postgres::default()
        .start()
        .await
        .expect("start postgres container (is DOCKER_HOST / a container runtime available?)");
    let host = container.get_host().await.expect("resolve container host");
    let port = container
        .get_host_port_ipv4(PG_PORT)
        .await
        .expect("resolve mapped postgres port");

    let ledger = PgClaimLedger::connect(&format!(
        "postgres://postgres:postgres@{host}:{port}/postgres"
    ))
    .await
    .expect("connect to postgres");
    ledger.migrate().await.expect("apply migrations");
    (container, ledger)
}

/// Connects a real [`SettlementClient`] to the fake and forgets the calls that took.
///
/// `connect` asks `eth_chainId`, which is harness setup rather than sweep behaviour;
/// clearing it here is what lets a test assert "the sweep made ZERO calls".
pub async fn connect_to(fake: &FakeChain) -> tollgate_settler::SettlementClient {
    let signer: PrivateKeySigner = SETTLER_KEY.parse().expect("fixture signer key");
    let client = tollgate_settler::SettlementClient::connect(fake.url(), signer)
        .await
        .expect("connect the settlement client to the fake chain");
    fake.clear_calls();
    client
}

/// A claim distinguished by its nonce, its deadline and its network, so each test
/// varies exactly the dimension it is about.
///
/// The signature is a well-formed, non-malleable `(r, s, v)` — settlement splits it
/// through core's parser, which rejects anything else before a byte is broadcast.
pub fn claim(nonce_suffix: char, valid_before: u64, network: Network) -> Claim {
    Claim {
        payer: PAYER.parse().expect("valid payer fixture"),
        nonce: format!("0x{}", String::from(nonce_suffix).repeat(64))
            .parse()
            .expect("valid nonce fixture"),
        payee: PAYEE.parse().expect("valid payee fixture"),
        value: VALUE.to_string().parse().expect("valid value fixture"),
        valid_after: "0".parse().expect("valid validAfter fixture"),
        valid_before: valid_before
            .to_string()
            .parse()
            .expect("valid validBefore fixture"),
        signature: format!("0x{}{}1b", "11".repeat(32), "22".repeat(32)),
        asset: ASSET.parse().expect("valid asset fixture"),
        network,
    }
}

/// Whether the claim with this nonce is still owed, read through the same public
/// query the settler uses.
///
/// `settled_at` has no getter — and `Claim` has no `Debug` — so a row's disappearance
/// from `settleable` is the only observation of settlement the ledger's API offers.
pub async fn is_still_owed(ledger: &PgClaimLedger, nonce_suffix: char) -> bool {
    let wanted = claim(nonce_suffix, 0, Network::BaseSepolia);
    ledger
        .settleable(0, 50)
        .await
        .expect("read settleable claims")
        .iter()
        .any(|c| c.nonce.as_str() == wanted.nonce.as_str())
}

/// Installs the process-wide log capture, once. Safe to call from every test: the
/// first caller wins and the rest share its buffer.
pub fn capture_logs() {
    let _ = buffer();
}

/// Everything logged by any test so far.
///
/// Tests share one buffer because a `tracing` subscriber is process-global, so each
/// assertion must match on a line that only ITS branch could have produced — in
/// practice the claim's nonce, which is unique per test.
pub fn logged() -> String {
    let bytes = buffer().lock().expect("log buffer mutex is not poisoned");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// The shared buffer, installing the subscriber on first use.
fn buffer() -> &'static Arc<Mutex<Vec<u8>>> {
    static BUFFER: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    BUFFER.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        // `try_init` rather than `init`: a second subscriber would panic, and this
        // is reached from whichever test happens to run first.
        let _ = tracing_subscriber::fmt()
            .with_writer(CaptureWriter(Arc::clone(&buffer)))
            .with_ansi(false)
            .try_init();
        buffer
    })
}

/// A `MakeWriter` that appends formatted events to the shared buffer. The fmt layer
/// writes one event per `write_all`, so lines from concurrent tests interleave as
/// whole lines rather than shredding each other.
#[derive(Clone)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer mutex is not poisoned")
            .write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CaptureWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
