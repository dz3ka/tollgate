//! End-to-end claims-ledger tests: one paid request, one durable row — and no
//! served request at all when the ledger is down.
//!
//! This is the proof of M5a's goal. A throwaway Postgres container, a stub
//! upstream, and the real gateway (`server::run`, which connects and migrates the
//! ledger itself) are wired together over TCP, then ONE signed request is driven
//! through the whole pipeline:
//!
//! 1. GET with a valid signed `X-PAYMENT` → 200 with the upstream's body, so the
//!    request really was gated, accepted, and proxied.
//! 2. `unsettled(10)` against the same database → exactly that claim, signature
//!    intact — the bytes a settlement worker will later replay on-chain.
//!
//! The other two tests cover the branches either side of that success path: a
//! gateway whose Postgres has been STOPPED must fail closed (503, no upstream work
//! given away), and a second gateway sharing only the ledger must reject a replay
//! its own nonce store has never seen.
//!
//! Both tests own their own container (see `postgres_claim_ledger.rs` for why
//! containers are never shared) — the fail-closed one stops its container, which
//! would poison anything else sharing it.
//!
//! The signing harness is duplicated inline from `proxy_e2e.rs` (which in turn
//! mirrors verify.rs's `sol!` oracle). Sharing it would mean a new test-support
//! crate spanning `tollgate-core` and `tollgate-gateway`; that is a bigger moving
//! part than the duplication it removes, so it stays copied for now.
//!
//! Needs a container runtime reachable via `DOCKER_HOST` (Docker or a rootless
//! Podman socket), like the other testcontainers suites.

use std::net::SocketAddr;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use base64::Engine as _;
use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use k256::ecdsa::SigningKey;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;

use tollgate_core::x402::{Network, PaymentRequirementsBuilder};
use tollgate_gateway::run;
use tollgate_middleware::PgClaimLedger;

// --- Fixed test parameters (same contract as proxy_e2e.rs) -----------------
//
// verifyingContract MUST equal `requirements.asset` and the (name, version) pair
// MUST equal `requirements.extra`, or the gateway recovers a different signer.

/// The asset the payment is denominated in; doubles as EIP-712 `verifyingContract`.
const ASSET: &str = "0x2222222222222222222222222222222222222222";
/// The recipient; must equal the authorization `to`.
const PAY_TO: &str = "0x3333333333333333333333333333333333333333";
/// EIP-712 domain `name`, sourced from `requirements.extra["name"]`.
const DOMAIN_NAME: &str = "USDC";
/// EIP-712 domain `version`, sourced from `requirements.extra["version"]`.
const DOMAIN_VERSION: &str = "2";
/// Amount required (and paid), in the asset's base units.
const AMOUNT: &str = "10000";
/// Base Sepolia's EIP-712 chain id (see `verify::chain_id`).
const CHAIN_ID: u64 = 84_532;
/// A far-future `validBefore`: the gate verifies against real wall-clock time.
const VALID_BEFORE: u64 = 9_999_999_999;
/// The stub upstream's known response body — proves end-to-end relay.
const UPSTREAM_BODY: &str = "hello from upstream";
/// Postgres' port INSIDE the container; the module image publishes it on an
/// ephemeral host port, and its default database/user/password are all `postgres`.
const PG_PORT: u16 = 5432;

// The EIP-3009 struct the client signs, mirrored from verify.rs's oracle.
sol! {
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// A `hyper-util` legacy client with an empty request body (all GETs here).
type TestClient = Client<HttpConnector, Empty<Bytes>>;

/// The signed `X-PAYMENT` header plus the fields the ledger row must carry, so
/// the assertions compare against what was actually signed rather than a
/// re-derivation.
struct SignedPayment {
    header: String,
    payer: String,
    nonce: String,
    signature: String,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_payment_is_recorded_in_the_claims_ledger() {
    let (_container, database_url) = start_postgres().await;
    let upstream_addr = spawn_upstream().await;
    let gateway_addr = spawn_gateway(&database_url, upstream_addr).await;

    // --- One paid request: must be proxied, and must leave a claim behind -----
    let payment = build_payment();
    let client: TestClient = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::get(format!("http://{gateway_addr}/"))
        .header("X-PAYMENT", &payment.header)
        .body(Empty::<Bytes>::new())
        .expect("build request");
    let resp = client.request(req).await.expect("gateway responded");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a valid payment must be proxied upstream (200)"
    );
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    assert_eq!(
        body.as_ref(),
        UPSTREAM_BODY.as_bytes(),
        "body must be the upstream's, proving the request really was forwarded"
    );

    // Read the ledger back through its own public API, on a second connection —
    // the row is asserted as it will be seen by the settlement worker.
    let ledger = PgClaimLedger::connect(&database_url)
        .await
        .expect("connect to the gateway's database");
    let owed = ledger.unsettled(10).await.expect("read unsettled claims");
    assert_eq!(
        owed.len(),
        1,
        "exactly the one accepted payment must be owed"
    );
    let claim = &owed[0];
    assert_eq!(
        claim.payer.as_str(),
        payment.payer,
        "the ledger must key the claim on the payer that signed it"
    );
    assert_eq!(claim.nonce.as_str(), payment.nonce);
    assert_eq!(claim.value.as_str(), AMOUNT);
    assert_eq!(claim.valid_before.as_str(), VALID_BEFORE.to_string());
    assert_eq!(
        claim.signature, payment.signature,
        "the signature must survive intact — it is what gets replayed on-chain"
    );
}

/// The fail-closed branch, end to end: a valid payment whose claim CANNOT be
/// recorded must be answered 503 and must not reach the upstream.
///
/// This is the most money-critical branch the ledger adds. The gateway boots
/// against a live Postgres (so it migrates and reports healthy), then the database
/// is STOPPED out from under it — the faithful model of a production outage — and
/// a single valid signed payment is driven through the real gate. Serving the
/// request here would hand out upstream work for a payment we can never collect,
/// so the assertion is on the exact 503 contract: status, and the fixed
/// non-leaking body that says nothing about which backend died.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn payment_is_refused_with_503_when_the_ledger_is_unreachable() {
    let (container, database_url) = start_postgres().await;
    let upstream_addr = spawn_upstream().await;
    // Returning means `run` already connected and migrated, so the outage below is
    // an outage of a HEALTHY gateway rather than a failure to start.
    let gateway_addr = spawn_gateway(&database_url, upstream_addr).await;

    container.stop().await.expect("stop the postgres container");

    let payment = build_payment();
    let client: TestClient = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::get(format!("http://{gateway_addr}/"))
        .header("X-PAYMENT", &payment.header)
        .body(Empty::<Bytes>::new())
        .expect("build request");
    // Budgeted above the ledger pool's 2s acquire timeout: a dead database must
    // surface as a response, and the timeout turns a hypothetical hang into a loud
    // failure instead of a stalled suite.
    let resp = tokio::time::timeout(Duration::from_mins(1), client.request(req))
        .await
        .expect("gateway must answer after the database dies, not hang")
        .expect("gateway responded");
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a claim we cannot record must fail CLOSED (503), never be served"
    );

    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    assert_eq!(
        std::str::from_utf8(&body).expect("503 body is UTF-8"),
        r#"{"error":"service unavailable"}"#,
        "the outage body is fixed and must leak nothing about the backend"
    );
}

/// The ledger is the DURABLE second line of replay defence: a payment already in
/// the ledger is rejected even by a gateway whose nonce store never saw it.
///
/// Two gateways share one Postgres and each owns a PRIVATE in-memory nonce store
/// (`redis_url: None`) — exactly what a restart, or a second instance behind a load
/// balancer, looks like. The same signed header is presented to each in turn. If
/// the gate forwarded on a ledger conflict, the second gateway would serve the
/// replay for free off one paid row, so `unsettled()` is asserted at BOTH steps: it
/// stays at exactly one row, which is what separates "rejected as a replay" from
/// "never recorded in the first place".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replayed_payment_is_rejected_by_a_second_gateway_sharing_the_ledger() {
    let (_container, database_url) = start_postgres().await;
    let upstream_addr = spawn_upstream().await;
    // Booted in sequence, not concurrently: the first applies the migration and the
    // second finds it already applied, so neither races the other's schema.
    let first_addr = spawn_gateway(&database_url, upstream_addr).await;
    let second_addr = spawn_gateway(&database_url, upstream_addr).await;

    let ledger = PgClaimLedger::connect(&database_url)
        .await
        .expect("connect to the gateways' database");
    let payment = build_payment();
    let client: TestClient = Client::builder(TokioExecutor::new()).build_http();

    let (status, body) = pay(&client, first_addr, &payment.header).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the first sighting of a valid payment must be proxied"
    );
    assert_eq!(
        body.as_ref(),
        UPSTREAM_BODY.as_bytes(),
        "body must be the upstream's, proving the request really was forwarded"
    );
    assert_eq!(
        ledger.unsettled(10).await.expect("read unsettled").len(),
        1,
        "the accepted payment must be owed exactly once"
    );

    // Same header, second gateway: its nonce store is empty, so ONLY the ledger can
    // catch this — and it must, with the same 402 the nonce store would have given.
    let (status, _body) = pay(&client, second_addr, &payment.header).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "a payment already in the ledger is a replay and must NOT be served again"
    );
    assert_eq!(
        ledger.unsettled(10).await.expect("read unsettled").len(),
        1,
        "the replay must not add a second row either — one payment, one claim"
    );
}

/// GETs `/` on `addr` with `header` as `X-PAYMENT`, returning the status and the
/// collected body.
async fn pay(client: &TestClient, addr: SocketAddr, header: &str) -> (StatusCode, Bytes) {
    let req = Request::get(format!("http://{addr}/"))
        .header("X-PAYMENT", header)
        .body(Empty::<Bytes>::new())
        .expect("build request");
    let resp = client.request(req).await.expect("gateway responded");
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    (status, body)
}

/// Boots a gateway on its own ephemeral port against `database_url`, proxying to
/// `upstream_addr`, and returns its address once it is accepting connections —
/// which means `run` has already connected to Postgres and migrated it.
///
/// `redis_url: None` is load-bearing, not incidental: each gateway then owns a
/// private in-memory nonce store, so two of them share the ledger and NOTHING else.
async fn spawn_gateway(database_url: &str, upstream_addr: SocketAddr) -> SocketAddr {
    let gateway_addr = reserve_ephemeral_addr().await;

    let requirements = PaymentRequirementsBuilder::exact(
        Network::BaseSepolia,
        PAY_TO.parse().expect("pay_to is valid hex"),
        ASSET.parse().expect("asset is valid hex"),
        AMOUNT.parse().expect("amount is decimal"),
        "http://localhost/",
        60,
    )
    .extra(serde_json::json!({ "name": DOMAIN_NAME, "version": DOMAIN_VERSION }))
    .build();

    let cfg = tollgate_gateway::GatewayConfig {
        listen: gateway_addr,
        upstream: format!("http://{upstream_addr}")
            .parse()
            .expect("upstream uri is absolute http"),
        upstream_timeout: Duration::from_secs(5),
        requirements,
        redis_url: None,
        database_url: Some(database_url.to_owned()),
    };
    // `run` returns a non-`Send` boxed error, so consume the result inside the
    // spawned task rather than letting it cross the spawn boundary.
    tokio::spawn(async move {
        if let Err(err) = run(cfg).await {
            eprintln!("gateway exited with error: {err}");
        }
    });
    wait_until_listening(gateway_addr).await;
    gateway_addr
}

/// Starts a fresh Postgres container and returns the handle plus its connection
/// URL. The handle MUST be kept alive for the test's duration — dropping it stops
/// and removes the container.
async fn start_postgres() -> (ContainerAsync<Postgres>, String) {
    let container = Postgres::default()
        .start()
        .await
        .expect("start postgres container (is DOCKER_HOST / a container runtime available?)");
    let host = container.get_host().await.expect("resolve container host");
    let port = container
        .get_host_port_ipv4(PG_PORT)
        .await
        .expect("resolve mapped postgres port");
    (
        container,
        format!("postgres://postgres:postgres@{host}:{port}/postgres"),
    )
}

/// Spawns the stub upstream on an ephemeral port and returns its address. Every
/// path answers with the known body; the gateway proxies the path verbatim.
async fn spawn_upstream() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream ephemeral port");
    let addr = listener.local_addr().expect("read upstream local_addr");
    let app = axum::Router::new().fallback(|| async { UPSTREAM_BODY });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream serve");
    });
    addr
}

/// Binds an ephemeral port, reads its address, and releases it for reuse.
async fn reserve_ephemeral_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway ephemeral port");
    listener.local_addr().expect("read gateway local_addr")
    // `listener` drops here, freeing the port for `run` to rebind.
}

/// Polls until `addr` accepts a TCP connection, so the request never races startup.
async fn wait_until_listening(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("gateway did not start listening on {addr} in time");
}

/// Builds a valid, signed `X-PAYMENT` header (standard base64 of the x402 payload
/// JSON) and reports the signed fields the ledger row is asserted against.
fn build_payment() -> SignedPayment {
    // A fixed key keeps the test deterministic; the from-address is derived from
    // its public key exactly as the verifier recovers it.
    let key = SigningKey::from_bytes(&[9u8; 32].into()).expect("valid signing key");
    let from = Address::from_public_key(key.verifying_key());
    let to: Address = PAY_TO.parse().expect("pay_to address");
    let verifying_contract: Address = ASSET.parse().expect("asset address");

    let value = U256::from_str_radix(AMOUNT, 10).expect("amount");
    let nonce_bytes = [0x22u8; 32];
    let nonce = B256::from(nonce_bytes);

    let domain = eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: CHAIN_ID,
        verifying_contract: verifying_contract,
    };
    let message = TransferWithAuthorization {
        from,
        to,
        value,
        validAfter: U256::ZERO,
        validBefore: U256::from(VALID_BEFORE),
        nonce,
    };
    let digest = message.eip712_signing_hash(&domain);

    let (sig, recid) = key
        .sign_prehash_recoverable(digest.as_slice())
        .expect("sign digest");
    let mut raw = [0u8; 65];
    raw[..64].copy_from_slice(&sig.to_bytes());
    raw[64] = 27 + recid.to_byte();
    let signature = format!("0x{}", alloy_primitives::hex::encode(raw));
    let nonce_hex = format!("0x{}", alloy_primitives::hex::encode(nonce_bytes));

    // The x402 wire JSON (camelCase, hex-string fields), standard-base64 encoded —
    // `decode_payment_header` uses STANDARD, not URL-safe.
    let payload = serde_json::json!({
        "x402Version": 1,
        "scheme": "exact",
        "network": "base-sepolia",
        "payload": {
            "signature": signature,
            "authorization": {
                "from": from.to_string(),
                "to": to.to_string(),
                "value": AMOUNT,
                "validAfter": "0",
                "validBefore": VALID_BEFORE.to_string(),
                "nonce": nonce_hex,
            }
        }
    });
    let json = serde_json::to_string(&payload).expect("serialize payload");

    SignedPayment {
        header: base64::engine::general_purpose::STANDARD.encode(json),
        // The ledger canonicalises the key halves to lowercase; `Address::to_string`
        // is EIP-55 checksummed, so the expectation is lowercased here too.
        payer: from.to_string().to_ascii_lowercase(),
        nonce: nonce_hex.to_ascii_lowercase(),
        signature,
    }
}
