//! End-to-end proxy test: a real gateway process in front of a real upstream.
//!
//! This exercises the whole M3 pipeline over TCP — no mocks, no in-process
//! shortcuts. A stub axum upstream is spawned on an ephemeral port, the gateway
//! (`server::run`) is spawned on another, and a raw `hyper-util` client drives
//! the three-request story:
//!
//! 1. GET without `X-PAYMENT`            → 402 + a serialized `Challenge`.
//! 2. GET with a valid signed `X-PAYMENT` → 200, relayed upstream body.
//! 3. GET replaying the SAME `X-PAYMENT` → 402 (nonce replay rejected).
//!
//! The signing harness is duplicated inline from the `#[cfg(test)]` oracle in
//! `tollgate-core/src/x402/verify.rs`; there is no third consumer yet, so
//! extracting a shared test-util would be premature (rule of three).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use k256::ecdsa::SigningKey;

use tollgate_core::x402::{Challenge, Network, PaymentRequirementsBuilder};
use tollgate_gateway::run;

// --- Fixed test parameters -------------------------------------------------
//
// verifyingContract MUST equal `requirements.asset`, and the (name, version)
// pair MUST equal `requirements.extra`, or the gateway will recover a different
// signer and reject the payment. These constants are threaded into BOTH the
// GatewayConfig and the EIP-712 domain the client signs under.

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
/// The `maxTimeoutSeconds` the fixture challenge advertises — and therefore the
/// longest validity window `verify_payment` will accept for a payment against it.
const MAX_TIMEOUT_SECS: u64 = 3_600;
/// The stub upstream's known response body — proves end-to-end relay.
const UPSTREAM_BODY: &str = "hello from upstream";
/// A benign custom header the client names in `Connection` on the paid request.
/// It is thus a per-hop header the proxy must scrub; the upstream asserting its
/// absence proves the `Connection`-listed hop-by-hop stripping actually runs.
const HOP_MARKER: &str = "x-hop-marker";

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

#[tokio::test(flavor = "multi_thread")]
async fn gateway_gates_then_proxies_then_blocks_replay() {
    // 1. Stand up the stub upstream on an ephemeral port. It records the headers
    //    of the last request it received so the test can assert on what the
    //    proxy actually forwarded.
    let (upstream_addr, upstream_headers) = spawn_upstream().await;
    let upstream_uri = format!("http://{upstream_addr}");

    // 2. Reserve an ephemeral port for the gateway, then hand it to `run`.
    //    We bind, read the address, and drop the listener so `run` can rebind
    //    it; the poll-connect loop below closes the resulting startup race.
    let gateway_addr = reserve_ephemeral_addr().await;

    let requirements = PaymentRequirementsBuilder::exact(
        Network::BaseSepolia,
        PAY_TO.parse().expect("pay_to is valid hex"),
        ASSET.parse().expect("asset is valid hex"),
        AMOUNT.parse().expect("amount is decimal"),
        "http://localhost/",
        MAX_TIMEOUT_SECS,
    )
    .extra(serde_json::json!({ "name": DOMAIN_NAME, "version": DOMAIN_VERSION }))
    .build();

    let cfg = tollgate_gateway::GatewayConfig {
        listen: gateway_addr,
        upstream: upstream_uri.parse().expect("upstream uri is absolute http"),
        upstream_timeout: Duration::from_secs(5),
        requirements,
        // No Redis URL: exercise the in-memory replay store, identical to M3.
        redis_url: None,
        // No claims ledger either: this test is the proxy/replay path, and the
        // ledger has its own e2e in `ledger_e2e.rs`.
        database_url: None,
    };
    // `run` returns a non-`Send` boxed error, so we consume the result inside
    // the spawned task rather than letting it cross the spawn boundary.
    tokio::spawn(async move {
        if let Err(err) = run(cfg).await {
            eprintln!("gateway exited with error: {err}");
        }
    });

    // Wait until the gateway actually accepts connections before driving it.
    wait_until_listening(gateway_addr).await;

    let client: TestClient = Client::builder(TokioExecutor::new()).build_http();
    let base = format!("http://{gateway_addr}/");

    // --- Request 1: no payment → 402 challenge --------------------------------
    let (status, body) = get(&client, &base, None, false).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "unpaid request must 402"
    );
    let challenge: Challenge =
        serde_json::from_slice(&body).expect("402 body must be a serialized Challenge");
    assert_eq!(challenge.x402_version, 1);
    assert!(
        !challenge.accepts.is_empty(),
        "challenge must advertise at least one accepted offer"
    );

    // --- Request 2: valid payment → 200 relayed upstream ----------------------
    // Carries the payment proof AND a `Connection: x-hop-marker` + `X-Hop-Marker`
    // pair, so this single request exercises both stripping paths at once.
    let header = build_payment_header();
    let (status, body) = get(&client, &base, Some(&header), true).await;
    assert_eq!(status, StatusCode::OK, "paid request must be proxied (200)");
    assert_eq!(
        body.as_ref(),
        UPSTREAM_BODY.as_bytes(),
        "body must be the upstream's response, proving end-to-end relay"
    );

    // The proxy must have scrubbed the payment proof and the per-hop header
    // before forwarding: assert on exactly what the upstream received.
    let forwarded = upstream_headers
        .lock()
        .expect("upstream capture mutex is not poisoned")
        .clone()
        .expect("upstream must have recorded the proxied request's headers");
    assert!(
        !forwarded.contains_key("x-payment"),
        "X-PAYMENT proof must never be forwarded upstream (it is the gateway's alone)"
    );
    assert!(
        !forwarded.contains_key(HOP_MARKER),
        "a header named in the client's Connection must be stripped as hop-by-hop"
    );

    // --- Request 3: replay the SAME header → 402 (nonce already spent) ---------
    let (status, _) = get(&client, &base, Some(&header), false).await;
    assert_eq!(
        status,
        StatusCode::PAYMENT_REQUIRED,
        "replaying a spent nonce must be rejected with 402"
    );
}

/// Spawns the stub upstream and returns the address it bound to together with a
/// handle to the headers of the most recent request it received. The test reads
/// that handle to verify the proxy scrubbed payment/hop-by-hop headers.
async fn spawn_upstream() -> (SocketAddr, Arc<Mutex<Option<HeaderMap>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream ephemeral port");
    let addr = listener.local_addr().expect("read upstream local_addr");

    // Shared slot the handler writes each request's headers into; the test reads
    // it after the successful relay.
    let captured: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);

    // A trivial app: every path returns the known body, recording the inbound
    // headers first. The gateway proxies the request path verbatim, so a
    // fallback handler covers `/`.
    let app = axum::Router::new().fallback(move |headers: HeaderMap| {
        let sink = Arc::clone(&sink);
        async move {
            *sink.lock().expect("upstream capture mutex is not poisoned") = Some(headers);
            UPSTREAM_BODY
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("upstream serve");
    });
    (addr, captured)
}

/// Binds an ephemeral port, reads its address, and releases it for reuse.
async fn reserve_ephemeral_addr() -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway ephemeral port");
    listener.local_addr().expect("read gateway local_addr")
    // `listener` drops here, freeing the port for `run` to rebind.
}

/// Polls until `addr` accepts a TCP connection, so requests never race startup.
async fn wait_until_listening(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("gateway did not start listening on {addr} in time");
}

/// Issues a GET to `uri`, optionally with an `X-PAYMENT` header, returning the
/// status and the fully-collected response body.
///
/// When `hop_probe` is set, the request also carries `Connection: x-hop-marker`
/// and the matching `X-Hop-Marker` header, letting the caller verify that the
/// proxy strips headers the `Connection` header names as per-hop.
async fn get(
    client: &TestClient,
    uri: &str,
    payment: Option<&str>,
    hop_probe: bool,
) -> (StatusCode, Bytes) {
    let mut builder = Request::get(uri);
    if let Some(value) = payment {
        builder = builder.header("X-PAYMENT", value);
    }
    if hop_probe {
        builder = builder
            .header(http::header::CONNECTION, HOP_MARKER)
            .header(HOP_MARKER, "leak-check");
    }
    let req = builder.body(Empty::<Bytes>::new()).expect("build request");
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

/// Builds a valid, signed `X-PAYMENT` header value (standard base64 of the
/// x402 payload JSON). Mirrors verify.rs's signing oracle: EIP-712 sign the
/// `TransferWithAuthorization` under {name, version, chainId, verifyingContract}
/// and assemble the 65-byte `r||s||v` signature with `v = 27 + recovery_id`.
fn build_payment_header() -> String {
    // A fixed key keeps the test deterministic; the from-address is derived from
    // its public key exactly as the verifier recovers it (keccak of the pubkey).
    let key = SigningKey::from_bytes(&[7u8; 32].into()).expect("valid signing key");
    let from = Address::from_public_key(key.verifying_key());
    let to: Address = PAY_TO.parse().expect("pay_to address");
    let verifying_contract: Address = ASSET.parse().expect("asset address");

    let value = U256::from_str_radix(AMOUNT, 10).expect("amount");
    let valid_after = U256::ZERO;
    // Derived from the real clock rather than a far-future constant: the gate now
    // refuses an authorization that stays valid for longer than the challenge's
    // `maxTimeoutSeconds` advertised, and a year-2286 deadline is precisely that.
    // Read ONCE — signing it and writing it into the JSON from two different reads
    // would produce a signature over a different deadline than the one sent.
    let valid_before_secs = now_unix() + MAX_TIMEOUT_SECS;
    let valid_before = U256::from(valid_before_secs);
    // A fixed nonce is fine: the replay test deliberately re-sends this header.
    let nonce_bytes = [0x11u8; 32];
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
        validAfter: valid_after,
        validBefore: valid_before,
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

    // Assemble the x402 wire JSON (camelCase, hex-string fields) and standard-
    // base64 encode it — `decode_payment_header` uses STANDARD, not URL-safe.
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
                "validBefore": valid_before_secs.to_string(),
                "nonce": format!("0x{}", alloy_primitives::hex::encode(nonce_bytes)),
            }
        }
    });
    let json = serde_json::to_string(&payload).expect("serialize payload");
    base64::engine::general_purpose::STANDARD.encode(json)
}

/// Wall-clock unix seconds: the same clock the gate verifies the authorization
/// against, so the fixture's deadline has to be expressed in it.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the unix epoch")
        .as_secs()
}
