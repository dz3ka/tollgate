//! The x402 payment gate: a [`tower::Layer`] and [`tower::Service`] that verify
//! payment before delegating to an inner [`axum`] service.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::response::Response;
use http::StatusCode;

use tollgate_core::x402::{
    decode_payment_header, verify_payment, Challenge, PaymentDecodeError, PaymentRequirements,
    VerifyError,
};
use tollgate_ledger::{Claim, PgClaimLedger};

use crate::store::{NonceBackend, NonceStore as _};

/// Immutable per-gate configuration: the payment requirements every request is
/// verified against, the replay store, and the optional claims ledger. Built once
/// at startup, shared via Arc.
pub struct GateConfig {
    /// The single offer every request is verified against and that is echoed in
    /// every 402 challenge.
    pub requirements: PaymentRequirements,
    /// The replay store recording spent nonces. `NonceBackend` is the runtime
    /// backend selection (in-memory or Redis); it is `Clone` and every clone of the
    /// gate shares the same underlying store (Arc / multiplexed connection).
    pub store: NonceBackend,
    /// Where accepted claims are recorded so they can be settled later. `None`
    /// means no ledger is configured and accepted payments are NOT persisted —
    /// the gate still works, the operator simply collects nothing.
    pub ledger: Option<PgClaimLedger>,
}

/// A [`tower::Layer`] that wraps an inner service in a [`PaymentGate`].
///
/// The configuration lives behind an `Arc` so that cloning the layer (tower and
/// axum clone layers/services freely, e.g. once per connection) is cheap and
/// every clone shares the same requirements and replay store.
#[derive(Clone)]
pub struct PaymentLayer {
    config: Arc<GateConfig>,
}

impl PaymentLayer {
    /// Builds a layer from `config`, taking ownership and sharing it via `Arc`.
    #[must_use]
    pub fn new(config: GateConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> tower::Layer<S> for PaymentLayer {
    type Service = PaymentGate<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PaymentGate {
            inner,
            config: self.config.clone(),
        }
    }
}

/// The gate service produced by [`PaymentLayer`]. Wraps an inner service `S` and
/// admits a request only once its `X-PAYMENT` header decodes, verifies, and is
/// not a replay; otherwise it answers 402 without ever touching `inner`.
#[derive(Clone)]
pub struct PaymentGate<S> {
    inner: S,
    config: Arc<GateConfig>,
}

impl<S> tower::Service<http::Request<Body>> for PaymentGate<S>
where
    S: tower::Service<http::Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    // A boxed future erases the concrete inner future type and lets `call` run an
    // `async move` block that awaits the inner service.
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Readiness (e.g. backpressure) is entirely the inner service's concern;
        // the gate itself is always ready to inspect a header.
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        // --- The tower "not-ready clone" footgun and its fix ---
        //
        // `poll_ready` reserved capacity in `self.inner`, but `call` must return
        // a `'static` future, so we have to move an inner service *into* the
        // future. Moving `self.inner` directly would leave `self` holding an
        // inner whose readiness has NOT been polled — a later `call` on it would
        // violate tower's contract. The fix: clone `self`, then swap the ready
        // `self.inner` out into `inner` (for the future) while leaving the fresh,
        // not-yet-polled clone behind in `self`. The readiness we polled travels
        // with the instance we actually call.
        let clone = self.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone.inner);
        let config = self.config.clone();

        Box::pin(async move {
            // Read `X-PAYMENT` into an owned `String` up front, while we still
            // hold `req`. A `HeaderValue` may in principle be non-UTF-8; the
            // x402 header is always ASCII base64, so a `to_str` failure means a
            // malformed header — treat it as a coarse decode failure.
            let header = match req.headers().get("x-payment") {
                None => {
                    // No payment attached at all: a plain unpaid request. Return
                    // the bare challenge with no `error` — nothing went *wrong*,
                    // the client simply has not paid yet.
                    return Ok(challenge_402(&config.requirements, None));
                }
                Some(value) => match value.to_str() {
                    Ok(s) => s.to_owned(),
                    Err(_) => {
                        return Ok(challenge_402(
                            &config.requirements,
                            Some("invalid payment header encoding"),
                        ));
                    }
                },
            };

            // Decode: base64 -> UTF-8 -> JSON -> validated payload.
            let payload = match decode_payment_header(&header) {
                Ok(p) => p,
                Err(e) => {
                    return Ok(challenge_402(&config.requirements, Some(decode_reason(&e))));
                }
            };

            // Capture the wall clock ONCE and thread the same value through both the
            // validity check and the TTL derivation below — verify must agree with
            // the TTL about "now", or a race across a second boundary could bound the
            // nonce lifetime differently from the window verify accepted.
            let now = now_unix();

            // Cryptographically and policy-verify against our requirements.
            if let Err(e) = verify_payment(&payload, &config.requirements, now) {
                return Ok(challenge_402(&config.requirements, Some(verify_reason(&e))));
            }

            // Replay guard: the (from, nonce) pair identifies an EIP-3009
            // authorization. `claim` atomically checks-and-records it. The backend
            // is now fallible (Redis I/O), so we match all three outcomes
            // EXHAUSTIVELY — the compiler forbids a catch-all `_ => forward` arm, so
            // a future backend variant cannot silently fall through to accept.
            //
            // The claim is built FIRST, before either the replay key or the store
            // call: it owns the canonical (lowercased) payer/nonce pair, so deriving
            // the key from it keeps the replay identity and the ledger's primary key
            // literally the same two strings — they cannot drift apart.
            let claim = Claim::from_payment(&payload, &config.requirements);
            let key = replay_key(&claim);
            // Per-claim TTL from the authorization's OWN validity window: a nonce
            // must be remembered exactly as long as its authorization could still be
            // validly presented, i.e. until `validBefore`. A fixed store-wide TTL
            // (e.g. from `max_timeout_seconds`) would expire the nonce while a
            // longer-dated authorization is still accepted by `verify_payment` above
            // — re-opening the replay this guard exists to close.
            //
            // Fail-SAFE direction: a `validBefore` that will not parse collapses to
            // `u64::MAX`, i.e. a huge TTL = over-remember. Over-remembering can never
            // admit a replay; only under-remembering can. `verify_payment` already
            // proved `now < validBefore`, so `vb - now >= 1` and the TTL is never
            // zero (a zero PX would be rejected by Redis and drop replay protection).
            let vb = claim
                .valid_before
                .as_str()
                .parse::<u64>()
                .unwrap_or(u64::MAX);
            let ttl = std::time::Duration::from_secs(vb.saturating_sub(now));
            match config.store.claim(&key, ttl).await {
                // Fresh nonce: paid, verified, first sighting. Record what we are
                // owed, THEN forward. The order is load-bearing in both directions:
                // recording before the nonce claim would persist replays, and
                // recording after the response would mean a request could be served
                // and paid for with no durable record of the money owed.
                Ok(true) => {
                    // Only the nonce is ever logged as the claim's correlator: the
                    // payer address, the replay key and the signature are all off
                    // limits (ADR-0020), which is also why `Claim` is not `Debug`.
                    if let Some(ledger) = &config.ledger {
                        match ledger.record(&claim).await {
                            Ok(true) => {
                                tracing::info!(nonce = claim.nonce.as_str(), "claim recorded");
                            }
                            // The nonce store said "fresh" and the ledger said
                            // "already there": the two stores disagree, and only one
                            // of them can be right. The nonce store is the one that
                            // FORGETS — an in-memory store across a restart, an
                            // expired or flushed Redis key — while the row is
                            // forever, so the ledger is authoritative on replay.
                            // Reject with the nonce store's own replay answer, byte
                            // for byte: a client must not learn which store caught it.
                            Ok(false) => {
                                tracing::warn!(
                                    nonce = claim.nonce.as_str(),
                                    "claim already in ledger; replay store and ledger diverged"
                                );
                                return Ok(challenge_402(
                                    &config.requirements,
                                    Some("payment nonce already used"),
                                ));
                            }
                            // Fail CLOSED, exactly like the nonce store: a payment we
                            // cannot record is money we cannot collect, so we must not
                            // serve the request. Same fixed 503 body as a nonce-store
                            // outage, deliberately — a client must not be able to tell
                            // which backend is down.
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    nonce = claim.nonce.as_str(),
                                    "claim ledger record failed"
                                );
                                return Ok(store_unavailable_503());
                            }
                        }
                    }
                    inner.call(req).await
                }
                // Already claimed: this authorization was spent -> replay, reject 402.
                Ok(false) => Ok(challenge_402(
                    &config.requirements,
                    Some("payment nonce already used"),
                )),
                // Backend outage: we can neither confirm nor deny a replay, so we
                // FAIL CLOSED — a store we cannot reach must never accept on doubt.
                // Log the failure (never the replay key or any secret; ADR-0020)
                // BEFORE building the 503, and convert to `Ok(Response)` so it never
                // bubbles as `S::Error` and never reaches `inner.call`.
                Err(e) => {
                    tracing::error!(error = %e, "nonce store claim failed");
                    Ok(store_unavailable_503())
                }
            }
        })
    }
}

/// Current unix time in whole seconds; falls back to 0 if the clock is before
/// the epoch (which would fail every timing check downstream — the safe default).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Canonical replay identity: the claim's `(payer, nonce)` pair joined by a colon.
/// EIP-3009 nonces are per-authorizer and address casing is non-semantic, so the
/// key must be lowercased — but it is lowercased in `Claim::from_payment` and
/// NOWHERE ELSE, so the replay key and the ledger's primary key are the same
/// canonical strings by construction rather than by two agreeing conventions.
fn replay_key(claim: &Claim) -> String {
    format!("{}:{}", claim.payer.as_str(), claim.nonce.as_str())
}

/// 402 + serialized `Challenge` JSON. `Content-Type: application/json`. NO `WWW-Authenticate`.
/// `reason` (when Some) becomes the challenge's `error` field via `Challenge::with_error`.
fn challenge_402(requirements: &PaymentRequirements, reason: Option<&str>) -> Response {
    let mut challenge = Challenge::new(vec![requirements.clone()]);
    if let Some(reason) = reason {
        challenge = challenge.with_error(reason);
    }

    // `Challenge` is composed entirely of serializable owned data, so encoding
    // cannot fail in practice; `expect` documents that invariant.
    let body = serde_json::to_string(&challenge).expect("Challenge serializes to JSON");

    Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static 402 challenge response is well-formed")
}

/// Fail-closed response for a nonce-store backend outage. Distinct from
/// `challenge_402`: a store outage is NOT the client's fault and must NOT tell
/// them to (re)pay, so it never carries a payment challenge. Body is a fixed,
/// non-leaking string — no backend/error detail, no Redis text, nothing an
/// attacker could use to fingerprint the store.
fn store_unavailable_503() -> Response {
    // Same `Response`/`Body`/header mechanism as `challenge_402`, but status 503
    // and a hardcoded body — the body is a constant, so there is nothing to encode.
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"error":"service unavailable"}"#))
        .expect("static 503 response is well-formed")
}

/// Coarse, NON-LEAKING mapping. Never surface crypto internals.
fn decode_reason(e: &PaymentDecodeError) -> &'static str {
    match e {
        PaymentDecodeError::Oversized { .. } => "payment header too large",
        PaymentDecodeError::Base64(_) => "payment header is not valid base64",
        PaymentDecodeError::Utf8(_) => "payment payload is not valid UTF-8",
        PaymentDecodeError::Malformed(_) => "payment payload is malformed",
        PaymentDecodeError::UnsupportedVersion { .. } => "unsupported x402 version",
        PaymentDecodeError::UnsupportedScheme(_) => "unsupported payment scheme",
        PaymentDecodeError::UnsupportedNetwork(_) => "unsupported network",
    }
}

/// Curated, NON-LEAKING mapping. The policy-level variants (expired, not-yet-valid,
/// insufficient value, recipient/network/scheme mismatch) map to specific safe
/// strings a client can act on. Every signature/domain/crypto variant collapses to
/// one generic `"payment verification failed"` so no oracle leaks. Do NOT echo the
/// `Display` of crypto errors.
fn verify_reason(e: &VerifyError) -> &'static str {
    match e {
        VerifyError::Expired => "payment authorization expired",
        VerifyError::NotYetValid => "payment authorization not yet valid",
        // Actionable, and it leaks nothing: `maxTimeoutSeconds` is advertised in
        // the challenge the client just read, so the fix is to re-sign inside it.
        VerifyError::ValidityWindowTooLong => "payment authorization is valid for too long",
        VerifyError::InsufficientValue => "payment amount is insufficient",
        VerifyError::RecipientMismatch => "payment recipient does not match",
        VerifyError::NetworkMismatch => "payment network does not match",
        VerifyError::SchemeMismatch => "payment scheme does not match",
        // Every remaining variant reflects a cryptographic/domain-binding fault.
        // Collapsing them to one opaque string denies an attacker an oracle into
        // signature recovery, malleability, or chain-id internals.
        VerifyError::SignatureFormat
        | VerifyError::SignatureMalleable
        | VerifyError::ZeroSigner
        | VerifyError::SignerMismatch
        | VerifyError::MissingDomain
        | VerifyError::DomainField { .. }
        | VerifyError::UnknownChainId(_)
        | VerifyError::FieldOverflow { .. } => "payment verification failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::store::InMemoryNonceStore;
    use tollgate_core::x402::{Network, PaymentPayload, PaymentRequirementsBuilder};
    use tower::{service_fn, Layer as _, ServiceExt as _};

    // Valid newtype fixtures: 40-hex address, 64-hex nonce.
    const PAY_TO: &str = "0x1111111111111111111111111111111111111111";
    const ASSET: &str = "0x2222222222222222222222222222222222222222";

    fn requirements() -> PaymentRequirements {
        PaymentRequirementsBuilder::exact(
            Network::Base,
            PAY_TO.parse().unwrap(),
            ASSET.parse().unwrap(),
            "10000".parse().unwrap(),
            "https://example.com/resource",
            60,
        )
        .build()
    }

    fn config() -> GateConfig {
        GateConfig {
            requirements: requirements(),
            store: NonceBackend::InMemory(InMemoryNonceStore::new()),
            // No ledger: these tests are about the gate's 402 contract. The ledger
            // path needs a real Postgres and is covered end to end in
            // `tollgate-gateway/tests/ledger_e2e.rs`.
            ledger: None,
        }
    }

    /// A trivial inner service that always succeeds with `200 OK`.
    fn ok_service() -> impl tower::Service<
        http::Request<Body>,
        Response = Response,
        Error = std::convert::Infallible,
        Future = impl std::future::Future<Output = Result<Response, std::convert::Infallible>> + Send,
    > + Clone {
        service_fn(|_req: http::Request<Body>| async {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        })
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn missing_payment_header_yields_bare_402() {
        let gate = PaymentLayer::new(config()).layer(ok_service());
        let req = http::Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let resp = gate.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        let json = body_json(resp).await;
        assert!(json.get("x402Version").is_some(), "must advertise version");
        assert!(
            json.get("error").is_none(),
            "an unpaid request is not an error"
        );
    }

    #[tokio::test]
    async fn malformed_payment_header_yields_402_with_error() {
        let gate = PaymentLayer::new(config()).layer(ok_service());
        let req = http::Request::builder()
            .uri("/")
            .header("x-payment", "not-base64!!")
            .body(Body::empty())
            .unwrap();

        let resp = gate.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        let json = body_json(resp).await;
        assert!(
            json.get("error").is_some(),
            "a decode failure must explain itself"
        );
    }

    #[test]
    fn replay_key_lowercases_and_joins() {
        // Built from a MIXED-CASE authorization, the way the gate builds it: the key
        // must come out fully lowercased even though nothing in `replay_key` itself
        // lowercases anything any more.
        let payload: PaymentPayload = serde_json::from_value(serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base",
            "payload": {
                "signature": "0xdeadbeef",
                "authorization": {
                    "from": "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "to": PAY_TO,
                    "value": "10000",
                    "validAfter": "0",
                    "validBefore": "9999999999",
                    "nonce": "0xABCDEF0000000000000000000000000000000000000000000000000000000000",
                },
            },
        }))
        .unwrap();
        let claim = Claim::from_payment(&payload, &requirements());
        assert_eq!(
            replay_key(&claim),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0xabcdef0000000000000000000000000000000000000000000000000000000000"
        );
    }

    // The fail-closed 503 must be a 503 JSON response whose body leaks NOTHING
    // about the backend — no error/Redis detail an attacker could fingerprint.
    #[tokio::test]
    async fn store_unavailable_503_is_503_json_and_non_leaking() {
        let resp = store_unavailable_503();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        // Exact fixed body: pins the non-leaking contract and doubles as a check
        // that no backend text ("redis", the error `Display`, a URL) slips in.
        assert_eq!(body, r#"{"error":"service unavailable"}"#);
        let lower = body.to_ascii_lowercase();
        assert!(!lower.contains("redis"), "must not name the backend");
        assert!(!lower.contains("backend"), "must not leak backend detail");
    }
}
