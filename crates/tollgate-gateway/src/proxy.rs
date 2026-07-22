//! The reverse-proxy fallback: forward an already-paid request to the fixed
//! operator-configured upstream.
//!
//! By the time a request reaches this handler the [`PaymentLayer`] has already
//! verified payment, so the proxy's job is purely transport: rewrite the path
//! onto the upstream base, scrub hop-by-hop and payment headers, and relay the
//! response. Two failure modes map to distinct statuses — an upstream that is
//! too slow yields 504, one that cannot be reached yields 502.
//!
//! [`PaymentLayer`]: tollgate_middleware::PaymentLayer

use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderName, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// A hyper-util legacy client over a plain-HTTP connector. M3 does not ship a
/// TLS connector (that is M6), so only `http://` upstreams are dialled.
type HttpClient = Client<HttpConnector, Body>;

/// RFC 7230 §6.1 hop-by-hop headers, which describe a single transport hop and
/// must never be forwarded across a proxy.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Shared proxy state carried as axum [`State`]: the fixed upstream base, the
/// per-request timeout, and a reusable connection-pooling client.
#[derive(Clone)]
pub(crate) struct ProxyCtx {
    /// The fixed upstream base. Its scheme+authority are the ONLY ones dialled.
    upstream: Uri,
    /// How long to await the upstream before giving up with a 504.
    timeout: Duration,
    /// Pooled HTTP client; cloning shares the underlying connection pool.
    client: HttpClient,
}

impl ProxyCtx {
    /// Builds a context around a fresh pooled client bound to the tokio runtime.
    pub(crate) fn new(upstream: Uri, timeout: Duration) -> Self {
        let client = Client::builder(TokioExecutor::new()).build_http();
        Self {
            upstream,
            timeout,
            client,
        }
    }
}

/// Forward a paid request to the configured upstream and relay the response.
pub(crate) async fn proxy(State(ctx): State<ProxyCtx>, req: Request) -> Response {
    let (mut parts, body) = req.into_parts();

    // SSRF GUARD: the upstream scheme+authority come solely from config; only
    // the path+query travel from the incoming request. A request-supplied host
    // can never redirect where we dial.
    let Some(upstream_uri) = build_upstream_uri(&ctx.upstream, &parts.uri) else {
        // Unreachable given a config-validated base + a parsed request URI, but
        // we never panic on the request path.
        tracing::error!("failed to rewrite request URI onto upstream base");
        return StatusCode::BAD_GATEWAY.into_response();
    };

    // Values captured for logging BEFORE the request is consumed. Only
    // method/path are logged — never headers, never the X-PAYMENT proof.
    let method = parts.method.clone();
    let path = upstream_uri.path().to_owned();

    strip_request_headers(&mut parts.headers);
    // The dial target is fixed by config, so the client's Host must not leak
    // upstream — rewrite it to the real upstream authority (matches its vhost).
    match ctx.upstream.authority() {
        Some(authority) => {
            // `authority.as_str()` is always a valid header value (ASCII host[:port]).
            parts.headers.insert(
                header::HOST,
                http::HeaderValue::from_str(authority.as_str())
                    .expect("upstream authority is a valid Host header value"),
            );
        }
        // Config validation guarantees an authority; drop Host rather than panic.
        None => {
            parts.headers.remove(header::HOST);
        }
    }
    parts.uri = upstream_uri;
    let outbound = Request::from_parts(parts, body);

    match tokio::time::timeout(ctx.timeout, ctx.client.request(outbound)).await {
        // The timeout elapsed before the upstream answered.
        Err(_elapsed) => {
            tracing::warn!(%method, path, "upstream timed out");
            StatusCode::GATEWAY_TIMEOUT.into_response()
        }
        // The client reached a transport/connection error.
        Ok(Err(err)) => {
            tracing::warn!(%method, path, error = %err, "upstream request failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
        // A response came back; relay it, scrubbing hop-by-hop headers it set.
        Ok(Ok(upstream_response)) => {
            let (mut head, body) = upstream_response.into_parts();
            strip_hop_by_hop(&mut head.headers);
            tracing::debug!(%method, path, status = head.status.as_u16(), "proxied upstream response");
            Response::from_parts(head, Body::new(body))
        }
    }
}

/// Builds the upstream URI: scheme+authority from `base`, path+query from
/// `incoming`. Returns `None` only if the recombination is somehow invalid.
fn build_upstream_uri(base: &Uri, incoming: &Uri) -> Option<Uri> {
    let mut parts = base.clone().into_parts();
    parts.path_and_query = Some(
        incoming
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| http::uri::PathAndQuery::from_static("/")),
    );
    Uri::from_parts(parts).ok()
}

/// Scrubs everything that must not cross the proxy on the way upstream:
/// hop-by-hop headers plus the payment proof, which is for the gateway alone.
fn strip_request_headers(headers: &mut HeaderMap) {
    strip_hop_by_hop(headers);
    headers.remove("x-payment");
}

/// Removes the fixed RFC 7230 hop-by-hop headers, plus any header the
/// `Connection` header itself names as connection-specific.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // The Connection header may list further per-hop header names; collect them
    // before removing Connection itself.
    let listed: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();

    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}
