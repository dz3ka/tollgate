#![forbid(unsafe_code)]
//! `tollgate-middleware` gates an [`axum`] service behind the x402 payment flow.
//!
//! The crate provides a [`tower`] [`Layer`](tower::Layer) —
//! [`PaymentLayer`] — that wraps any inner service in a [`PaymentGate`]. The
//! gate inspects each request's `X-PAYMENT` header, decodes and verifies the
//! payment against a fixed set of [`PaymentRequirements`], guards against nonce
//! replay via an [`InMemoryNonceStore`], and only then forwards the request to
//! the inner service. Any failure short-circuits with a 402 challenge response
//! instead — the client is told what to pay and (when useful) why the last
//! attempt was rejected.
//!
//! [`PaymentRequirements`]: tollgate_core::x402::PaymentRequirements

mod gate;
mod store;

pub use gate::{GateConfig, PaymentGate, PaymentLayer};
pub use store::{InMemoryNonceStore, NonceBackend, NonceStore, NonceStoreError, RedisNonceStore};
