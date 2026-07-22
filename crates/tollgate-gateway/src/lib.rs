#![forbid(unsafe_code)]
//! Library face of `tollgate-gateway`, exposing the server entry point and its
//! configuration so integration tests (and future embedders) can drive the
//! gateway in-process. The `main.rs` binary remains the production entry point;
//! this crate root simply re-exports the same modules as a linkable library.

pub mod config;
mod proxy;
pub mod server;

pub use config::GatewayConfig;
pub use server::run;
