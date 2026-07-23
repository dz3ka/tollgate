#![forbid(unsafe_code)]
//! `tollgate-settler` redeems accepted payment claims on-chain.
//!
//! The gateway records every accepted payment in the claims ledger and moves on;
//! nothing in the request path ever touches a blockchain. This crate is the other
//! end of that split — it reads what is still owed and replays each payer's
//! EIP-3009 authorization against the token contract, turning a signature the
//! operator holds into actual funds.
//!
//! Three modules, one per concern: configuration ([`config`]), the chain client
//! ([`chain`]), and the sweep policy that joins them to the claims ledger
//! ([`worker`]). The binary is a thin shell around [`worker::run`].

pub mod chain;
pub mod config;
pub mod worker;

pub use chain::{Redemption, SettleError, SettlementClient};
pub use config::SettlerConfig;
pub use worker::{run, settle_batch, Shutdown, SweepReport};
