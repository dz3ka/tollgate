//! x402 protocol wire types, 402-challenge generation, and X-PAYMENT decoding.
//!
//! Pinned to x402 protocol version 1. The authoritative wire contract is the
//! legacy zod schemas in coinbase/x402 at the revision in `SPEC_REVISION`;
//! the prose specs have drifted toward v2 and are NOT authoritative here.

mod challenge;
mod error;
mod payment;
mod types;
mod verify;

pub use challenge::*;
pub use error::*;
pub use payment::*;
pub use types::*;
pub use verify::*;

/// The x402 protocol version this crate implements on the wire.
pub const X402_VERSION: u8 = 1;

/// The coinbase/x402 git revision whose zod schemas this crate is pinned to.
pub const SPEC_REVISION: &str = "coinbase/x402@dd927a26cfefc98c24b3ec38b3a8f204dad0c60d";

/// Maximum accepted size, in bytes, of a raw `X-PAYMENT` header (`DoS` guard).
pub const MAX_PAYMENT_HEADER_BYTES: usize = 8 * 1024;

/// Maximum decimal digits permitted in a `UintStr` (U256 max is 78 digits).
pub const MAX_UINT_DIGITS: usize = 78; // U256 max is 78 decimal digits
