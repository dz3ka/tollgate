#![forbid(unsafe_code)]
//! `tollgate-core` is the domain/types foundation crate for tollgate.
//!
//! It holds the shared domain vocabulary and pure logic that higher layers
//! (such as the gateway binary) build on. At M0 scaffold stage it exposes
//! only a version probe used to prove the cross-crate link.

pub mod x402;

/// Returns the crate's semantic version, sourced from Cargo at build time.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::version;

    #[test]
    fn version_reports_crate_version() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
        assert!(!version().is_empty());
    }
}
