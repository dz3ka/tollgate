//! `X-PAYMENT` header decoding: base64 -> UTF-8 -> JSON -> validated payload,
//! followed by protocol-level version/scheme/network checks. No cryptography
//! (signature verification is deferred to M2).

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::error::PaymentDecodeError;
use super::types::{EvmAddress, Network, Nonce, Scheme, UintStr};
use super::{MAX_PAYMENT_HEADER_BYTES, X402_VERSION};

/// A decoded `X-PAYMENT` payload proving a client's intent to pay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// The x402 protocol version the payload speaks.
    pub x402_version: u8,
    /// The payment scheme (protocol v1: `exact`).
    pub scheme: Scheme,
    /// The network the payment settles on.
    pub network: Network,
    /// The scheme-specific payload; for `exact`/EVM this is the authorization.
    pub payload: ExactEvmPayload,
}

/// The `exact`-scheme EVM payload: an EIP-3009 authorization plus its
/// signature. The signature is retained verbatim; its cryptographic
/// verification is out of scope for M1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactEvmPayload {
    /// The client's signature over the authorization (validated in M2).
    pub signature: String,
    /// The EIP-3009 transfer authorization.
    pub authorization: ExactEvmPayloadAuthorization,
}

/// The EIP-3009 `transferWithAuthorization` fields the client committed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactEvmPayloadAuthorization {
    /// The payer's address.
    pub from: EvmAddress,
    /// The recipient's address.
    pub to: EvmAddress,
    /// The transfer amount in the asset's base units.
    pub value: UintStr,
    /// Unix seconds before which the authorization is not yet valid.
    pub valid_after: UintStr,
    /// Unix seconds after which the authorization has expired.
    pub valid_before: UintStr,
    /// The replay-protection nonce.
    pub nonce: Nonce,
}

/// Decodes a raw `X-PAYMENT` header value into a validated [`PaymentPayload`].
///
/// The header is size-checked, then standard-base64 decoded, UTF-8 decoded,
/// JSON parsed (which also enforces field-newtype validation), and finally
/// checked against the supported protocol version, scheme, and network.
///
/// # Errors
/// Returns [`PaymentDecodeError`] when:
/// - the header exceeds [`MAX_PAYMENT_HEADER_BYTES`] ([`Oversized`](PaymentDecodeError::Oversized)),
/// - it is not valid standard base64 ([`Base64`](PaymentDecodeError::Base64)),
/// - the bytes are not UTF-8 ([`Utf8`](PaymentDecodeError::Utf8)),
/// - the JSON is malformed or a field fails validation ([`Malformed`](PaymentDecodeError::Malformed)),
/// - the version is not 1 ([`UnsupportedVersion`](PaymentDecodeError::UnsupportedVersion)),
/// - the scheme is unrecognised ([`UnsupportedScheme`](PaymentDecodeError::UnsupportedScheme)), or
/// - the network is unrecognised ([`UnsupportedNetwork`](PaymentDecodeError::UnsupportedNetwork)).
pub fn decode_payment_header(header: &str) -> Result<PaymentPayload, PaymentDecodeError> {
    if header.len() > MAX_PAYMENT_HEADER_BYTES {
        return Err(PaymentDecodeError::Oversized {
            len: header.len(),
            max: MAX_PAYMENT_HEADER_BYTES,
        });
    }

    let bytes = base64::engine::general_purpose::STANDARD.decode(header)?;
    let json = std::str::from_utf8(&bytes)?;
    let payload: PaymentPayload = serde_json::from_str(json)?;

    if payload.x402_version != X402_VERSION {
        return Err(PaymentDecodeError::UnsupportedVersion {
            found: payload.x402_version,
        });
    }

    match payload.scheme {
        Scheme::Exact => {}
        Scheme::Unknown(ref s) => {
            return Err(PaymentDecodeError::UnsupportedScheme(s.clone()));
        }
    }

    match payload.network {
        Network::Base
        | Network::BaseSepolia
        | Network::Avalanche
        | Network::AvalancheFuji
        | Network::Polygon
        | Network::PolygonAmoy
        | Network::Solana
        | Network::SolanaDevnet
        | Network::Sei
        | Network::SeiTestnet
        | Network::Iotex
        | Network::Abstract
        | Network::AbstractTestnet
        | Network::Peaq
        | Network::Story
        | Network::Educhain
        | Network::SkaleBaseSepolia => {}
        Network::Unknown(ref s) => {
            return Err(PaymentDecodeError::UnsupportedNetwork(s.clone()));
        }
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDR: &str = "0x1111111111111111111111111111111111111111";
    const NONCE64: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    fn encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    fn sample_json() -> String {
        format!(
            r#"{{"x402Version":1,"scheme":"exact","network":"base","payload":{{"signature":"0xdeadbeef","authorization":{{"from":"{ADDR}","to":"{ADDR}","value":"1000","validAfter":"0","validBefore":"9999999999","nonce":"{NONCE64}"}}}}}}"#
        )
    }

    #[test]
    fn round_trips_valid_payload() {
        let header = encode(&sample_json());
        let payload = decode_payment_header(&header).unwrap();
        let reencoded = encode(&serde_json::to_string(&payload).unwrap());
        let again = decode_payment_header(&reencoded).unwrap();
        assert_eq!(payload, again);
        assert_eq!(payload.scheme, Scheme::Exact);
        assert_eq!(payload.network, Network::Base);
    }

    #[test]
    fn rejects_oversized() {
        let big = "A".repeat(MAX_PAYMENT_HEADER_BYTES + 1);
        assert!(matches!(
            decode_payment_header(&big),
            Err(PaymentDecodeError::Oversized { .. })
        ));
    }

    #[test]
    fn rejects_invalid_base64() {
        assert!(matches!(
            decode_payment_header("not!valid!base64!"),
            Err(PaymentDecodeError::Base64(_))
        ));
    }

    #[test]
    fn rejects_non_utf8() {
        let header = base64::engine::general_purpose::STANDARD.encode([0xff, 0xfe, 0xfd]);
        assert!(matches!(
            decode_payment_header(&header),
            Err(PaymentDecodeError::Utf8(_))
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        let header = encode("{not json");
        assert!(matches!(
            decode_payment_header(&header),
            Err(PaymentDecodeError::Malformed(_))
        ));
    }

    #[test]
    fn field_validation_failures_are_malformed() {
        // Bad nonce (too short), bad address, and non-decimal value each
        // surface through serde as Malformed.
        let bad_nonce = sample_json().replace(NONCE64, "0x1234");
        let bad_addr = sample_json().replace(ADDR, "0xnothex");
        let bad_value = sample_json().replace(r#""value":"1000""#, r#""value":"12a""#);
        for json in [bad_nonce, bad_addr, bad_value] {
            assert!(matches!(
                decode_payment_header(&encode(&json)),
                Err(PaymentDecodeError::Malformed(_))
            ));
        }
    }

    #[test]
    fn rejects_unsupported_version() {
        let json = sample_json().replace(r#""x402Version":1"#, r#""x402Version":2"#);
        assert!(matches!(
            decode_payment_header(&encode(&json)),
            Err(PaymentDecodeError::UnsupportedVersion { found: 2 })
        ));
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let json = sample_json().replace(r#""scheme":"exact""#, r#""scheme":"upto""#);
        assert!(matches!(
            decode_payment_header(&encode(&json)),
            Err(PaymentDecodeError::UnsupportedScheme(s)) if s == "upto"
        ));
    }

    #[test]
    fn rejects_unsupported_network() {
        let json = sample_json().replace(r#""network":"base""#, r#""network":"ethereum""#);
        assert!(matches!(
            decode_payment_header(&encode(&json)),
            Err(PaymentDecodeError::UnsupportedNetwork(s)) if s == "ethereum"
        ));
    }

    #[test]
    fn nonce_boundary_63_rejected_64_accepted() {
        let nonce63 = "0x111111111111111111111111111111111111111111111111111111111111111";
        let json63 = sample_json().replace(NONCE64, nonce63);
        assert!(matches!(
            decode_payment_header(&encode(&json63)),
            Err(PaymentDecodeError::Malformed(_))
        ));
        // 64 accepted is covered by round_trips_valid_payload.
        assert!(decode_payment_header(&encode(&sample_json())).is_ok());
    }

    #[test]
    fn tolerates_unknown_authorization_key() {
        // Proves there is no `deny_unknown_fields`: an extra key parses fine.
        let json = sample_json().replace(
            &format!(r#""nonce":"{NONCE64}""#),
            &format!(r#""nonce":"{NONCE64}","futureField":true"#),
        );
        assert!(decode_payment_header(&encode(&json)).is_ok());
    }
}
