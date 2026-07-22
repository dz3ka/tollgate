//! Error types for x402 field validation and `X-PAYMENT` header decoding.

/// A wire field failed structural validation while converting from its string
/// form into a validated newtype.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FieldFormatError {
    /// The value was empty but a non-empty string was required.
    #[error("field value must not be empty")]
    Empty,
    /// A decimal string exceeded the maximum permitted number of digits.
    #[error("decimal field exceeds maximum of {max} digits")]
    TooLong {
        /// The maximum number of digits allowed.
        max: usize,
    },
    /// The value was not a `0x`-prefixed 40-hex-character EVM address.
    #[error("invalid EVM address: expected 0x followed by 40 hex characters")]
    InvalidAddress,
    /// The value was not a `0x`-prefixed 64-hex-character nonce.
    #[error("invalid nonce: expected 0x followed by 64 hex characters")]
    InvalidNonce,
    /// The value contained characters other than ASCII decimal digits.
    #[error("invalid decimal field: expected ASCII digits only")]
    NotDecimal,
}

/// A raw `X-PAYMENT` header could not be decoded into a validated
/// [`PaymentPayload`](crate::x402::PaymentPayload).
#[derive(Debug, thiserror::Error)]
pub enum PaymentDecodeError {
    /// The header exceeded the maximum accepted size before decoding.
    #[error("X-PAYMENT header too large: {len} bytes exceeds maximum of {max}")]
    Oversized {
        /// The observed header length in bytes.
        len: usize,
        /// The maximum permitted header length in bytes.
        max: usize,
    },
    /// The header was not valid standard base64.
    #[error("X-PAYMENT header is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The base64-decoded bytes were not valid UTF-8.
    #[error("X-PAYMENT payload is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    /// The JSON was malformed or a field failed newtype validation.
    #[error("X-PAYMENT payload is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    /// The payload declared an unsupported `x402Version`.
    #[error("unsupported x402 version: found {found}, expected 1")]
    UnsupportedVersion {
        /// The version found in the payload.
        found: u8,
    },
    /// The payload declared a payment scheme this crate does not support.
    #[error("unsupported payment scheme: {0}")]
    UnsupportedScheme(String),
    /// The payload declared a network this crate does not recognise.
    #[error("unsupported network: {0}")]
    UnsupportedNetwork(String),
}
