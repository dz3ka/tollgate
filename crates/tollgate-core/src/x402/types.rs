//! x402 wire value types: schemes, networks, validated string newtypes, and
//! the `PaymentRequirements` accepted-payment descriptor.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::error::FieldFormatError;
use super::MAX_UINT_DIGITS;

/// The payment scheme of an x402 offer. Protocol version 1 defines only
/// `exact`; any other wire string is preserved as [`Scheme::Unknown`] for
/// forward compatibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum Scheme {
    /// The `exact` scheme: pay a fixed amount to a fixed recipient.
    Exact,
    /// Any scheme string not recognised by this crate.
    Unknown(String),
}

impl From<String> for Scheme {
    fn from(value: String) -> Self {
        match value.as_str() {
            "exact" => Self::Exact,
            _ => Self::Unknown(value),
        }
    }
}

impl From<Scheme> for String {
    fn from(value: Scheme) -> Self {
        match value {
            Scheme::Exact => "exact".to_owned(),
            Scheme::Unknown(s) => s,
        }
    }
}

/// A blockchain network identifier. Known variants map to fixed kebab-case
/// wire strings; unrecognised strings are preserved as [`Network::Unknown`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum Network {
    /// Base mainnet (`base`).
    Base,
    /// Base Sepolia testnet (`base-sepolia`).
    BaseSepolia,
    /// Avalanche C-Chain mainnet (`avalanche`).
    Avalanche,
    /// Avalanche Fuji testnet (`avalanche-fuji`).
    AvalancheFuji,
    /// Polygon mainnet (`polygon`).
    Polygon,
    /// Polygon Amoy testnet (`polygon-amoy`).
    PolygonAmoy,
    /// Solana mainnet (`solana`).
    Solana,
    /// Solana Devnet (`solana-devnet`).
    SolanaDevnet,
    /// Sei mainnet (`sei`).
    Sei,
    /// Sei testnet (`sei-testnet`).
    SeiTestnet,
    /// `IoTeX` mainnet (`iotex`).
    Iotex,
    /// Abstract mainnet (`abstract`).
    Abstract,
    /// Abstract testnet (`abstract-testnet`).
    AbstractTestnet,
    /// peaq mainnet (`peaq`).
    Peaq,
    /// Story mainnet (`story`).
    Story,
    /// EDU Chain (`educhain`).
    Educhain,
    /// SKALE Base Sepolia (`skale-base-sepolia`).
    SkaleBaseSepolia,
    /// Any network string not recognised by this crate.
    Unknown(String),
}

impl From<String> for Network {
    fn from(value: String) -> Self {
        match value.as_str() {
            "base" => Self::Base,
            "base-sepolia" => Self::BaseSepolia,
            "avalanche" => Self::Avalanche,
            "avalanche-fuji" => Self::AvalancheFuji,
            "polygon" => Self::Polygon,
            "polygon-amoy" => Self::PolygonAmoy,
            "solana" => Self::Solana,
            "solana-devnet" => Self::SolanaDevnet,
            "sei" => Self::Sei,
            "sei-testnet" => Self::SeiTestnet,
            "iotex" => Self::Iotex,
            "abstract" => Self::Abstract,
            "abstract-testnet" => Self::AbstractTestnet,
            "peaq" => Self::Peaq,
            "story" => Self::Story,
            "educhain" => Self::Educhain,
            "skale-base-sepolia" => Self::SkaleBaseSepolia,
            _ => Self::Unknown(value),
        }
    }
}

impl From<Network> for String {
    fn from(value: Network) -> Self {
        match value {
            Network::Base => "base",
            Network::BaseSepolia => "base-sepolia",
            Network::Avalanche => "avalanche",
            Network::AvalancheFuji => "avalanche-fuji",
            Network::Polygon => "polygon",
            Network::PolygonAmoy => "polygon-amoy",
            Network::Solana => "solana",
            Network::SolanaDevnet => "solana-devnet",
            Network::Sei => "sei",
            Network::SeiTestnet => "sei-testnet",
            Network::Iotex => "iotex",
            Network::Abstract => "abstract",
            Network::AbstractTestnet => "abstract-testnet",
            Network::Peaq => "peaq",
            Network::Story => "story",
            Network::Educhain => "educhain",
            Network::SkaleBaseSepolia => "skale-base-sepolia",
            Network::Unknown(s) => return s,
        }
        .to_owned()
    }
}

/// Returns `true` iff `s` is exactly `0x` followed by `expected_hex_len`
/// ASCII hexadecimal characters.
fn is_hex_with_prefix(s: &str, expected_hex_len: usize) -> bool {
    let Some(hex) = s.strip_prefix("0x") else {
        return false;
    };
    hex.len() == expected_hex_len && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// An EVM address: `0x` followed by exactly 40 hex characters.
///
/// Original casing is preserved (EIP-55 checksums are meaningful later).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EvmAddress(String);

impl EvmAddress {
    /// Returns the address as its original-cased `0x`-prefixed string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EvmAddress {
    type Error = FieldFormatError;

    /// # Errors
    /// Returns [`FieldFormatError::InvalidAddress`] if `value` is not `0x`
    /// followed by exactly 40 hex characters.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_hex_with_prefix(&value, 40) {
            Ok(Self(value))
        } else {
            Err(FieldFormatError::InvalidAddress)
        }
    }
}

impl FromStr for EvmAddress {
    type Err = FieldFormatError;

    /// # Errors
    /// Returns [`FieldFormatError::InvalidAddress`] if `s` is not `0x`
    /// followed by exactly 40 hex characters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl AsRef<str> for EvmAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<EvmAddress> for String {
    fn from(value: EvmAddress) -> Self {
        value.0
    }
}

/// A replay-protection nonce: `0x` followed by exactly 64 hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Nonce(String);

impl Nonce {
    /// Returns the nonce as its `0x`-prefixed hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Nonce {
    type Error = FieldFormatError;

    /// # Errors
    /// Returns [`FieldFormatError::InvalidNonce`] if `value` is not `0x`
    /// followed by exactly 64 hex characters.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_hex_with_prefix(&value, 64) {
            Ok(Self(value))
        } else {
            Err(FieldFormatError::InvalidNonce)
        }
    }
}

impl FromStr for Nonce {
    type Err = FieldFormatError;

    /// # Errors
    /// Returns [`FieldFormatError::InvalidNonce`] if `s` is not `0x`
    /// followed by exactly 64 hex characters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<Nonce> for String {
    fn from(value: Nonce) -> Self {
        value.0
    }
}

/// A non-negative integer serialized as a decimal string.
///
/// Accepts a non-empty run of ASCII digits up to
/// [`MAX_UINT_DIGITS`](crate::x402::MAX_UINT_DIGITS) long. This single newtype
/// covers `maxAmountRequired`, `value`, `validAfter` and `validBefore`. The
/// spec documents `value` as <=18 digits and validAfter/validBefore as unix
/// seconds; M1 uses one U256-width guard for simplicity, deferring tighter
/// per-field bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UintStr(String);

impl UintStr {
    /// Returns the value as its decimal string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for UintStr {
    type Error = FieldFormatError;

    /// # Errors
    /// Returns [`FieldFormatError::Empty`] if `value` is empty,
    /// [`FieldFormatError::NotDecimal`] if it contains a non-digit, or
    /// [`FieldFormatError::TooLong`] if it exceeds
    /// [`MAX_UINT_DIGITS`](crate::x402::MAX_UINT_DIGITS) digits.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(FieldFormatError::Empty);
        }
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(FieldFormatError::NotDecimal);
        }
        if value.len() > MAX_UINT_DIGITS {
            return Err(FieldFormatError::TooLong {
                max: MAX_UINT_DIGITS,
            });
        }
        Ok(Self(value))
    }
}

impl FromStr for UintStr {
    type Err = FieldFormatError;

    /// # Errors
    /// Returns [`FieldFormatError::Empty`], [`FieldFormatError::NotDecimal`],
    /// or [`FieldFormatError::TooLong`] per [`UintStr::try_from`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl AsRef<str> for UintStr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<UintStr> for String {
    fn from(value: UintStr) -> Self {
        value.0
    }
}

/// A single accepted-payment descriptor advertised in a 402 challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// The payment scheme (protocol v1: always `exact`).
    pub scheme: Scheme,
    /// The network the payment must settle on.
    pub network: Network,
    /// The exact amount required, in the asset's base units.
    pub max_amount_required: UintStr,
    /// The resource URL being gated.
    pub resource: String,
    /// Human-readable description of the resource.
    pub description: String,
    /// MIME type of the gated resource.
    pub mime_type: String,
    /// Optional JSON schema describing the resource's output.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub output_schema: Option<serde_json::Value>,
    /// The recipient address the payment must pay to.
    pub pay_to: EvmAddress,
    /// Maximum seconds the facilitator may take to settle.
    pub max_timeout_seconds: u64,
    /// The asset (token contract) the payment is denominated in.
    pub asset: EvmAddress,
    /// Optional scheme-specific extra data (e.g. EIP-712 domain fields).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub extra: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evm_address_accepts_canonical() {
        let a = "0x1234567890abcdefABCDEF1234567890abcdef12";
        assert_eq!(EvmAddress::from_str(a).unwrap().as_str(), a);
    }

    #[test]
    fn evm_address_rejects_bad_shapes() {
        for bad in [
            "",
            "0x1234567890abcdef1234567890abcdef1234567", // 39 hex
            "0x1234567890abcdef1234567890abcdef123456789", // 41 hex
            "0x1234567890abcdef1234567890abcdef1234567g", // non-hex
            "1234567890abcdef1234567890abcdef12345678",  // no 0x
        ] {
            assert_eq!(
                EvmAddress::from_str(bad),
                Err(FieldFormatError::InvalidAddress),
                "expected reject for {bad:?}"
            );
        }
    }

    #[test]
    fn nonce_accepts_and_rejects_by_length() {
        let good = "0x1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(Nonce::from_str(good).unwrap().as_str(), good);
        let short = "0x111111111111111111111111111111111111111111111111111111111111111"; // 63
        let long = "0x11111111111111111111111111111111111111111111111111111111111111111"; // 65
        assert_eq!(Nonce::from_str(short), Err(FieldFormatError::InvalidNonce));
        assert_eq!(Nonce::from_str(long), Err(FieldFormatError::InvalidNonce));
    }

    #[test]
    fn uintstr_accepts_valid() {
        for good in ["0", "10000", &"9".repeat(78)] {
            assert_eq!(UintStr::from_str(good).unwrap().as_str(), good);
        }
    }

    #[test]
    fn uintstr_rejects_invalid() {
        assert_eq!(UintStr::from_str(""), Err(FieldFormatError::Empty));
        assert_eq!(UintStr::from_str("12a"), Err(FieldFormatError::NotDecimal));
        assert_eq!(
            UintStr::from_str(&"9".repeat(79)),
            Err(FieldFormatError::TooLong { max: 78 })
        );
    }

    #[test]
    fn scheme_round_trips() {
        assert_eq!(serde_json::to_value(Scheme::Exact).unwrap(), "exact");
        let de: Scheme = serde_json::from_value(serde_json::json!("exact")).unwrap();
        assert_eq!(de, Scheme::Exact);
        let unknown: Scheme = serde_json::from_value(serde_json::json!("upto")).unwrap();
        assert_eq!(unknown, Scheme::Unknown("upto".to_owned()));
    }

    #[test]
    fn network_known_variants_round_trip() {
        let cases = [
            (Network::Base, "base"),
            (Network::BaseSepolia, "base-sepolia"),
            (Network::Avalanche, "avalanche"),
            (Network::AvalancheFuji, "avalanche-fuji"),
            (Network::Polygon, "polygon"),
            (Network::PolygonAmoy, "polygon-amoy"),
            (Network::Solana, "solana"),
            (Network::SolanaDevnet, "solana-devnet"),
            (Network::Sei, "sei"),
            (Network::SeiTestnet, "sei-testnet"),
            (Network::Iotex, "iotex"),
            (Network::Abstract, "abstract"),
            (Network::AbstractTestnet, "abstract-testnet"),
            (Network::Peaq, "peaq"),
            (Network::Story, "story"),
            (Network::Educhain, "educhain"),
            (Network::SkaleBaseSepolia, "skale-base-sepolia"),
        ];
        for (variant, wire) in cases {
            assert_eq!(serde_json::to_value(variant.clone()).unwrap(), wire);
            let de: Network = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(de, variant);
        }
    }

    #[test]
    fn network_unknown_deserializes() {
        let de: Network = serde_json::from_value(serde_json::json!("ethereum")).unwrap();
        assert_eq!(de, Network::Unknown("ethereum".to_owned()));
    }
}
