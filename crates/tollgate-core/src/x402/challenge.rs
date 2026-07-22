//! 402-challenge generation: the `Challenge` response body and an ergonomic
//! builder for `PaymentRequirements`.

use serde::{Deserialize, Serialize};

use super::types::{EvmAddress, Network, PaymentRequirements, Scheme, UintStr};
use super::X402_VERSION;

/// The body of an HTTP 402 response: the offers a client may pay to proceed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// The x402 protocol version this challenge speaks.
    pub x402_version: u8,
    /// The accepted-payment options; a client satisfies any one of them.
    pub accepts: Vec<PaymentRequirements>,
    /// Optional human-readable error explaining a prior failed attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional payer hint echoed by clients; tolerated and ignored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<serde_json::Value>,
}

impl Challenge {
    /// Builds a fresh challenge over `accepts`, stamping the current
    /// [`X402_VERSION`](crate::x402::X402_VERSION) with no error or payer.
    #[must_use]
    pub fn new(accepts: Vec<PaymentRequirements>) -> Self {
        Self {
            x402_version: X402_VERSION,
            accepts,
            error: None,
            payer: None,
        }
    }

    /// Attaches a human-readable error message, consuming and returning `self`.
    #[must_use]
    pub fn with_error(mut self, msg: impl Into<String>) -> Self {
        self.error = Some(msg.into());
        self
    }
}

/// Fluent builder for [`PaymentRequirements`] with sensible defaults.
///
/// The scheme is hard-coded to [`Scheme::Exact`] because protocol version 1
/// defines only the `exact` scheme; string fields default to empty and the
/// optional JSON fields default to absent.
#[derive(Debug, Clone)]
pub struct PaymentRequirementsBuilder {
    inner: PaymentRequirements,
}

impl PaymentRequirementsBuilder {
    /// Starts an `exact`-scheme requirement with the mandatory fields set and
    /// all optional fields at their defaults.
    #[must_use]
    pub fn exact(
        network: Network,
        pay_to: EvmAddress,
        asset: EvmAddress,
        max_amount_required: UintStr,
        resource: impl Into<String>,
        max_timeout_seconds: u64,
    ) -> Self {
        Self {
            inner: PaymentRequirements {
                scheme: Scheme::Exact,
                network,
                max_amount_required,
                resource: resource.into(),
                description: String::new(),
                mime_type: String::new(),
                output_schema: None,
                pay_to,
                max_timeout_seconds,
                asset,
                extra: None,
            },
        }
    }

    /// Sets the human-readable resource description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.inner.description = description.into();
        self
    }

    /// Sets the resource's MIME type.
    #[must_use]
    pub fn mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.inner.mime_type = mime_type.into();
        self
    }

    /// Sets the optional output JSON schema.
    #[must_use]
    pub fn output_schema(mut self, output_schema: serde_json::Value) -> Self {
        self.inner.output_schema = Some(output_schema);
        self
    }

    /// Sets the optional scheme-specific extra data.
    #[must_use]
    pub fn extra(mut self, extra: serde_json::Value) -> Self {
        self.inner.extra = Some(extra);
        self
    }

    /// Finalises the builder into a [`PaymentRequirements`].
    #[must_use]
    pub fn build(self) -> PaymentRequirements {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> EvmAddress {
        s.parse().unwrap()
    }

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirementsBuilder::exact(
            Network::Base,
            addr("0x1111111111111111111111111111111111111111"),
            addr("0x2222222222222222222222222222222222222222"),
            "10000".parse().unwrap(),
            "https://example.com/resource",
            60,
        )
        .description("a thing")
        .build()
    }

    #[test]
    fn builder_serializes_expected_keys() {
        let value = serde_json::to_value(sample_requirements()).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj["maxAmountRequired"], serde_json::json!("10000"));
        assert!(obj["payTo"].is_string());
        assert_eq!(obj["maxTimeoutSeconds"], serde_json::json!(60));
        assert!(obj["maxTimeoutSeconds"].is_number());
        assert_eq!(obj["scheme"], serde_json::json!("exact"));
        assert!(!obj.contains_key("outputSchema"));
        assert!(!obj.contains_key("extra"));
    }

    #[test]
    fn challenge_new_omits_optionals() {
        let ch = Challenge::new(vec![sample_requirements()]);
        let value = serde_json::to_value(&ch).unwrap();
        let obj = value.as_object().unwrap();
        assert_eq!(obj["x402Version"], serde_json::json!(1));
        assert!(!obj.contains_key("error"));
        assert!(!obj.contains_key("payer"));
    }

    #[test]
    fn challenge_with_error_includes_error() {
        let ch = Challenge::new(vec![sample_requirements()]).with_error("payment expired");
        let value = serde_json::to_value(&ch).unwrap();
        assert_eq!(value["error"], serde_json::json!("payment expired"));
    }

    #[test]
    fn challenge_round_trips() {
        let ch = Challenge::new(vec![sample_requirements()]).with_error("nope");
        let json = serde_json::to_string(&ch).unwrap();
        let back: Challenge = serde_json::from_str(&json).unwrap();
        assert_eq!(ch, back);
    }
}
