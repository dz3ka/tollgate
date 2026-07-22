//! Offline cryptographic verification of `exact`/EVM x402 payments.
//!
//! This module reconstructs the EIP-712 / EIP-3009
//! `TransferWithAuthorization` digest a client signed, recovers the signer
//! from the supplied secp256k1 signature, and checks it against the
//! authorization plus the server's [`PaymentRequirements`]. It is the only
//! place in the crate that pulls in the alloy/k256 crypto stack; the M1 decode
//! path stays dependency-light. No network access happens here: the caller
//! supplies `now_unix`, so verification is fully deterministic and testable.
//!
//! The EIP-712 hashing is hand-rolled (rather than via `alloy-sol-types`) to
//! keep the production dependency tree trimmed; an in-file oracle test pins the
//! hand-rolled digest against the `sol!`-macro implementation.

use alloy_primitives::{keccak256, Address, Signature, B256, U256};

use super::payment::PaymentPayload;
use super::types::{EvmAddress, Network, Nonce, PaymentRequirements, Scheme, UintStr};

/// A payment failed cryptographic or policy verification.
///
/// Every variant carries only owned/`'static`/plain data, so the type is
/// cheaply comparable (`Eq`) — useful for asserting exact failure modes in
/// tests and for structured error reporting upstream.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    /// The payload scheme did not match the requirements, or was not `exact`.
    #[error("scheme mismatch: payload and requirements must both be the exact scheme")]
    SchemeMismatch,
    /// The payload network did not match the requirements network.
    #[error("network mismatch: payload network differs from requirements network")]
    NetworkMismatch,
    /// The requirements network has no vetted M2 EIP-712 chain id.
    #[error("unknown chain id for network: {0}")]
    UnknownChainId(String),
    /// The requirements carried no `extra` object to source the domain from.
    #[error("missing EIP-712 domain: requirements.extra is absent")]
    MissingDomain,
    /// A required EIP-712 domain field was missing or not a JSON string.
    #[error("invalid EIP-712 domain field: {field} is missing or not a string")]
    DomainField {
        /// The offending domain field name (`name` or `version`).
        field: &'static str,
    },
    /// The authorization `to` did not match the required `payTo` recipient.
    #[error("recipient mismatch: authorization 'to' differs from payTo")]
    RecipientMismatch,
    /// The authorization `value` was below `maxAmountRequired`.
    #[error("insufficient value: authorization value is below the required amount")]
    InsufficientValue,
    /// A decimal `UintStr` field overflowed `U256` while parsing.
    #[error("field overflow: {field} does not fit in a 256-bit unsigned integer")]
    FieldOverflow {
        /// The offending field name (`value`, `validAfter`, or `validBefore`).
        field: &'static str,
    },
    /// The current time is before the authorization's `validAfter`.
    #[error("not yet valid: current time is before validAfter")]
    NotYetValid,
    /// The current time is at or after the authorization's `validBefore`.
    #[error("expired: current time is at or after validBefore")]
    Expired,
    /// The signature was not `0x` + 130 hex, or its `v` byte was out of range.
    #[error("signature format: expected 0x + 130 hex characters with a valid recovery id")]
    SignatureFormat,
    /// The signature used a high-`s` value (EIP-2 malleability).
    #[error("signature malleable: high-s value is rejected per EIP-2")]
    SignatureMalleable,
    /// Recovery yielded the zero address.
    #[error("zero signer: signature recovered the zero address")]
    ZeroSigner,
    /// The recovered signer did not match the authorization `from`.
    #[error("signer mismatch: recovered signer differs from authorization 'from'")]
    SignerMismatch,
}

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// `keccak256("TransferWithAuthorization(...)")` preimage, per EIP-3009.
const TRANSFER_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// Cryptographically verifies an `exact`/EVM x402 payment against the server's
/// requirements at `now_unix` (unix seconds). Offline: no network.
///
/// # Errors
/// Returns [`VerifyError`] if the scheme/network binding, EIP-712 domain
/// sourcing, signer recovery, recipient/amount/timing checks, or signature
/// well-formedness fail. See the individual [`VerifyError`] variants.
pub fn verify_payment(
    payload: &PaymentPayload,
    requirements: &PaymentRequirements,
    now_unix: u64,
) -> Result<(), VerifyError> {
    // 1. Scheme binding: payload and requirements must agree, and be `exact`.
    if payload.scheme != requirements.scheme || payload.scheme != Scheme::Exact {
        return Err(VerifyError::SchemeMismatch);
    }

    // 2. Network binding.
    if payload.network != requirements.network {
        return Err(VerifyError::NetworkMismatch);
    }

    // 3. Chain id: only vetted EIP-712 chain ids are honoured (see `chain_id`).
    let chain_id = chain_id(&requirements.network)
        .ok_or_else(|| VerifyError::UnknownChainId(network_wire(&requirements.network)))?;

    // 4. EIP-712 domain must be sourced from `extra`, never defaulted: the
    //    (name, version) pair is hashed into the signature and thus binds it.
    let extra = requirements
        .extra
        .as_ref()
        .ok_or(VerifyError::MissingDomain)?;
    let name = extra
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerifyError::DomainField { field: "name" })?;
    let version = extra
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or(VerifyError::DomainField { field: "version" })?;

    // 5. Field-level policy checks on the authorization.
    let auth = &payload.payload.authorization;
    let from = addr(&auth.from);
    let to = addr(&auth.to);
    let pay_to = addr(&requirements.pay_to);
    let verifying_contract = addr(&requirements.asset);

    if to != pay_to {
        return Err(VerifyError::RecipientMismatch);
    }

    let value = parse_u256(&auth.value, "value")?;
    let valid_after = parse_u256(&auth.valid_after, "validAfter")?;
    let valid_before = parse_u256(&auth.valid_before, "validBefore")?;
    let required = parse_u256(&requirements.max_amount_required, "maxAmountRequired")?;

    if value < required {
        return Err(VerifyError::InsufficientValue);
    }

    // Compare timing in U256 space to avoid a separate u64 overflow path.
    let now = U256::from(now_unix);
    if now < valid_after {
        return Err(VerifyError::NotYetValid);
    }
    if now >= valid_before {
        return Err(VerifyError::Expired);
    }

    // 6. Reconstruct the digest, recover the signer, and compare to `from`.
    let digest = eip712_digest(
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce_word(&auth.nonce),
        name,
        version,
        chain_id,
        verifying_contract,
    );

    let signer = recover_signer(&payload.payload.signature, &digest)?;
    if signer == Address::ZERO {
        return Err(VerifyError::ZeroSigner);
    }
    if signer != from {
        return Err(VerifyError::SignerMismatch);
    }

    Ok(())
}

/// Maps a supported network to its EIP-712 `chainId`.
///
/// Verify-support is a strict subset of decode-support: a wrong `chainId` would
/// let a signature minted for another chain be accepted here, so only vetted,
/// testnet-targeted ids are listed. Everything else (mainnets we do not settle
/// on, all Solana variants, `Unknown`, other EVM chains) returns `None`.
fn chain_id(net: &Network) -> Option<u64> {
    match net {
        Network::Base => Some(8453),
        Network::BaseSepolia => Some(84_532),
        _ => None,
    }
}

/// Returns a network's wire string, for error reporting.
fn network_wire(net: &Network) -> String {
    net.clone().into()
}

/// Converts a validated [`EvmAddress`] into an alloy [`Address`].
///
/// `EvmAddress` is already `0x` + 40 hex by construction, so the hex decode
/// cannot fail; `Address::from_slice` is used (not `Address::from_str`, which
/// would enforce an EIP-55 checksum and reject valid all-lowercase input).
fn addr(a: &EvmAddress) -> Address {
    let hex = a.as_str().strip_prefix("0x").unwrap_or(a.as_str());
    let bytes =
        alloy_primitives::hex::decode(hex).expect("EvmAddress is validated hex at construction");
    Address::from_slice(&bytes)
}

/// Decodes a validated [`Nonce`] into its raw 32-byte word (used verbatim in
/// the struct hash — the nonce is *not* re-hashed).
fn nonce_word(n: &Nonce) -> B256 {
    let hex = n.as_str().strip_prefix("0x").unwrap_or(n.as_str());
    let bytes =
        alloy_primitives::hex::decode(hex).expect("Nonce is validated 0x + 64 hex at construction");
    B256::from_slice(&bytes)
}

/// Parses a decimal [`UintStr`] into a [`U256`], mapping overflow/parse
/// failures to [`VerifyError::FieldOverflow`].
///
/// # Errors
/// Returns [`VerifyError::FieldOverflow`] tagged with `field` when the decimal
/// string does not fit in a 256-bit unsigned integer.
fn parse_u256(s: &UintStr, field: &'static str) -> Result<U256, VerifyError> {
    U256::from_str_radix(s.as_str(), 10).map_err(|_| VerifyError::FieldOverflow { field })
}

/// Keccak-256 of `words` concatenated as 32-byte big-endian slots.
fn keccak_words(words: &[B256]) -> B256 {
    let mut buf = Vec::with_capacity(words.len() * 32);
    for w in words {
        buf.extend_from_slice(w.as_slice());
    }
    keccak256(buf)
}

/// Builds the EIP-712 `TransferWithAuthorization` signing digest.
///
/// Layout mirrors EIP-712 exactly: a domain separator over
/// `(name, version, chainId, verifyingContract)`, a struct hash over the
/// authorization fields, and the `0x1901`-prefixed final keccak.
#[allow(clippy::too_many_arguments)]
fn eip712_digest(
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Address,
) -> B256 {
    let domain_separator = keccak_words(&[
        keccak256(DOMAIN_TYPE.as_bytes()),
        keccak256(name.as_bytes()),
        keccak256(version.as_bytes()),
        U256::from(chain_id).into(),
        verifying_contract.into_word(),
    ]);

    let struct_hash = keccak_words(&[
        keccak256(TRANSFER_TYPE.as_bytes()),
        from.into_word(),
        to.into_word(),
        value.into(),
        valid_after.into(),
        valid_before.into(),
        nonce,
    ]);

    let mut preimage = [0u8; 66];
    preimage[0] = 0x19;
    preimage[1] = 0x01;
    preimage[2..34].copy_from_slice(domain_separator.as_slice());
    preimage[34..66].copy_from_slice(struct_hash.as_slice());
    keccak256(preimage)
}

/// Parses a `0x`-prefixed 65-byte signature, rejects high-`s` malleability, and
/// recovers the signer address from `digest`.
///
/// # Errors
/// - [`VerifyError::SignatureFormat`] if the string is not `0x` + 130 hex, the
///   recovery id is out of range, or recovery itself fails.
/// - [`VerifyError::SignatureMalleable`] if `s` is in the upper half-order.
fn recover_signer(signature: &str, digest: &B256) -> Result<Address, VerifyError> {
    let hex = signature
        .strip_prefix("0x")
        .ok_or(VerifyError::SignatureFormat)?;
    if hex.len() != 130 {
        return Err(VerifyError::SignatureFormat);
    }
    let bytes = alloy_primitives::hex::decode(hex).map_err(|_| VerifyError::SignatureFormat)?;
    // decode of 130 hex chars yields exactly 65 bytes.

    // Accept v ∈ {27, 28} (EIP-155-free) and raw parity v ∈ {0, 1}.
    let recid = match bytes[64] {
        27 | 28 => bytes[64] - 27,
        v @ (0 | 1) => v,
        _ => return Err(VerifyError::SignatureFormat),
    };

    let r = B256::from_slice(&bytes[0..32]);
    let s = B256::from_slice(&bytes[32..64]);
    let sig = Signature::from_scalars_and_parity(r, s, recid == 1);

    // `normalize_s` returns `Some` only when `s` is high — that is the
    // malleable twin, which we reject outright (security-actionable per EIP-2).
    if sig.normalize_s().is_some() {
        return Err(VerifyError::SignatureMalleable);
    }

    sig.recover_address_from_prehash(digest)
        .map_err(|_| VerifyError::SignatureFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_sol_types::{eip712_domain, sol, SolStruct};
    use k256::ecdsa::SigningKey;

    use crate::x402::payment::{ExactEvmPayload, ExactEvmPayloadAuthorization, PaymentPayload};

    const ASSET: &str = "0x2222222222222222222222222222222222222222";
    const NONCE: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const NAME: &str = "USD Coin";
    const VERSION: &str = "2";
    const NOW: u64 = 1_000;

    // A fixed private key (0x0101..01) makes every signature deterministic.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32].into()).unwrap()
    }

    fn signer_address() -> Address {
        Address::from_public_key(signing_key().verifying_key())
    }

    fn requirements(
        value_required: &str,
        network: Network,
        extra: Option<serde_json::Value>,
    ) -> PaymentRequirements {
        PaymentRequirements {
            scheme: Scheme::Exact,
            network,
            max_amount_required: value_required.parse().unwrap(),
            resource: "https://example.com/r".to_owned(),
            description: String::new(),
            mime_type: String::new(),
            output_schema: None,
            pay_to: PAY_TO.parse().unwrap(),
            max_timeout_seconds: 60,
            asset: ASSET.parse().unwrap(),
            extra,
        }
    }

    const PAY_TO: &str = "0x3333333333333333333333333333333333333333";

    fn default_extra() -> serde_json::Value {
        serde_json::json!({ "name": NAME, "version": VERSION })
    }

    /// Builds a payload whose `from` is `signer_address`, signed over the
    /// digest for the given authorization fields. `mutate` can tamper with the
    /// 65-byte signature bytes before they are hex-encoded.
    fn signed_payload(
        value: &str,
        valid_after: &str,
        valid_before: &str,
        to: &str,
        from: Address,
        mutate: impl Fn(&mut [u8; 65]),
    ) -> PaymentPayload {
        let digest = eip712_digest(
            from,
            addr_from(to),
            U256::from_str_radix(value, 10).unwrap(),
            U256::from_str_radix(valid_after, 10).unwrap(),
            U256::from_str_radix(valid_before, 10).unwrap(),
            nonce_word(&NONCE.parse().unwrap()),
            NAME,
            VERSION,
            8453,
            addr_from(ASSET),
        );

        let (sig, recid) = signing_key()
            .sign_prehash_recoverable(digest.as_slice())
            .unwrap();
        let mut raw = [0u8; 65];
        raw[..64].copy_from_slice(&sig.to_bytes());
        raw[64] = 27 + recid.to_byte();
        mutate(&mut raw);
        let signature = format!("0x{}", alloy_primitives::hex::encode(raw));

        PaymentPayload {
            x402_version: 1,
            scheme: Scheme::Exact,
            network: Network::Base,
            payload: ExactEvmPayload {
                signature,
                authorization: ExactEvmPayloadAuthorization {
                    from: format!("{from}").parse().unwrap(),
                    to: to.parse().unwrap(),
                    value: value.parse().unwrap(),
                    valid_after: valid_after.parse().unwrap(),
                    valid_before: valid_before.parse().unwrap(),
                    nonce: NONCE.parse().unwrap(),
                },
            },
        }
    }

    fn addr_from(s: &str) -> Address {
        addr(&s.parse::<EvmAddress>().unwrap())
    }

    fn valid_payload() -> PaymentPayload {
        signed_payload("1000", "0", "9999999999", PAY_TO, signer_address(), |_| {})
    }

    // ---- Oracle: hand-rolled digest == alloy-sol-types sol! implementation ----

    sol! {
        struct TransferWithAuthorization {
            address from;
            address to;
            uint256 value;
            uint256 validAfter;
            uint256 validBefore;
            bytes32 nonce;
        }
    }

    #[test]
    fn hand_rolled_digest_matches_sol_oracle() {
        let from = signer_address();
        let to = addr_from(PAY_TO);
        let value = U256::from(1000u64);
        let valid_after = U256::from(0u64);
        let valid_before = U256::from(9_999_999_999u64);
        let nonce = nonce_word(&NONCE.parse().unwrap());

        let ours = eip712_digest(
            from,
            to,
            value,
            valid_after,
            valid_before,
            nonce,
            NAME,
            VERSION,
            8453,
            addr_from(ASSET),
        );

        let domain = eip712_domain! {
            name: NAME,
            version: VERSION,
            chain_id: 8453u64,
            verifying_contract: addr_from(ASSET),
        };
        let msg = TransferWithAuthorization {
            from,
            to,
            value,
            validAfter: valid_after,
            validBefore: valid_before,
            nonce,
        };
        let oracle = msg.eip712_signing_hash(&domain);

        assert_eq!(
            ours, oracle,
            "hand-rolled EIP-712 digest must match the sol! oracle"
        );
    }

    // ---- Positive ----

    #[test]
    fn accepts_a_valid_payment() {
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(verify_payment(&valid_payload(), &reqs, NOW), Ok(()));
    }

    // ---- Adversarial ----

    #[test]
    fn tampered_signature_byte_is_signer_mismatch() {
        // Flip a byte inside r: still a well-formed low-s sig, but recovers a
        // different address.
        let payload = signed_payload("1000", "0", "9999999999", PAY_TO, signer_address(), |raw| {
            raw[0] ^= 0x01;
        });
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::SignerMismatch)
        );
    }

    #[test]
    fn from_not_matching_recovered_signer_is_mismatch() {
        // Sign with key A (the fixture key) but claim `from` = a different addr.
        let other = "0x4444444444444444444444444444444444444444";
        let payload = signed_payload("1000", "0", "9999999999", PAY_TO, addr_from(other), |_| {});
        // signed_payload set `from` to `other`, but the signature is over key A.
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::SignerMismatch)
        );
    }

    #[test]
    fn high_s_twin_is_malleable() {
        // secp256k1 curve order n.
        let n = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        let payload = signed_payload("1000", "0", "9999999999", PAY_TO, signer_address(), |raw| {
            // Replace s with its high-half twin (n - s); the recovery byte is
            // left in range so the malleability gate (not the format gate) fires.
            let s = U256::from_be_slice(&raw[32..64]);
            let high = n - s;
            raw[32..64].copy_from_slice(&high.to_be_bytes::<32>());
        });
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::SignatureMalleable)
        );
    }

    #[test]
    fn out_of_range_recovery_id_is_format_error() {
        let payload = signed_payload("1000", "0", "9999999999", PAY_TO, signer_address(), |raw| {
            raw[64] = 29;
        });
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::SignatureFormat)
        );
    }

    #[test]
    fn truncated_signature_is_format_error() {
        let mut payload = valid_payload();
        payload.payload.signature.truncate(20);
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::SignatureFormat)
        );
    }

    #[test]
    fn wrong_recipient_is_recipient_mismatch() {
        let other = "0x4444444444444444444444444444444444444444";
        let payload = signed_payload("1000", "0", "9999999999", other, signer_address(), |_| {});
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::RecipientMismatch)
        );
    }

    #[test]
    fn value_below_required_is_insufficient() {
        let payload = valid_payload();
        let reqs = requirements("2000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::InsufficientValue)
        );
    }

    #[test]
    fn before_valid_after_is_not_yet_valid() {
        let payload = signed_payload(
            "1000",
            "5000",
            "9999999999",
            PAY_TO,
            signer_address(),
            |_| {},
        );
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::NotYetValid)
        );
    }

    #[test]
    fn at_or_after_valid_before_is_expired() {
        let payload = signed_payload("1000", "0", "1000", PAY_TO, signer_address(), |_| {});
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        // now == validBefore == 1000 → expired.
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn overflowing_value_is_field_overflow() {
        let mut payload = valid_payload();
        payload.payload.authorization.value = "9".repeat(78).parse().unwrap();
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::FieldOverflow { field: "value" })
        );
    }

    #[test]
    fn network_disagreement_is_network_mismatch() {
        let mut payload = valid_payload();
        payload.network = Network::BaseSepolia;
        let reqs = requirements("1000", Network::Base, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::NetworkMismatch)
        );
    }

    #[test]
    fn unsupported_chain_is_unknown_chain_id() {
        let mut payload = valid_payload();
        payload.network = Network::Polygon;
        let reqs = requirements("1000", Network::Polygon, Some(default_extra()));
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::UnknownChainId("polygon".to_owned()))
        );
    }

    #[test]
    fn absent_extra_is_missing_domain() {
        let payload = valid_payload();
        let reqs = requirements("1000", Network::Base, None);
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::MissingDomain)
        );
    }

    #[test]
    fn extra_without_name_is_domain_field() {
        let payload = valid_payload();
        let reqs = requirements(
            "1000",
            Network::Base,
            Some(serde_json::json!({ "version": VERSION })),
        );
        assert_eq!(
            verify_payment(&payload, &reqs, NOW),
            Err(VerifyError::DomainField { field: "name" })
        );
    }

    // ---- chain_id unit ----

    #[test]
    fn chain_id_lists_only_vetted_networks() {
        assert_eq!(chain_id(&Network::Base), Some(8453));
        assert_eq!(chain_id(&Network::BaseSepolia), Some(84_532));
        assert_eq!(chain_id(&Network::Polygon), None);
        assert_eq!(chain_id(&Network::Solana), None);
        assert_eq!(chain_id(&Network::Unknown("ethereum".to_owned())), None);
    }
}
