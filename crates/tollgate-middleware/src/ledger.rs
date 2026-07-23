//! The Postgres claims ledger: the durable record of every ACCEPTED payment.
//!
//! The nonce store (`store.rs`) answers "has this authorization been spent?" and
//! then forgets — its Redis keys expire. This ledger answers the other half:
//! "what do we still have to collect?". A claim recorded here is money owed to the
//! operator until a settlement worker redeems it on-chain (M5b), so the rows carry
//! the complete, verbatim EIP-3009 authorization plus its signature.
//!
//! Deliberately NOT a trait. There is exactly one backend (Postgres), and the
//! inherent `async fn`s below let auto-trait leakage make the returned futures
//! `Send` without a spelled-out bound — which is all the tower gate needs to hold
//! one across an `.await`. This is the opposite call from `NonceStore` (RPITIT +
//! explicit `+ Send`, ADR-0022) and it is intentional: that trait exists because
//! two backends do, and this one has one.

use sqlx::Row as _;

use tollgate_core::x402::{
    EvmAddress, FieldFormatError, Network, Nonce, PaymentPayload, PaymentRequirements, UintStr,
};

/// One accepted payment claim: everything a settlement worker needs to redeem the
/// authorization on-chain, and nothing it does not.
///
/// Deliberately NOT `Debug`. The struct holds a payment `signature` — a bearer
/// credential for the payer's funds — so `?claim` / `{claim:?}` must be a COMPILE
/// ERROR rather than a judgement call at every log site (ADR-0020 forbids secrets
/// in logs; this makes the rule mechanical).
pub struct Claim {
    /// The payer, ASCII-lowercased. Half of the ledger's primary key.
    pub payer: EvmAddress,
    /// The authorization nonce, ASCII-lowercased. The other half of the key.
    pub nonce: Nonce,
    /// The recipient the payer actually signed for.
    pub payee: EvmAddress,
    /// The authorized amount in the asset's base units.
    pub value: UintStr,
    /// Unix seconds before which the authorization is not yet valid.
    pub valid_after: UintStr,
    /// Unix seconds after which the authorization has expired — the settlement
    /// deadline, and therefore the ledger's natural work ordering.
    pub valid_before: UintStr,
    /// The payer's signature over the authorization. A bearer credential.
    pub signature: String,
    /// The token contract the payment is denominated in.
    pub asset: EvmAddress,
    /// The network the authorization settles on.
    pub network: Network,
}

impl Claim {
    /// Builds a claim from a payment that has just been verified and accepted.
    ///
    /// This is the SINGLE canonicalisation site: `payer` and `nonce` are
    /// ASCII-lowercased here and nowhere else, because together they are the
    /// ledger's primary key and must agree exactly with the gate's replay key
    /// (`gate.rs`, ADR-0017) — otherwise the same authorization could be recorded
    /// twice under two casings and settled twice.
    ///
    /// `payee` comes from the SIGNED authorization's `to`, not from
    /// `requirements.pay_to`: the settlement worker must replay what the payer
    /// actually signed, and only the signed value will satisfy the contract. (The
    /// two agree in practice — `verify_payment` rejects a recipient mismatch — but
    /// the signed field is the one with authority.)
    ///
    /// # Panics
    /// Cannot panic in practice: ASCII-lowercasing a `0x`-prefixed hex string
    /// leaves both its length and its hex-ness intact, so the validating
    /// constructors that re-wrap the lowercased values cannot reject them.
    #[must_use]
    pub fn from_payment(payload: &PaymentPayload, requirements: &PaymentRequirements) -> Self {
        let auth = &payload.payload.authorization;
        Self {
            payer: EvmAddress::try_from(auth.from.as_str().to_ascii_lowercase())
                .expect("lowercasing a validated address preserves its format"),
            nonce: Nonce::try_from(auth.nonce.as_str().to_ascii_lowercase())
                .expect("lowercasing a validated nonce preserves its format"),
            payee: auth.to.clone(),
            value: auth.value.clone(),
            valid_after: auth.valid_after.clone(),
            valid_before: auth.valid_before.clone(),
            signature: payload.payload.signature.clone(),
            asset: requirements.asset.clone(),
            network: requirements.network.clone(),
        }
    }
}

/// A failure while reading or writing the claims ledger. One variant today
/// (Postgres I/O plus decode faults funnelled into it); it is an enum so a second
/// failure mode can arrive without churning every caller's `match`.
///
/// The `Display` is FIXED and says nothing about the backend: a claim-ledger error
/// can reach a log line or, indirectly, a client-visible response, and the sqlx
/// `Display` carries table names, SQL fragments and sometimes the connection
/// string. The detail is not lost — it stays reachable through
/// [`source`](std::error::Error::source) for an operator reading a full error chain.
#[derive(Debug, thiserror::Error)]
pub enum ClaimLedgerError {
    #[error("claim ledger backend error")]
    Backend(#[from] sqlx::Error),
}

/// A row that will not convert back into the validated core newtypes is a DECODE
/// fault, not a logic bug: the database is an external system, so whatever it hands
/// back is untrusted input and gets validated like any other wire value. Wrapping
/// it as `sqlx::Error::Decode` keeps it in the one error variant while preserving
/// the original [`FieldFormatError`] as the error chain's source.
impl From<FieldFormatError> for ClaimLedgerError {
    fn from(e: FieldFormatError) -> Self {
        Self::Backend(sqlx::Error::Decode(Box::new(e)))
    }
}

/// The Postgres-backed claims ledger.
///
/// Holds a `PgPool` (cheap to clone — every clone shares the same pool), and
/// nothing else: notably NOT the connection URL, which may carry a password and
/// must never be reachable from a log site. Not `Debug` for the same reason.
#[derive(Clone)]
pub struct PgClaimLedger {
    pool: sqlx::PgPool,
}

impl PgClaimLedger {
    /// Opens the pool, eagerly establishing one connection so that a bad URL or a
    /// down database fails at wiring time rather than on the first paid request.
    ///
    /// # Errors
    /// Returns [`ClaimLedgerError::Backend`] if the URL is malformed or the initial
    /// connection cannot be established.
    pub async fn connect(url: &str) -> Result<Self, ClaimLedgerError> {
        // The acquire timeout is deliberately far below sqlx's 30s default. The gate
        // awaits `record` INSIDE a request's accept path, so with the default a dead
        // Postgres would hold each paid request for 30s before failing closed, piling
        // up in-flight requests under load. Two seconds only changes how fast we
        // reach the 503 — never whether we do.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(url)
            .await?;
        Ok(Self { pool })
    }

    /// Applies any migrations the target database has not run yet.
    ///
    /// The SQL is embedded at COMPILE time by `sqlx::migrate!()`, so building this
    /// crate never needs a live database. Re-running is safe: sqlx records applied
    /// versions in `_sqlx_migrations` and skips them.
    ///
    /// # Errors
    /// Returns [`ClaimLedgerError::Backend`] if a migration cannot be applied or
    /// the recorded checksum of an already-applied migration no longer matches.
    pub async fn migrate(&self) -> Result<(), ClaimLedgerError> {
        // A migration failure is its own `MigrateError`; `sqlx::Error` already has a
        // variant for it, so one explicit hop lands it in `Backend` like every other
        // ledger fault (`?` will not chain two `From`s on its own).
        sqlx::migrate!()
            .run(&self.pool)
            .await
            .map_err(sqlx::Error::from)?;
        Ok(())
    }

    /// Records an accepted claim. `Ok(true)` = inserted, `Ok(false)` = a row with
    /// this `(payer, nonce)` was already present and nothing changed.
    ///
    /// The duplicate case is `ON CONFLICT DO NOTHING` rather than an error because
    /// the primary key IS the replay identity: at this layer the write is simply a
    /// no-op and the claim stays owed exactly once. Overwriting it would let a
    /// re-presented authorization clobber a row that may already be settled.
    ///
    /// The CALLER, however, must read `Ok(false)` as a REPLAY signal, not as
    /// "harmless, carry on": this row outlives whatever the nonce store remembers
    /// (its keys expire, an in-memory store dies with the process), so a conflict
    /// here means the authorization was already spent even when the nonce store
    /// swears it is fresh. The gate rejects on it (`gate.rs`).
    ///
    /// # Errors
    /// Returns [`ClaimLedgerError::Backend`] if the statement cannot be executed.
    pub async fn record(&self, claim: &Claim) -> Result<bool, ClaimLedgerError> {
        // `Network`'s wire form is only reachable by value, so materialise it once.
        let network = String::from(claim.network.clone());
        // `$7::NUMERIC` is load-bearing: the uint256 travels as TEXT and Postgres
        // casts it on the way in, so no Rust numeric type (and no bigdecimal /
        // rust_decimal dependency) ever has to represent a 78-digit value.
        let result = sqlx::query(
            "INSERT INTO claims \
             (payer, nonce, payee, signature, value, valid_after, valid_before, asset, network) \
             VALUES ($1,$2,$3,$4,$5,$6,$7::NUMERIC,$8,$9) \
             ON CONFLICT (payer, nonce) DO NOTHING",
        )
        .bind(claim.payer.as_str())
        .bind(claim.nonce.as_str())
        .bind(claim.payee.as_str())
        .bind(claim.signature.as_str())
        .bind(claim.value.as_str())
        .bind(claim.valid_after.as_str())
        .bind(claim.valid_before.as_str())
        .bind(claim.asset.as_str())
        .bind(network.as_str())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    /// Reads unsettled (owed) claims, soonest-expiring first. `limit` bounds the
    /// read so a caller can never pull an unbounded result set into memory.
    ///
    /// # Errors
    /// Returns [`ClaimLedgerError::Backend`] if the query fails or a row does not
    /// convert back into the validated core newtypes.
    pub async fn unsettled(&self, limit: u32) -> Result<Vec<Claim>, ClaimLedgerError> {
        // `valid_before::TEXT` is the read-back half of the TEXT/NUMERIC trick in
        // `record`. The ORDER BY must be QUALIFIED (`claims.valid_before`): a bare
        // name matching an output column resolves to that output column, which here
        // is the TEXT projection — and text ordering puts "10" before "9", settling
        // claims in the wrong order. The qualified name binds to the NUMERIC column.
        // `payer, nonce` break ties so the order is total and the read deterministic.
        let rows = sqlx::query(
            "SELECT payer, nonce, payee, signature, value, valid_after, \
             valid_before::TEXT AS valid_before, asset, network \
             FROM claims WHERE settled_at IS NULL \
             ORDER BY claims.valid_before ASC, payer, nonce LIMIT $1",
        )
        // Postgres has no unsigned integers; every u32 widens into an i64 losslessly.
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(claim_from_row).collect()
    }
}

/// Rebuilds a [`Claim`] from a ledger row, re-validating every field through the
/// core newtypes' normal constructors — the database is an external system, so
/// nothing here is unchecked. `network` needs no constructor: its `From<String>`
/// is total, preserving an unrecognised wire string as `Network::Unknown`.
fn claim_from_row(row: &sqlx::postgres::PgRow) -> Result<Claim, ClaimLedgerError> {
    Ok(Claim {
        payer: EvmAddress::try_from(row.try_get::<String, _>("payer")?)?,
        nonce: Nonce::try_from(row.try_get::<String, _>("nonce")?)?,
        payee: EvmAddress::try_from(row.try_get::<String, _>("payee")?)?,
        value: UintStr::try_from(row.try_get::<String, _>("value")?)?,
        valid_after: UintStr::try_from(row.try_get::<String, _>("valid_after")?)?,
        valid_before: UintStr::try_from(row.try_get::<String, _>("valid_before")?)?,
        signature: row.try_get("signature")?,
        asset: EvmAddress::try_from(row.try_get::<String, _>("asset")?)?,
        network: Network::from(row.try_get::<String, _>("network")?),
    })
}

#[cfg(test)]
mod tests {
    use super::Claim;

    use tollgate_core::x402::{Network, PaymentPayload, PaymentRequirements};

    // Mixed-case fixtures: the point of these tests is which casing survives and
    // which field each value is taken from.
    const PAYER_MIXED: &str = "0xAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaa";
    const NONCE_MIXED: &str = "0xABCDEF0000000000000000000000000000000000000000000000000000000000";
    const SIGNED_TO: &str = "0x1111111111111111111111111111111111111111";
    const REQUIREMENTS_PAY_TO: &str = "0x2222222222222222222222222222222222222222";
    const ASSET: &str = "0x3333333333333333333333333333333333333333";

    fn payload() -> PaymentPayload {
        serde_json::from_value(serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base-sepolia",
            "payload": {
                "signature": "0xdeadbeef",
                "authorization": {
                    "from": PAYER_MIXED,
                    "to": SIGNED_TO,
                    "value": "10000",
                    "validAfter": "0",
                    "validBefore": "9999999999",
                    "nonce": NONCE_MIXED,
                },
            },
        }))
        .expect("fixture payload is a valid PaymentPayload")
    }

    fn requirements() -> PaymentRequirements {
        tollgate_core::x402::PaymentRequirementsBuilder::exact(
            Network::BaseSepolia,
            REQUIREMENTS_PAY_TO.parse().expect("valid pay_to fixture"),
            ASSET.parse().expect("valid asset fixture"),
            "10000".parse().expect("valid amount fixture"),
            "https://example.com/resource",
            60,
        )
        .build()
    }

    #[test]
    fn from_payment_lowercases_payer_and_nonce() {
        // The ledger's primary key must match the gate's replay key exactly, and
        // that key is lowercased — so a mixed-case authorization has to land in the
        // ledger canonicalised, or the same claim could be recorded twice.
        let claim = Claim::from_payment(&payload(), &requirements());
        assert_eq!(claim.payer.as_str(), PAYER_MIXED.to_ascii_lowercase());
        assert_eq!(claim.nonce.as_str(), NONCE_MIXED.to_ascii_lowercase());
    }

    #[test]
    fn from_payment_takes_payee_from_the_signed_authorization() {
        // `to` is what the payer SIGNED; `requirements.pay_to` is merely what we
        // asked for. Only the signed value can be replayed on-chain, so the two
        // fixtures differ here to prove which one the ledger keeps.
        let claim = Claim::from_payment(&payload(), &requirements());
        assert_eq!(claim.payee.as_str(), SIGNED_TO);
        assert_ne!(claim.payee.as_str(), REQUIREMENTS_PAY_TO);
    }

    #[test]
    fn from_payment_copies_the_remaining_authorization_fields_verbatim() {
        // The settlement worker replays these bytes on-chain; any lossy copy here
        // produces a claim that cannot be redeemed.
        let claim = Claim::from_payment(&payload(), &requirements());
        assert_eq!(claim.value.as_str(), "10000");
        assert_eq!(claim.valid_after.as_str(), "0");
        assert_eq!(claim.valid_before.as_str(), "9999999999");
        assert_eq!(claim.signature, "0xdeadbeef");
        assert_eq!(claim.asset.as_str(), ASSET);
        assert_eq!(claim.network, Network::BaseSepolia);
    }
}
