//! The settlement chain client: the settler's one window onto Base.
//!
//! Everything on-chain the worker needs is here and nothing else — read the
//! connected chain id, ask whether an authorization has already been spent, and
//! redeem one. There is deliberately no batching, no gas strategy and no nonce
//! management: this type does one claim at a time and the caller (M5b's sweep
//! loop) decides the policy.
//!
//! Like [`PgClaimLedger`](tollgate_ledger::PgClaimLedger) this is ONE concrete
//! type, not a trait (ADR-0028). There is exactly one implementation — a real
//! JSON-RPC provider — and a mock seam invented before a second implementation
//! exists would only let the tests agree with themselves.

use std::time::Duration;

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockNumberOrTag, Filter, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolEvent};

use tollgate_core::x402::{self, EvmAddress, Network, Nonce, UintStr};
use tollgate_ledger::Claim;

alloy::sol! {
    /// EIP-3009. The signed authorization is replayed verbatim; `(v, r, s)` are the
    /// payer's signature split into the three arguments the contract takes.
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    );

    /// EIP-3009's replay map: `true` once an authorization has been used or
    /// cancelled. Consulting it turns a guaranteed-revert redeem into a cheap read.
    function authorizationState(address authorizer, bytes32 nonce) returns (bool);

    /// Emitted by `transferWithAuthorization` — and ONLY by it. `cancelAuthorization`
    /// writes the very same `authorizationState` slot but emits
    /// `AuthorizationCanceled` instead, so this event is the one on-chain fact that
    /// distinguishes "the payer paid us" from "the payer took it back". Declared here
    /// rather than hand-hashing the topic so the signature and its keccak can never
    /// drift apart.
    ///
    /// It identifies the NONCE, not the claim: no recipient, no amount. Two
    /// authorizations sharing a nonce produce the same event, so a hit here is only
    /// half of a payment proof — see [`SettlementClient::redemption_status`].
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /// ERC-20's transfer event: the other half of that proof. It is the only place
    /// the chain records WHO was paid and HOW MUCH, and the token emits exactly one
    /// per `transferWithAuthorization`.
    event Transfer(address indexed from, address indexed to, uint256 value);
}

/// How long a sent transaction is waited on before the settler gives up on its
/// receipt. Bounded on purpose: without it a stuck mempool would park the sweep
/// loop forever. A timeout is NOT a failed settlement — the transaction may still
/// land — so the caller must treat it as "unknown", which is exactly what
/// [`SettlementClient::is_authorization_used`] is for on the next pass.
const RECEIPT_TIMEOUT: Duration = Duration::from_mins(2);

/// How far back from the chain tip the `AuthorizationUsed` lookup reaches.
///
/// A window rather than `earliest..=latest`, and it is a correctness fix rather than a
/// tuning knob: provider tiers that cap `eth_getLogs` by block RANGE reject an
/// unbounded query outright, and a rejected query leaves a claim that WAS redeemed
/// marked owed until it expires — money collected and never recorded, with a permanent
/// non-zero `failed` in the sweep's liveness line.
///
/// A redemption of THIS claim can only have happened inside the claim's own validity
/// window, and that window is bounded where the payment is ACCEPTED rather than assumed
/// here: [`verify_payment`](tollgate_core::x402::verify_payment) rejects an
/// authorization whose `validBefore` lies beyond `now + maxTimeoutSeconds` (plus a
/// small clock-skew grace), so no claim in the ledger can outlive the timeout its
/// challenge advertised (seconds to minutes). 10 000 blocks is ~5.5 hours at Base's
/// 2-second blocks — orders of magnitude of headroom over that — while staying at the
/// tightest block range the strict provider tiers document, so the query is both
/// sufficient and universally accepted. An operator advertising a `maxTimeoutSeconds`
/// anywhere near 5.5 hours is the one change that would break the premise, and it must
/// widen this window with it.
///
/// That bound is NOT the same as "no false negatives", and the difference is a real
/// residual. It constrains `validBefore - now`; nothing constrains `validAfter`. A payer
/// may sign `validAfter = 0`, present the payload only much later, and be redeemed
/// straight away — the redemption is then as old as the payload is, and once it falls
/// out of this window the lookup finds no log and reports [`Redemption::Cancelled`]: an
/// accusation against a payer who actually paid. It costs the operator nothing (the row
/// stays owed) and it is not reachable through the gateway's own flow, which records the
/// claim when it accepts the payment. Tracked as a follow-up; closing it properly means
/// bounding the window from the claim's own `validAfter`, or recording where the
/// settlement landed.
const LOG_LOOKBACK_BLOCKS: u64 = 10_000;

/// A failure while settling a claim on-chain.
///
/// The `Display` of every variant is FIXED and mentions no URL: an RPC endpoint
/// carries an API key and alloy's transport errors happily print the endpoint they
/// failed to reach (ADR-0034). The underlying error stays reachable through
/// [`source`](std::error::Error::source) for an operator reading a full chain,
/// exactly as [`ClaimLedgerError`](tollgate_ledger::ClaimLedgerError) does.
///
/// Note that [`SettlementClient::redeem`] has no success enum: a reverted receipt is
/// an `Err`, because a claim whose redemption reverted has NOT been settled and
/// must not be marked as such.
#[derive(Debug, thiserror::Error)]
pub enum SettleError {
    /// The JSON-RPC endpoint could not be reached, or rejected the request.
    #[error("settlement rpc error")]
    Rpc(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The endpoint answered `eth_chainId` with a chain tollgate does not settle
    /// on. Fails closed at connect time (ADR-0010): pointing the settler at the
    /// wrong network would broadcast the operator's signature to a chain where the
    /// authorizations mean something else.
    #[error("connected chain is not a supported settlement chain")]
    UnsupportedChain {
        /// What the endpoint reported.
        chain_id: u64,
    },

    /// The claim settles on a different chain than this client is connected to.
    #[error("claim network does not match the connected chain")]
    ChainMismatch {
        /// The chain this client is connected to.
        connected: u64,
    },

    /// A ledger row did not convert into the ABI types the call needs — a bad
    /// signature, or a numeric field that does not fit a `uint256`.
    #[error("claim cannot be encoded for settlement")]
    MalformedClaim {
        /// Which part of the claim was unusable.
        field: &'static str,
    },

    /// The transaction was mined and the EVM reverted it. Terminal for this
    /// attempt: the claim is still owed and the gas is still spent.
    #[error("settlement transaction {tx_hash} reverted")]
    Reverted {
        /// The mined transaction's hash, for correlating with a block explorer.
        tx_hash: String,
    },

    /// A log named a transaction the endpoint then had no receipt for — a reorg
    /// between the two reads, or a node that has pruned it. INCONCLUSIVE, never a
    /// verdict: without the receipt there is no way to see what the transaction
    /// actually transferred, so the claim stays owed and the next sweep asks again.
    #[error("no receipt for transaction {tx_hash}, which a log says exists")]
    ReceiptUnavailable {
        /// The transaction the log pointed at, for correlating with a block explorer.
        tx_hash: String,
    },

    /// A matching log carried no transaction hash or no block position, so there is
    /// no route from the event to the money that would have moved with it.
    /// INCONCLUSIVE for the same reason [`SettleError::ReceiptUnavailable`] is: it
    /// proves nothing either way, and a claim must never be reported as spent
    /// elsewhere — an accusation against the payer — on the strength of a field the
    /// endpoint did not fill in.
    #[error("an AuthorizationUsed log cannot be traced to the transfer beside it")]
    UntraceableLog,

    /// An `AuthorizationUsed` was its transaction's LAST log: nothing at all followed
    /// the event, so the `Transfer` the confirmation pairs with was never emitted after
    /// it. INCONCLUSIVE, and pointedly not a verdict on the payer — the suspect is the
    /// token. The pairing is coupled to Circle's `FiatTokenV2` marking the
    /// authorization used and THEN transferring; that address is an upgradeable proxy,
    /// and a successor restoring EIP-3009's reference order would produce this for
    /// EVERY genuine payment. Reported as an operator-facing fault so the claim stays
    /// owed rather than the payer being accused of reusing a nonce (a successor that is
    /// PRESENT but is not this claim's transfer remains
    /// [`Redemption::OtherAuthorization`]).
    #[error("no log followed an AuthorizationUsed inside its transaction: the token's event emission order is not the one settlement pairs on")]
    EmissionOrderMismatch,

    /// The endpoint answered the log query with logs, and NOT ONE of them named the
    /// asset, payer and nonce the filter pinned server-side. An honest provider cannot
    /// do that, so the suspect is the provider — buggy, compromised, or in the middle —
    /// and nothing was learned about this claim either way. INCONCLUSIVE for the same
    /// reason [`SettleError::UntraceableLog`] is, and pointedly not a verdict on the
    /// payer: an infrastructure fault must not enter the audit trail as a reused nonce.
    /// Logs that DID match and simply were not paid for stay
    /// [`Redemption::OtherAuthorization`]; an empty answer stays
    /// [`Redemption::Cancelled`].
    #[error("the endpoint returned logs that do not match the filter it was given")]
    UnfilteredLogs,
}

impl SettleError {
    /// Boxes any transport/provider error into [`SettleError::Rpc`], keeping it as
    /// the error chain's source while the `Display` stays fixed.
    fn rpc(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Rpc(Box::new(e))
    }
}

/// What a SPENT authorization was actually spent on.
///
/// `authorizationState` reports one bit for three histories with wildly different
/// consequences, and only one of them is money the operator can bank. The enum
/// exists so a caller has to name which one it is acting on: a `bool` here is what
/// let "the nonce is gone" read as "we were paid".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redemption {
    /// A `transferWithAuthorization` moved this claim's value from its payer to its
    /// payee in its own asset. The ONLY variant that may mark a ledger row settled.
    Confirmed,
    /// The nonce was spent with no `transferWithAuthorization` behind it: the payer
    /// called `cancelAuthorization`, and nothing was ever paid.
    Cancelled,
    /// The nonce was spent BY a `transferWithAuthorization` — just not by this
    /// claim's. Two authorizations can share a nonce, and only the first to reach
    /// the contract runs; the claim is unpayable and was never paid.
    OtherAuthorization,
}

/// A connected, wallet-bearing JSON-RPC client for one settlement chain.
///
/// Deliberately NOT `Debug`: the provider holds the operator's signing wallet and
/// the endpoint URL (which carries an API key), so `{client:?}` must not compile
/// (ADR-0034). The endpoint is not stored as a field either — it is consumed by
/// [`SettlementClient::connect`] and dropped, mirroring `PgClaimLedger`.
pub struct SettlementClient {
    /// Type-erased so the concrete filler stack (wallet, gas, nonce, chain id)
    /// does not leak into this struct's signature.
    provider: DynProvider,
    /// Read once at connect and cached: it cannot change under a live endpoint
    /// without that being an operator error worth failing on, and every claim is
    /// checked against it.
    chain_id: u64,
}

impl SettlementClient {
    /// Connects to `rpc_url`, signing with `signer`, and verifies the endpoint is
    /// on a chain tollgate settles on.
    ///
    /// The `eth_chainId` round-trip is eager on purpose — the same call it does two
    /// jobs: it proves the endpoint is actually reachable (a dead RPC fails at
    /// startup, not on the first claim) and it pins the chain to core's ONE
    /// allowlist, the same table `verify_payment` accepts signatures under
    /// (ADR-0010). Verifying under Base Sepolia and settling on mainnet would
    /// otherwise be a configuration typo away.
    ///
    /// # Errors
    /// - [`SettleError::Rpc`] if the URL cannot be parsed or the endpoint cannot be
    ///   reached.
    /// - [`SettleError::UnsupportedChain`] if the endpoint is on any other chain.
    pub async fn connect(rpc_url: &str, signer: PrivateKeySigner) -> Result<Self, SettleError> {
        // `.wallet(..)` installs the signing filler, so `send_transaction` below
        // gets a locally-signed `eth_sendRawTransaction` — the key never leaves
        // this process and is never handed to the RPC provider.
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(signer))
            .connect(rpc_url)
            .await
            .map_err(SettleError::rpc)?
            .erased();

        let chain_id = provider.get_chain_id().await.map_err(SettleError::rpc)?;
        if !is_settlement_chain(chain_id) {
            return Err(SettleError::UnsupportedChain { chain_id });
        }

        Ok(Self { provider, chain_id })
    }

    /// The chain this client is connected to.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Asks the token contract whether this authorization has already been used or
    /// cancelled — an `eth_call`, so it costs no gas and writes nothing.
    ///
    /// `true` means redeeming would revert. It is the settler's cheap answer to the
    /// question a lost receipt leaves open ("did my transaction land?"), and its
    /// guard against paying gas for a claim someone else already settled.
    ///
    /// It is NOT a proof of payment: `cancelAuthorization` sets the identical bit.
    /// A caller that wants to know whether money actually moved must follow a `true`
    /// with [`SettlementClient::redemption_status`].
    ///
    /// # Errors
    /// - [`SettleError::ChainMismatch`] if the claim does not belong to this chain.
    /// - [`SettleError::MalformedClaim`] if the payer or nonce will not convert.
    /// - [`SettleError::Rpc`] if the call fails or returns undecodable output.
    pub async fn is_authorization_used(&self, claim: &Claim) -> Result<bool, SettleError> {
        self.require_same_chain(claim)?;

        let call = authorizationStateCall {
            authorizer: address(&claim.payer, "payer")?,
            nonce: word(&claim.nonce, "nonce")?,
        };
        let output = self
            .provider
            .call(call_to_asset(claim, call.abi_encode())?)
            .await
            .map_err(SettleError::rpc)?;

        authorizationStateCall::abi_decode_returns(&output).map_err(SettleError::rpc)
    }

    /// Works out what a spent authorization was spent ON: this claim's payment, a
    /// cancellation, or somebody else's transfer.
    ///
    /// This exists because [`SettlementClient::is_authorization_used`] cannot tell
    /// payment from cancellation: EIP-3009's `cancelAuthorization` writes the same
    /// `_authorizationStates[authorizer][nonce] = true` slot that
    /// `authorizationState` reads. A payer who is served and then cancels their own
    /// authorization for ~50k gas would otherwise have the settler record revenue it
    /// never received. Only `transferWithAuthorization` emits `AuthorizationUsed`, so
    /// the absence of that log is a cancellation.
    ///
    /// Its PRESENCE, however, is not yet a payment. The event carries `(authorizer,
    /// nonce)` and nothing else, and a nonce is not a claim: a payer can sign two
    /// authorizations under one nonce — a large one presented to the gateway, a
    /// 1-wei one paid to themselves — be served, and then broadcast the cheap one.
    /// The resulting event is entirely genuine and matches this filter exactly. So a
    /// hit is only a pointer: the transaction it names is fetched and the ERC-20
    /// `Transfer` emitted immediately BEFORE the event is what decides, because that
    /// is where the recipient and the amount actually live — see
    /// [`SettlementClient::paired_transfer_paid_claim`].
    ///
    /// # Errors
    /// - [`SettleError::ChainMismatch`] if the claim does not belong to this chain.
    /// - [`SettleError::MalformedClaim`] if a claim field will not convert.
    /// - [`SettleError::Rpc`] if the block number, log or receipt query fails.
    /// - [`SettleError::ReceiptUnavailable`] if a log's transaction has no receipt.
    /// - [`SettleError::UntraceableLog`] if a log named no transaction or position.
    /// - [`SettleError::EmissionOrderMismatch`] if a log had no successor at all.
    /// - [`SettleError::UnfilteredLogs`] if no returned log matched the filter.
    pub async fn redemption_status(&self, claim: &Claim) -> Result<Redemption, SettleError> {
        self.require_same_chain(claim)?;

        // One extra round-trip, to anchor the window — see [`LOG_LOOKBACK_BLOCKS`].
        let latest = self
            .provider
            .get_block_number()
            .await
            .map_err(SettleError::rpc)?;
        let asset = address(&claim.asset, "asset")?;
        // Topic 1 is the indexed `authorizer` and topic 2 the indexed `nonce`, in
        // declaration order — the same two values that key the replay map.
        let payer_topic = address(&claim.payer, "payer")?.into_word();
        let nonce_topic = word(&claim.nonce, "nonce")?;

        let filter = Filter::new()
            .address(asset)
            .from_block(latest.saturating_sub(LOG_LOOKBACK_BLOCKS))
            .to_block(BlockNumberOrTag::Latest)
            .event_signature(AuthorizationUsed::SIGNATURE_HASH)
            .topic1(payer_topic)
            .topic2(nonce_topic);

        let logs = self
            .provider
            .get_logs(&filter)
            .await
            .map_err(SettleError::rpc)?;
        if logs.is_empty() {
            return Ok(Redemption::Cancelled);
        }

        let mut untraceable = false;
        let mut any_matched = false;
        for log in &logs {
            // The filter pinned the asset, the payer and the nonce SERVER-SIDE, so an
            // honest endpoint cannot answer with anything else — which is exactly why
            // the answer is re-read here rather than taken on trust. This endpoint is
            // the only oracle there is for whether a claim was paid, and no settlement
            // transaction is kept in the ledger to reconcile against afterwards, so a
            // provider that is buggy, compromised or in the middle could answer the
            // query for THIS nonce with the log of a genuine payment for another one,
            // pass every check below, and book a second claim off a single payment with
            // nothing left to detect it. Verifying the answer against the question costs
            // three comparisons. A log that fails them is not this claim's log and is
            // therefore evidence of nothing — skipped, and remembered as skipped, because
            // an answer made up ENTIRELY of such logs is a fault in the endpoint rather
            // than a fact about the payer (see [`SettleError::UnfilteredLogs`]).
            //
            // `get` rather than indexing: a malformed log with too few topics must read
            // as non-matching, not panic on the money path.
            let topics = log.inner.topics();
            if log.inner.address != asset
                || topics.get(1) != Some(&payer_topic)
                || topics.get(2) != Some(&nonce_topic)
            {
                continue;
            }
            any_matched = true;

            // A log with neither of these is a PENDING one, which a filter ending at
            // `latest` cannot return. If one somehow arrives anyway it is not evidence
            // of anything: with no transaction there is no receipt to read, and with no
            // block position the transfer beside it cannot be identified. Remembered
            // rather than ignored, because falling through would report the claim as
            // spent on someone else's transfer — a verdict this log cannot support.
            let (Some(tx_hash), Some(log_index)) = (log.transaction_hash, log.log_index) else {
                untraceable = true;
                continue;
            };
            if self
                .paired_transfer_paid_claim(claim, tx_hash, log_index)
                .await?
            {
                return Ok(Redemption::Confirmed);
            }
        }

        if untraceable {
            return Err(SettleError::UntraceableLog);
        }
        // Three different facts reach this point and only the last is the payer's doing:
        // an empty answer (returned as `Cancelled` above), an answer none of whose logs
        // was this claim's, and an answer whose log WAS this claim's but was not paired
        // with its payment. Only the third supports `OtherAuthorization`.
        if !any_matched {
            return Err(SettleError::UnfilteredLogs);
        }
        Ok(Redemption::OtherAuthorization)
    }

    /// Whether the `AuthorizationUsed` at block position `log_index`, inside
    /// transaction `tx_hash`, is the one THIS claim was paid by: the log immediately
    /// AFTER it must be an ERC-20 `Transfer` of the claim's `value`, from its payer to
    /// its payee, emitted by the claim's own asset.
    ///
    /// All four fields are checked together because each alone is forgeable by the
    /// party who benefits — a payer controls the recipient and the amount of the
    /// authorization they broadcast themselves, and any contract can emit a
    /// `Transfer` that merely looks right.
    ///
    /// And the transfer must be paired with THIS event, not merely present in the
    /// same transaction. One transaction can spend many nonces — Multicall3 is
    /// canonical on Base and `transferWithAuthorization` is signature-authenticated,
    /// so `msg.sender` is irrelevant and anyone may bundle — and a transaction-wide
    /// search would let ONE genuine transfer confirm every nonce beside it. A payer
    /// served k times on one route (same payee, same asset, same value: `value >=
    /// maxAmountRequired` is all verification demands) could then pay once and have k
    /// claims marked settled.
    ///
    /// The successor is the pair because Circle's `FiatTokenV2` marks the
    /// authorization used and THEN transfers — the OPPOSITE order to EIP-3009's
    /// reference implementation, which transfers first. That is a coupling to the
    /// deployed USDC contract and it is deliberate: `tests/settle_tenderly.rs` asserts
    /// the emission order against real Base Sepolia USDC rather than trusting the EIP
    /// text, and a different EIP-3009 token could well need the other direction. It is
    /// documented, not auto-detected — a settler that sniffed the order per token
    /// would have to decide what to do when neither neighbour fits, on the money path.
    ///
    /// Exactly ONE neighbour is accepted, never either. Under a Multicall3 bundle the
    /// attacker chooses the call order, so a genuine redemption's `Transfer` sits
    /// immediately BEFORE the next call's `AuthorizationUsed`:
    ///
    /// ```text
    /// @0 AuthorizationUsed(nonce A)   @1 Transfer(payer -> payee, V)   <- the payment
    /// @2 AuthorizationUsed(nonce B)   @3 Transfer(payer -> payer, 1)   <- the bundle
    /// ```
    ///
    /// Accepting `±1` as a portability hedge would let claim B's event at `@2` match
    /// the genuine transfer at `@1` and settle a claim nobody paid — the very exploit
    /// this pairing exists to close. The asymmetry IS the check.
    ///
    /// # Errors
    /// - [`SettleError::MalformedClaim`] if a claim field will not convert.
    /// - [`SettleError::Rpc`] if the receipt query fails.
    /// - [`SettleError::ReceiptUnavailable`] if the transaction has no receipt.
    /// - [`SettleError::EmissionOrderMismatch`] if the event has no successor log.
    async fn paired_transfer_paid_claim(
        &self,
        claim: &Claim,
        tx_hash: FixedBytes<32>,
        log_index: u64,
    ) -> Result<bool, SettleError> {
        // Saturating rather than `+ 1`: the money path takes no panics, and a log at
        // `u64::MAX` simply matches nothing below.
        let transfer_index = log_index.saturating_add(1);

        let receipt = self
            .provider
            .get_transaction_receipt(tx_hash)
            .await
            .map_err(SettleError::rpc)?
            .ok_or_else(|| SettleError::ReceiptUnavailable {
                tx_hash: tx_hash.to_string(),
            })?;

        // A reverted transaction moves no money and settles nothing. Unreachable today
        // — a revert discards the logs, so `eth_getLogs` cannot point at one in the
        // first place — but that is an invariant guaranteed somewhere else, and this is
        // the money path: stating it here costs one comparison.
        if !receipt.status() {
            return Ok(false);
        }

        let asset = address(&claim.asset, "asset")?;
        let from = address(&claim.payer, "payer")?;
        let to = address(&claim.payee, "payee")?;
        let value = uint(&claim.value, "value")?;

        // `log_index` counts logs across the whole BLOCK while a receipt carries only
        // its own transaction's, so the successor is SEARCHED FOR by index — never
        // reached by subscripting `receipt.logs()`, which is offset by every log the
        // block's earlier transactions emitted.
        //
        // Nothing at that index means nothing inside this transaction followed the
        // event, which is not a fact about this claim at all: the token did not emit
        // its `Transfer` after its `AuthorizationUsed`, and the emission-order coupling
        // the whole confirmation rests on has broken. Inconclusive, and aimed at the
        // operator — see [`SettleError::EmissionOrderMismatch`].
        let Some(transfer) = receipt
            .logs()
            .iter()
            .find(|log| log.log_index == Some(transfer_index))
        else {
            return Err(SettleError::EmissionOrderMismatch);
        };

        // `decode_log` rejects anything whose topic0 is not `Transfer`, so the log
        // that happens to sit there cannot accidentally match by being some other
        // event of the right shape.
        Ok(transfer.inner.address == asset
            && Transfer::decode_log(&transfer.inner)
                .is_ok_and(|t| t.from == from && t.to == to && t.value == value))
    }

    /// Redeems the claim on-chain: sends `transferWithAuthorization` AND waits for
    /// its receipt, up to [`RECEIPT_TIMEOUT`].
    ///
    /// Returns the transaction hash of a receipt whose status is success. A mined
    /// but REVERTED transaction is [`SettleError::Reverted`], never an `Ok` —
    /// nothing about this call may tempt a caller into marking an unpaid claim
    /// settled.
    ///
    /// # Errors
    /// - [`SettleError::ChainMismatch`] if the claim does not belong to this chain.
    /// - [`SettleError::MalformedClaim`] if any field will not convert.
    /// - [`SettleError::Rpc`] if broadcast fails, or no receipt arrives in time.
    /// - [`SettleError::Reverted`] if the transaction was mined and reverted.
    pub async fn redeem(&self, claim: &Claim) -> Result<String, SettleError> {
        self.require_same_chain(claim)?;

        let tx = call_to_asset(claim, redeem_calldata(claim)?)?;
        let pending = self
            .provider
            .send_transaction(tx)
            .await
            .map_err(SettleError::rpc)?;

        // The timeout bounds only how long we WAIT. The transaction is already
        // broadcast, so timing out says "unknown", not "failed" — which is why the
        // caller must not mark the claim settled on this error and why
        // `is_authorization_used` exists to resolve it later.
        let receipt = pending
            .with_timeout(Some(RECEIPT_TIMEOUT))
            .get_receipt()
            .await
            .map_err(SettleError::rpc)?;

        let tx_hash = receipt.transaction_hash.to_string();
        if receipt.status() {
            Ok(tx_hash)
        } else {
            Err(SettleError::Reverted { tx_hash })
        }
    }

    /// Rejects a claim minted for another chain before a single byte is broadcast.
    fn require_same_chain(&self, claim: &Claim) -> Result<(), SettleError> {
        if x402::chain_id(&claim.network) == Some(self.chain_id) {
            Ok(())
        } else {
            Err(SettleError::ChainMismatch {
                connected: self.chain_id,
            })
        }
    }
}

/// Wraps `calldata` in a transaction aimed at the claim's own token contract.
///
/// The `to` comes from the CLAIM, not from configuration: the asset is part of
/// what the payer signed (it is the EIP-712 `verifyingContract`), so any other
/// target would be a contract the signature was never meant for.
fn call_to_asset(claim: &Claim, calldata: Vec<u8>) -> Result<TransactionRequest, SettleError> {
    Ok(TransactionRequest::default()
        .to(address(&claim.asset, "asset")?)
        .input(calldata.into()))
}

/// Whether `chain_id` is one tollgate settles on.
///
/// Derived from core's allowlist rather than restated here, so the set of chains
/// signatures are VERIFIED under and the set they are SETTLED on cannot drift
/// apart (ADR-0010).
fn is_settlement_chain(chain_id: u64) -> bool {
    [Network::Base, Network::BaseSepolia]
        .iter()
        .any(|net| x402::chain_id(net) == Some(chain_id))
}

/// ABI-encodes the `transferWithAuthorization` call for `claim`.
///
/// Free-standing and chain-free so it can be pinned by an offline test: the exact
/// bytes here are what actually moves the money, and a silent re-encoding would
/// otherwise only be caught on a live chain.
fn redeem_calldata(claim: &Claim) -> Result<Vec<u8>, SettleError> {
    // Splitting the signature is delegated to core, which is the workspace's only
    // signature parser — and therefore the only place the EIP-2 high-`s`
    // malleability rejection lives (ADR-0013). Re-deriving `(r, s, v)` here would
    // quietly route settlement around that check.
    let (r, s, v) = x402::split_signature(&claim.signature)
        .map_err(|_| SettleError::MalformedClaim { field: "signature" })?;

    let call = transferWithAuthorizationCall {
        from: address(&claim.payer, "payer")?,
        to: address(&claim.payee, "payee")?,
        value: uint(&claim.value, "value")?,
        validAfter: uint(&claim.valid_after, "valid_after")?,
        validBefore: uint(&claim.valid_before, "valid_before")?,
        nonce: word(&claim.nonce, "nonce")?,
        v,
        r: FixedBytes(r),
        s: FixedBytes(s),
    };
    Ok(call.abi_encode())
}

/// Converts a validated [`EvmAddress`] into an alloy [`Address`].
///
/// `EvmAddress` is `0x` + 40 hex by construction, so this cannot fail in practice
/// — but it is a fallible conversion rather than an `expect`, because the value
/// came out of the database and the money path takes no panics.
fn address(a: &EvmAddress, field: &'static str) -> Result<Address, SettleError> {
    a.as_str()
        .parse::<Address>()
        .map_err(|_| SettleError::MalformedClaim { field })
}

/// Decodes a validated [`Nonce`] into its raw 32-byte word. The nonce is used
/// verbatim — EIP-3009 does not hash it.
fn word(n: &Nonce, field: &'static str) -> Result<FixedBytes<32>, SettleError> {
    n.as_str()
        .parse::<FixedBytes<32>>()
        .map_err(|_| SettleError::MalformedClaim { field })
}

/// Parses a decimal [`UintStr`] into a `uint256`.
fn uint(s: &UintStr, field: &'static str) -> Result<U256, SettleError> {
    U256::from_str_radix(s.as_str(), 10).map_err(|_| SettleError::MalformedClaim { field })
}

#[cfg(test)]
mod tests {
    use super::{
        is_settlement_chain, redeem_calldata, transferWithAuthorizationCall, AuthorizationUsed,
    };

    use alloy::primitives::keccak256;
    use alloy::sol_types::{SolCall, SolEvent};

    use tollgate_core::x402::Network;
    use tollgate_ledger::Claim;

    /// Fixed claim behind the pinned calldata vector below. Every field is a
    /// distinct repeated byte so a swapped argument shows up as a shifted run of
    /// nibbles rather than a subtle diff.
    fn fixture() -> Claim {
        Claim {
            payer: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .parse()
                .expect("fixture payer"),
            nonce: "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                .parse()
                .expect("fixture nonce"),
            payee: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .parse()
                .expect("fixture payee"),
            value: "10000".parse().expect("fixture value"),
            valid_after: "0".parse().expect("fixture valid_after"),
            valid_before: "9999999999".parse().expect("fixture valid_before"),
            // r = 0x11..11, s = 0x22..22 (low half-order, so not malleable), v = 27.
            signature: format!("0x{}{}1b", "11".repeat(32), "22".repeat(32)),
            asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
                .parse()
                .expect("fixture asset"),
            network: Network::BaseSepolia,
        }
    }

    #[test]
    fn transfer_with_authorization_selector_matches_its_canonical_signature() {
        // The selector is the first thing the token contract dispatches on: get it
        // wrong and every settlement reverts. `sol!` derives it from the argument
        // list we wrote, so this asserts that list against the EIP-3009 signature
        // independently, rather than trusting the macro to agree with itself.
        const CANONICAL: &str = "transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)";
        assert_eq!(
            transferWithAuthorizationCall::SELECTOR,
            keccak256(CANONICAL.as_bytes())[..4],
            "selector must be keccak256 of the canonical EIP-3009 signature"
        );
    }

    #[test]
    fn authorization_used_topic_matches_its_canonical_signature() {
        // This topic is how the settler tells "the payer paid us" from "the payer
        // cancelled". A typo in the event declaration would match NOTHING, so every
        // already-redeemed claim would be reported as CANCELLED and quietly left
        // uncollected — a wrong answer with no error line anywhere. The hermetic fake
        // deliberately does not parse the filter it is handed, so nothing else in the
        // suite would notice; this assertion is the hash's only oracle.
        //
        // `Transfer` needs no twin of this test: the fake pins ERC-20's real topic as
        // a literal, so a wrong declaration there makes the confirmation branch fail
        // outright.
        const CANONICAL: &str = "AuthorizationUsed(address,bytes32)";
        assert_eq!(
            AuthorizationUsed::SIGNATURE_HASH,
            keccak256(CANONICAL.as_bytes()),
            "the event topic must be keccak256 of the canonical EIP-3009 signature"
        );
    }

    #[test]
    fn redeem_calldata_matches_the_pinned_vector() {
        // A PINNED vector, not a re-computation: these bytes are what actually moves
        // the payer's money, so any change to the argument order, the encoding, or
        // the signature split must fail loudly here instead of on-chain.
        const PINNED: &str = "e3ee160e\
            000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
            000000000000000000000000bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\
            0000000000000000000000000000000000000000000000000000000000002710\
            0000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000000000000000000000000002540be3ff\
            cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\
            000000000000000000000000000000000000000000000000000000000000001b\
            1111111111111111111111111111111111111111111111111111111111111111\
            2222222222222222222222222222222222222222222222222222222222222222";

        let calldata = redeem_calldata(&fixture()).expect("fixture claim must encode");
        assert_eq!(
            alloy::hex::encode(&calldata),
            PINNED.replace([' ', '\n'], ""),
            "settlement calldata drifted from the pinned vector"
        );
    }

    #[test]
    fn settlement_chains_are_exactly_cores_allowlist() {
        // Base + Base Sepolia settle; everything else — mainnet, an L2 we never
        // verified under, a typo'd chain id — must fail closed at connect.
        assert!(is_settlement_chain(8453), "base must settle");
        assert!(is_settlement_chain(84_532), "base sepolia must settle");
        assert!(!is_settlement_chain(1), "ethereum mainnet must not settle");
        assert!(
            !is_settlement_chain(0),
            "an absent chain id must not settle"
        );
    }
}
