//! A local JSON-RPC endpoint that answers exactly what one settlement sweep asks.
//!
//! The settler reaches its chain through ONE seam — the `TOLLGATE_RPC_URL` string
//! handed to [`SettlementClient::connect`] — so pointing that seam at an axum server
//! on `127.0.0.1` exercises the real provider, the real fillers, the real signing
//! wallet and the real ABI encoding, with nothing mocked below the socket. That is
//! why there is no chain-client trait and no mock transport in the crate itself
//! (ADR-0028): a seam invented for the tests would let them agree with themselves.
//!
//! Two properties make it a useful oracle rather than just a stub:
//!
//! * It RECORDS every method it is asked for, so a test can assert that a call was
//!   never made — which is the only way to prove a claim was skipped rather than
//!   attempted-and-rejected.
//! * It answers ONLY the methods a sweep legitimately needs. Anything else comes
//!   back as JSON-RPC "method not found", so a future change that starts calling
//!   something new fails loudly here instead of silently passing.
//!
//! The 250ms poll interval that makes the receipt wait quick is not configured
//! anywhere: alloy's client guesses `is_local` from the URL's host and uses 250ms
//! instead of its 7s remote default (`alloy-rpc-client/src/client.rs:233`).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

/// The transaction hash every canned receipt carries. Fixed so a test can assert on
/// the exact value the worker logged beside the nonce.
pub const TX_HASH: &str = "0xdead000000000000000000000000000000000000000000000000000000000001";

/// One redemption inside the fake's single canned transaction.
///
/// Circle's `FiatTokenV2` marks the nonce used and THEN moves the money, so a
/// redemption contributes two ADJACENT logs in that order: the `AuthorizationUsed`
/// naming the nonce it spent, and the ERC-20 `Transfer` that paid someone. That
/// order is the deployed contract's, asserted against real Base Sepolia USDC in
/// `settle_tenderly.rs` — it is the reverse of EIP-3009's reference implementation,
/// so it is copied from the chain rather than from the EIP.
///
/// A list of these is how a test describes one transaction that redeems several
/// authorizations at once — the shape a Multicall3 bundle has on-chain, and the case
/// in which "the receipt contains a correct transfer somewhere" stops meaning "this
/// nonce was the one paid for".
#[derive(Clone, Copy)]
pub struct Redeemed {
    /// Whose nonce was spent: the repeated character of the claim's nonce fixture.
    pub nonce_suffix: char,
    /// Who the accompanying transfer paid...
    pub to: &'static str,
    /// ...and how much.
    pub value: u64,
}

/// How the fake should answer the questions a sweep actually branches on.
///
/// The flags are deliberately independent switches rather than a state machine: each
/// one is a separate way the far side of the wire can differ from the happy path, and
/// a test perturbs exactly one of them so that what it proves is unambiguous. Folding
/// them into an enum would make combinations inexpressible and the fixtures harder to
/// read, which is the opposite of what this file is for.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy)]
pub struct FakeConfig {
    /// What `eth_chainId` reports. Also what `SettlementClient::connect` pins.
    pub chain_id: u64,
    /// The `authorizationState` the token contract returns — i.e. whether this
    /// authorization's nonce has been spent, by redemption OR by cancellation.
    pub authorization_used: bool,
    /// What the ONE canned transaction actually did, in order.
    ///
    /// This is the dimension that separates the ways a nonce gets spent. Empty means
    /// no `transferWithAuthorization` ever ran for the queried nonce, which with
    /// `authorization_used` set is "the payer cancelled" — the same bit on-chain and
    /// necessarily a different outcome. A redemption whose `to`/`value` are not the
    /// claim's is a nonce spent on somebody else's payment, and two entries are a
    /// bundle: one transaction redeeming several authorizations.
    pub redeemed: &'static [Redeemed],
    /// Whether the `AuthorizationUsed` log the log query returns names the
    /// transaction it came from. `true` withholds the hash — the shape a PENDING log
    /// has — leaving the settler with an event it cannot trace to any money.
    pub log_names_no_transaction: bool,
    /// Whether `eth_getLogs` honours the nonce the filter pinned. `true` makes the
    /// endpoint answer EVERY query with every `AuthorizationUsed` the transaction
    /// emitted, whichever nonce was asked about — the shape a buggy, compromised or
    /// intercepted provider has, and the one thing the settler cannot detect by
    /// asking the same endpoint again.
    pub logs_ignore_the_filter: bool,
    /// Whether the token emits its `Transfer` BEFORE the `AuthorizationUsed` (EIP-3009's
    /// reference order) instead of after it (deployed `FiatTokenV2`'s). `true` is the
    /// world a future token upgrade would put the settler in: every redemption is
    /// genuine, and no log follows the event the settler pairs on.
    pub reference_emission_order: bool,
    /// Whether the canned receipt's status is success (`true`) or reverted.
    pub receipt_succeeds: bool,
}

impl FakeConfig {
    /// Base Sepolia, a fresh authorization, a receipt that succeeds: the happy path
    /// every test starts from and then perturbs in exactly one dimension.
    pub fn base_sepolia() -> Self {
        Self {
            chain_id: 84_532,
            authorization_used: false,
            // Matches `authorization_used`: a nonce nobody has spent was spent by no
            // redemption either.
            redeemed: &[],
            log_names_no_transaction: false,
            logs_ignore_the_filter: false,
            reference_emission_order: false,
            receipt_succeeds: true,
        }
    }
}

/// A running fake endpoint plus the record of everything asked of it.
pub struct FakeChain {
    url: String,
    calls: Arc<Mutex<Vec<String>>>,
}

impl FakeChain {
    /// Binds an ephemeral port and serves until the test process exits.
    ///
    /// The task is deliberately never joined: it dies with the runtime, and a test
    /// that finished has nothing left to ask.
    pub async fn spawn(config: FakeConfig) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake rpc endpoint");
        let addr: SocketAddr = listener.local_addr().expect("read fake rpc local_addr");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = Arc::new(Fake {
            config,
            calls: Arc::clone(&calls),
        });
        let app = axum::Router::new()
            .fallback(handle)
            .with_state(Arc::clone(&state));
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fake rpc");
        });

        Self {
            // `127.0.0.1` (not `localhost`) so alloy's local-host guess fires and the
            // receipt poll runs at 250ms rather than 7s.
            url: format!("http://{addr}"),
            calls,
        }
    }

    /// The endpoint URL, to be fed through the production `rpc_url` seam.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Forgets every recorded call. Used right after `connect`, whose `eth_chainId`
    /// is harness setup rather than anything a sweep did.
    pub fn clear_calls(&self) {
        self.recorded().clear();
    }

    /// Every JSON-RPC method received since the last [`FakeChain::clear_calls`], in
    /// order.
    pub fn calls(&self) -> Vec<String> {
        self.recorded().clone()
    }

    /// How many times `method` was asked for. `0` is the interesting answer: it is
    /// what proves a claim never reached the chain at all.
    pub fn call_count(&self, method: &str) -> usize {
        self.recorded().iter().filter(|m| *m == method).count()
    }

    fn recorded(&self) -> std::sync::MutexGuard<'_, Vec<String>> {
        self.calls.lock().expect("call log mutex is not poisoned")
    }
}

/// The server's state: its canned answers and the shared call log.
struct Fake {
    config: FakeConfig,
    calls: Arc<Mutex<Vec<String>>>,
}

/// Serves one JSON-RPC POST, single or batched.
///
/// Batching is handled because it is the transport's choice, not ours: alloy may
/// coalesce requests, and a fake that only understood single calls would fail in a
/// way that looks like a bug in the worker.
async fn handle(State(fake): State<Arc<Fake>>, Json(body): Json<Value>) -> Json<Value> {
    match body {
        Value::Array(requests) => Json(Value::Array(
            requests.iter().map(|req| answer(&fake, req)).collect(),
        )),
        single => Json(answer(&fake, &single)),
    }
}

/// Answers one request object, recording the method it named.
fn answer(fake: &Arc<Fake>, request: &Value) -> Value {
    let method = request["method"].as_str().unwrap_or_default().to_owned();
    let id = request["id"].clone();
    fake.calls
        .lock()
        .expect("call log mutex is not poisoned")
        .push(method.clone());

    match result_for(&fake.config, &method, request) {
        Some(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        // Everything outside the sweep's vocabulary is an explicit error: an
        // unexpected call must break the test, not be silently absorbed.
        None => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": "method or request not supported by the fake" },
        }),
    }
}

/// The canned result for a supported method, or `None` if it is not one a sweep may
/// make — or is one the fake cannot answer as asked.
///
/// The set was arrived at empirically — arms were added until the happy path stopped
/// erroring, then removed again while it still passed — and every one of the nine
/// is a call the real provider stack makes: `eth_chainId` at connect, `eth_call` for
/// the `authorizationState` pre-flight, `eth_blockNumber` + `eth_getLogs` for the
/// `AuthorizationUsed` confirmation that follows a spent nonce (the block number
/// anchors the bounded lookback window), `eth_getTransactionCount` for alloy's
/// nonce filler, `eth_feeHistory` + `eth_estimateGas` for its gas filler,
/// `eth_sendRawTransaction` for the broadcast and `eth_getTransactionReceipt` both
/// for the wait (twice: once eagerly, once on the poll ticker) and for reading back
/// the logs of the transaction that spent the nonce.
///
/// Notably ABSENT are `eth_newBlockFilter` / `eth_getFilterChanges`. Alloy's
/// `watch_pending_transaction` asks for the receipt FIRST and returns "already
/// confirmed" if it exists (`alloy-provider/src/provider/trait.rs:1855`), so a fake
/// that always has the receipt ready never starts the block heartbeat at all. That
/// is a property of this fixture, not of the worker: an endpoint that withheld the
/// receipt for a while would need both.
fn result_for(config: &FakeConfig, method: &str, request: &Value) -> Option<Value> {
    Some(match method {
        "eth_chainId" => json!(format!("0x{:x}", config.chain_id)),
        // A uint256-wide boolean, exactly as the ABI encodes a `bool` return.
        "eth_call" => json!(format!("0x{:064x}", u8::from(config.authorization_used))),
        // A chain barely past genesis, so the settler's lookback window clamps to
        // block 0 and the canned logs below are inside it whatever the window's width.
        "eth_blockNumber" => json!("0x1"),
        // Answered for the nonce ACTUALLY asked about rather than with one canned log
        // per query: the transaction below may have spent several nonces, and which
        // one the caller asked about is the whole difference between the claim that
        // was paid and the ones bundled beside it.
        "eth_getLogs" => json!(authorization_used_logs(config, &requested_nonce(request)?)),
        // The signer has never transacted, so every sweep starts at nonce 0.
        "eth_getTransactionCount" => json!("0x0"),
        "eth_feeHistory" => json!({
            "oldestBlock": "0x1",
            "baseFeePerGas": ["0x7", "0x7"],
            "gasUsedRatio": [0.5],
            "reward": [["0x1"]],
        }),
        "eth_estimateGas" => json!("0x186a0"),
        "eth_sendRawTransaction" => json!(TX_HASH),
        "eth_getTransactionReceipt" => receipt(config),
        _ => return None,
    })
}

/// The nonce an `eth_getLogs` filter pinned as topic 2, lowercased.
///
/// `None` — a filter that does not name a nonce — makes the whole query
/// UNANSWERABLE rather than empty. An empty log list is a meaningful answer here
/// ("the payer cancelled"), so a query this fake cannot key off must fail loudly
/// instead of quietly reading as one. A topic may be serialised as a bare string or
/// as a one-element array of alternatives, so both spellings are read.
fn requested_nonce(request: &Value) -> Option<String> {
    let topic = &request["params"][0]["topics"][2];
    let hex = topic
        .as_str()
        .or_else(|| topic.get(0).and_then(Value::as_str))?;
    Some(hex.to_ascii_lowercase())
}

/// The `AuthorizationUsed` logs for `nonce` — at most one, since a nonce is spendable
/// exactly once.
fn authorization_used_logs(config: &FakeConfig, nonce: &str) -> Vec<Value> {
    transaction_logs(config)
        .into_iter()
        .filter(|log| {
            log["topics"][0] != TRANSFER_TOPIC
                && (config.logs_ignore_the_filter || log["topics"][2] == nonce)
        })
        .map(|mut log| {
            if config.log_names_no_transaction {
                // A log that names no transaction is what a PENDING one looks like.
                // It leaves the settler an event with no route to the money.
                log["transactionHash"] = Value::Null;
            }
            log
        })
        .collect()
}

/// Every log the fake's one transaction emitted, in the order the chain recorded them.
///
/// The leading transfer is unrelated — right event, right asset, wrong parties —
/// because a real transaction may carry several and the settler must find the one
/// belonging to ITS nonce rather than trust whichever comes first. Each redemption
/// then contributes its `AuthorizationUsed` immediately followed by its `Transfer`,
/// which is the order real USDC emits them in and the pairing the settler relies on —
/// unless [`FakeConfig::reference_emission_order`] flips it.
fn transaction_logs(config: &FakeConfig) -> Vec<Value> {
    let mut logs = vec![transfer_log(super::PAYEE, super::PAYER, 1)];
    for redeemed in config.redeemed {
        let event = authorization_used_log(redeemed.nonce_suffix);
        let transfer = transfer_log(super::PAYER, redeemed.to, redeemed.value);
        // The pair is always adjacent — only which one comes first is configurable,
        // because that order is the token's and not the settler's to choose.
        if config.reference_emission_order {
            logs.push(transfer);
            logs.push(event);
        } else {
            logs.push(event);
            logs.push(transfer);
        }
    }

    // `logIndex` is assigned LAST because it is a property of the block, not of this
    // transaction: see [`FIRST_LOG_INDEX`].
    for (position, log) in logs.iter_mut().enumerate() {
        let index = FIRST_LOG_INDEX + u64::try_from(position).expect("a small log list");
        log["logIndex"] = json!(format!("0x{index:x}"));
    }
    logs
}

/// The block-wide index of this transaction's FIRST log.
///
/// Deliberately not zero. `logIndex` counts logs across the whole BLOCK, not within
/// a receipt, so a transaction that is not the block's first starts partway up the
/// numbering — and code that used a `logIndex` to subscript a receipt's own log list
/// would read the wrong log or none at all. Offsetting it here is what makes the
/// difference observable instead of accidentally harmless.
const FIRST_LOG_INDEX: u64 = 0x10;

/// One `AuthorizationUsed` log, for the nonce built from `nonce_suffix`.
///
/// Only the nonce topic is real, and it is load-bearing: it is how the fake answers
/// for the authorization actually asked about. topic0 is left blank on purpose — the
/// settler never decodes this log (it matches it by filter, then by POSITION), and
/// restating the event's keccak here would only make the fixture agree with the
/// crate's `sol!` declaration instead of testing it.
fn authorization_used_log(nonce_suffix: char) -> Value {
    json!({
        "address": super::ASSET,
        "topics": [zeros(32), topic(super::PAYER), nonce_word(nonce_suffix)],
        "data": "0x",
        "blockHash": zeros(32),
        "blockNumber": "0x1",
        "transactionHash": TX_HASH,
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

/// A mined receipt for [`TX_HASH`], successful or reverted, carrying every log the
/// transaction emitted.
///
/// `status` is one point of this fixture: a reverted receipt is the one on-chain
/// answer that must NOT mark a claim settled. The logs are the other: the settler
/// reaches the receipt of whichever transaction spent the nonce and looks there for
/// the money, because the `AuthorizationUsed` event alone never names a recipient or
/// an amount.
fn receipt(config: &FakeConfig) -> Value {
    json!({
        "transactionHash": TX_HASH,
        "transactionIndex": "0x0",
        "blockHash": zeros(32),
        "blockNumber": "0x1",
        "from": zeros(20),
        "to": zeros(20),
        "cumulativeGasUsed": "0x186a0",
        "gasUsed": "0x186a0",
        "contractAddress": Value::Null,
        "logs": transaction_logs(config),
        "logsBloom": zeros(256),
        "status": if config.receipt_succeeds { "0x1" } else { "0x0" },
        "type": "0x2",
        "effectiveGasPrice": "0x7",
    })
}

/// `keccak256("Transfer(address,address,uint256)")` — ERC-20's one canonical event.
///
/// Written out rather than derived from the crate under test ON PURPOSE. The settler
/// decodes this log against its own `sol!` declaration, so a fixture that computed
/// the hash the same way would only prove the two agree with each other; a literal
/// makes the fake an independent oracle for the topic.
const TRANSFER_TOPIC: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

/// One ERC-20 `Transfer` of the fixture asset. `from` and `to` are indexed, so they
/// are topics; the amount travels in the data word.
fn transfer_log(from: &str, to: &str, value: u64) -> Value {
    json!({
        "address": super::ASSET,
        "topics": [TRANSFER_TOPIC, topic(from), topic(to)],
        "data": format!("0x{value:064x}"),
        "blockHash": zeros(32),
        "blockNumber": "0x1",
        "transactionHash": TX_HASH,
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

/// A claim nonce as its 32-byte word: the fixture nonces are one character repeated.
fn nonce_word(nonce_suffix: char) -> Value {
    json!(format!("0x{}", String::from(nonce_suffix).repeat(64)))
}

/// An address as an indexed topic: left-padded to a 32-byte word.
fn topic(address: &str) -> Value {
    json!(format!(
        "0x{}{}",
        "00".repeat(12),
        address.trim_start_matches("0x")
    ))
}

/// A `0x`-prefixed run of `n` zero bytes, for the many hash-shaped fields above.
fn zeros(n: usize) -> Value {
    json!(format!("0x{}", "00".repeat(n)))
}
