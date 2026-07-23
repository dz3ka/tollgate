//! M5b — one settlement sweep against a REAL chain, from a REAL signature.
//!
//! The hermetic suite next door proves every branch of the sweep's state machine
//! with the far side of the socket replaced by a canned JSON-RPC fake. It cannot
//! prove the one thing that only a chain can answer: that the bytes we broadcast are
//! bytes the token contract ACCEPTS. A fake will happily return a successful receipt
//! for calldata no `FiatToken` would ever honour, so a wrong `v`, a swapped argument
//! or a mis-built EIP-712 digest would pass every offline test and fail on the first
//! real claim.
//!
//! So this test signs a genuine EIP-3009 authorization with a throwaway key and lets
//! the shipping worker redeem it against canonical Base Sepolia USDC on a Tenderly
//! virtual testnet forked from Base Sepolia — then checks the money actually moved.
//!
//! ## Why it is env-gated
//! The endpoint URL carries an API key, so it lives outside the repository and is
//! injected as `TOLLGATE_TENDERLY_RPC_URL`. Without it this test SKIPS: it makes no
//! network call, starts no container and never fails. `make ci` on a machine that has
//! never seen the credential must be completely unaffected by this file, which is why
//! the environment check is the very first thing the test does.
//!
//! ## Why the fork keeps chain id 84532
//! USDC's EIP-712 domain separator is bound to the chain id of the network it was
//! deployed on. A virtual testnet with a vanity chain id would make every
//! authorization fail signature validation inside the contract — and would also fall
//! outside `tollgate-core`'s settlement allowlist, so `SettlementClient::connect`
//! would refuse the endpoint. The fork therefore keeps Base Sepolia's real chain id,
//! and the test asserts that before doing anything else.

// The shared harness serves two test binaries; this one needs the Postgres container
// and the log capture but not the JSON-RPC fake, so part of it is dead code here.
#[allow(dead_code)]
mod support;

use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync as _;
use alloy::sol_types::SolCall;

use tollgate_core::x402::Network;
use tollgate_ledger::Claim;
use tollgate_settler::{settle_batch, SettlementClient, Shutdown, SweepReport};

use support::{capture_logs, logged, start_migrated_ledger};

alloy::sol! {
    /// `FiatToken`'s own EIP-712 domain separator. Reading it beats rebuilding it —
    /// see [`domain_separator`].
    function DOMAIN_SEPARATOR() returns (bytes32);

    /// The token balance, used to prove the settlement moved real value rather than
    /// merely mining a successful transaction.
    function balanceOf(address account) returns (uint256);
}

/// The environment variable carrying the forked endpoint. Its VALUE is a credential
/// and is never logged, asserted on, or written anywhere.
const RPC_URL_VAR: &str = "TOLLGATE_TENDERLY_RPC_URL";

/// Canonical Base Sepolia USDC, checksummed. The fork inherits its real deployment —
/// proxy, storage and all — so the authorization is validated by the same contract
/// that would validate it on the live testnet.
const USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

/// Base Sepolia's chain id. Asserted rather than assumed: see the module header.
const BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;

/// The authorized amount, in USDC base units (6 decimals) — 0.01 USDC.
const VALUE: u64 = 10_000;

/// How long the authorization stays redeemable. Comfortably past the sweep's
/// `MIN_LEAD`, so the claim is genuine work rather than one filtered out for expiry.
const LIFETIME_SECS: u64 = 3_600;

/// Gas money for the throwaway relayer: 1 ETH, which is orders of magnitude more than
/// one `transferWithAuthorization` costs and saves tuning it.
const GAS_FUNDING_WEI: u128 = 1_000_000_000_000_000_000;

/// EIP-3009's struct type, verbatim. The typehash is keccak of exactly this string,
/// so a stray space here is a signature the contract will reject.
const TRANSFER_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// The whole point of M5b, end to end: a signature a payer really made becomes USDC
/// the operator really holds, and the ledger row stops being owed.
///
/// It asserts three independent facts, because any one alone can lie. The sweep
/// REPORT says the worker thinks it settled; the LEDGER says the row left the work
/// queue; the on-chain RECEIPT and token BALANCE say the chain agrees. A bug that
/// satisfies all three has actually settled a payment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signed_authorization_is_redeemed_against_real_usdc() {
    let Some(rpc_url) = endpoint() else { return };
    capture_logs();

    // A second, wallet-free provider for the test's OWN reads and cheat calls. The
    // settler's client is deliberately not reused: this test must observe the chain
    // the way an outsider would, not through the object under test.
    let chain = ProviderBuilder::new().connect(&rpc_url).await;
    let chain = redacted(chain, "connect to the forked endpoint");
    assert_eq!(
        redacted(chain.get_chain_id().await, "read the chain id"),
        BASE_SEPOLIA_CHAIN_ID,
        "the fork must keep Base Sepolia's chain id, or USDC's domain separator \
         (and core's settlement allowlist) no longer match this endpoint"
    );

    // Throwaway on both sides: the payer key signs away funds and the relayer key
    // signs transactions, so neither may ever be a key that exists outside this test.
    let payer = PrivateKeySigner::random();
    let relayer = PrivateKeySigner::random();
    // The operator collects to the account that pays the gas — realistic, and being
    // freshly generated it starts with a zero USDC balance the test can assert on.
    let recipient = relayer.address();

    fund_gas(&chain, recipient).await;
    fund_usdc(&chain, payer.address(), U256::from(VALUE)).await;
    assert_eq!(
        usdc_balance(&chain, recipient).await,
        U256::ZERO,
        "a freshly generated recipient must start with no USDC, or the balance check below proves nothing"
    );

    let now = now_unix();
    let claim = signed_claim(
        &payer,
        recipient,
        domain_separator(&chain).await,
        now + LIFETIME_SECS,
    );

    let (_container, ledger) = start_migrated_ledger().await;
    assert!(
        ledger.record(&claim).await.expect("record the claim"),
        "the fixture claim must insert, or the sweep below would have nothing to do"
    );

    let client = redacted(
        SettlementClient::connect(&rpc_url, relayer).await,
        "connect the settlement client",
    );
    // The sweep's clock is the same "now" the authorization was written against, so
    // the claim sits well inside its validity window.
    let report = settle_batch(&ledger, &client, now, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 1,
            failed: 0,
            skipped: 0
        },
        "the worker must report the claim settled"
    );
    assert!(
        !still_owed(&ledger, &claim).await,
        "a settled claim must leave the work queue, or the next sweep pays to redeem it again"
    );

    // The chain's own verdict. `settle_batch` could report success off a receipt it
    // misread, so the receipt is fetched independently, by the hash the worker logged
    // — which is also the only handle an operator has on the transaction.
    let tx_hash = logged_tx_hash(claim.nonce.as_str());
    let receipt = redacted(
        chain
            .get_transaction_receipt(
                tx_hash
                    .parse()
                    .expect("the logged tx hash is a 32-byte word"),
            )
            .await,
        "read the settlement receipt",
    )
    .expect("the transaction hash the worker logged must exist on-chain");
    assert!(
        receipt.status(),
        "the settlement transaction must have a SUCCESS receipt, not merely have been mined"
    );
    assert_transfer_immediately_follows_authorization_used(
        &receipt,
        payer.address(),
        recipient,
        claim
            .nonce
            .as_str()
            .parse()
            .expect("the claim nonce is a word"),
    );
    assert_eq!(
        usdc_balance(&chain, recipient).await,
        U256::from(VALUE),
        "the recipient must actually hold the authorized USDC — a mined transaction that moved nothing is not a settlement"
    );
}

/// Asserts the fact settlement confirmation is BUILT ON: real USDC emits the ERC-20
/// `Transfer` immediately AFTER the `AuthorizationUsed` that spent the nonce.
///
/// `redemption_status` pairs each event with the transfer at `logIndex + 1`, because
/// one transaction can spend many nonces and a transaction-wide search would let a
/// single genuine payment confirm every claim bundled beside it. That pairing is only
/// sound if the two logs really are adjacent, in that order — a property of Circle's
/// `FiatTokenV2` code (it marks the authorization used, THEN transfers, which is the
/// REVERSE of EIP-3009's reference implementation), not of anything tollgate controls.
/// No canned receipt can prove it, and the EIP text gets it backwards, so it is
/// asserted here against the deployed contract. A token that emitted the other order
/// would fail this test rather than silently go unsettleable.
///
/// The topics are derived from the canonical EIP signatures rather than from the
/// settler's own `sol!` declarations, so this checks USDC against the standard instead
/// of checking tollgate against itself.
fn assert_transfer_immediately_follows_authorization_used(
    receipt: &TransactionReceipt,
    from: Address,
    to: Address,
    nonce: B256,
) {
    let logs = receipt.logs();
    let authorization_used = keccak256("AuthorizationUsed(address,bytes32)");
    let position = logs
        .iter()
        .position(|log| {
            log.inner.address == usdc()
                && log.inner.topics().first() == Some(&authorization_used)
                && log.inner.topics().get(2) == Some(&nonce)
        })
        .expect("the redemption must emit AuthorizationUsed for the claim's nonce");
    let transfer = logs.get(position + 1).expect(
        "AuthorizationUsed must not be the transaction's last log, or nothing could \
         have transferred the money with it",
    );
    // Adjacency in the BLOCK-wide numbering as well as in this receipt's list: that is
    // the index the settler actually does its arithmetic on.
    assert_eq!(
        transfer.log_index,
        logs[position].log_index.map(|index| index + 1),
        "the paying transfer must sit at exactly logIndex + 1 of the event"
    );
    assert_eq!(
        transfer.inner.address,
        usdc(),
        "the paying transfer must come from the token contract itself"
    );
    assert_eq!(
        transfer.inner.topics().first(),
        Some(&keccak256("Transfer(address,address,uint256)")),
        "the log before AuthorizationUsed must be an ERC-20 Transfer"
    );
    assert_eq!(
        transfer.inner.topics().get(1),
        Some(&from.into_word()),
        "the paired transfer must come FROM the payer"
    );
    assert_eq!(
        transfer.inner.topics().get(2),
        Some(&to.into_word()),
        "the paired transfer must go TO the claim's payee"
    );
    assert_eq!(
        U256::from_be_slice(transfer.inner.data.data.as_ref()),
        U256::from(VALUE),
        "the paired transfer must carry the claim's value"
    );
}

/// Signs a real EIP-3009 authorization and wraps it as the ledger row a gateway
/// would have written for it.
///
/// The signing and the row are built TOGETHER, in one function, on purpose: the
/// contract checks the signature against exactly these six fields, so a claim that
/// disagrees with the digest by a single byte reverts with no useful diagnostic.
/// Splitting them across the test body is how that divergence creeps in.
fn signed_claim(
    payer: &PrivateKeySigner,
    recipient: Address,
    domain_separator: B256,
    valid_before: u64,
) -> Claim {
    // Unique per run with no RNG of its own: the payer key is freshly random, so its
    // address is too. This matters because the fork REMEMBERS — a nonce replayed from
    // a previous run would be rejected by the contract as already used.
    let nonce = keccak256(payer.address().as_slice());
    let digest = transfer_digest(
        domain_separator,
        payer.address(),
        recipient,
        U256::from(VALUE),
        U256::ZERO,
        U256::from(valid_before),
        nonce,
    );
    let signature = payer
        .sign_hash_sync(&digest)
        .expect("sign the authorization digest");

    Claim {
        payer: lowercase_hex(payer.address())
            .parse()
            .expect("a hex address is a valid EvmAddress"),
        nonce: format!("0x{}", alloy::hex::encode(nonce))
            .parse()
            .expect("a 32-byte word is a valid Nonce"),
        payee: lowercase_hex(recipient)
            .parse()
            .expect("a hex address is a valid EvmAddress"),
        value: VALUE
            .to_string()
            .parse()
            .expect("a decimal is a valid UintStr"),
        valid_after: "0".parse().expect("a decimal is a valid UintStr"),
        valid_before: valid_before
            .to_string()
            .parse()
            .expect("a decimal is a valid UintStr"),
        // `as_bytes` puts `v` in the 65th byte as 27/28, which is what core's
        // signature parser accepts — and k256 already normalised `s` to the low half
        // order, so the parser's EIP-2 malleability check passes.
        signature: format!("0x{}", alloy::hex::encode(signature.as_bytes())),
        asset: USDC.parse().expect("the canonical USDC address is valid"),
        network: Network::BaseSepolia,
    }
}

/// The endpoint to test against, or `None` after saying why the test was skipped.
///
/// This is half the value of the file. The credential lives outside the repository,
/// so the ONLY acceptable behaviour without it is to do nothing at all: no container,
/// no socket, no failure. An `eprintln!` rather than a silent return so a run that
/// looks green is not quietly hiding an untested path. The value itself is never
/// printed.
fn endpoint() -> Option<String> {
    match std::env::var(RPC_URL_VAR) {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!(
                "SKIPPED settle_tenderly: {RPC_URL_VAR} is unset. \
                 Set it to a Tenderly virtual testnet forked from Base Sepolia to run \
                 the on-chain settlement end-to-end test."
            );
            None
        }
    }
}

/// Unwraps a chain-facing result, DISCARDING the error rather than printing it.
///
/// `expect` would format the error, and alloy's transport errors happily include the
/// endpoint they failed to reach — which here is a URL with an API key in its path
/// (ADR-0034). A dead fork must produce a useful test failure, not a credential in
/// the CI log, so the panic message says what was being attempted and nothing else.
#[track_caller]
fn redacted<T, E>(result: Result<T, E>, what: &str) -> T {
    let Ok(value) = result else {
        panic!("could not {what} (error redacted: it may carry the rpc credential)")
    };
    value
}

/// Gives the relayer enough ETH to pay for one settlement.
///
/// A freshly generated key holds nothing on a fork of a public testnet and there is
/// no faucet inside a test, so the balance is set directly through Tenderly's cheat
/// RPC. It is a plain JSON-RPC method with no typed provider API behind it, hence the
/// raw request.
async fn fund_gas(chain: &impl Provider, address: Address) {
    let _: serde_json::Value = redacted(
        chain
            .raw_request(
                Cow::Borrowed("tenderly_setBalance"),
                (address, U256::from(GAS_FUNDING_WEI)),
            )
            .await,
        "fund the relayer with gas",
    );
}

/// Gives the payer the USDC the authorization spends, by writing the token's balance
/// slot through Tenderly's cheat RPC.
///
/// Setting the balance rather than transferring it from a whale keeps the test from
/// depending on any particular account still holding funds on the forked block.
async fn fund_usdc(chain: &impl Provider, address: Address, amount: U256) {
    let _: serde_json::Value = redacted(
        chain
            .raw_request(
                Cow::Borrowed("tenderly_setErc20Balance"),
                (usdc(), address, amount),
            )
            .await,
        "fund the payer with USDC",
    );
}

/// Reads USDC's OWN EIP-712 domain separator off the chain.
///
/// Deliberately NOT rebuilt from `name` and `version` strings. `FiatToken`'s version
/// is `"2"` on this deployment and `"1"` on others, and guessing wrong produces an
/// opaque revert inside the contract's signature check that looks identical to a
/// dozen other mistakes. Signing against the authoritative separator collapses that
/// search space: if validation still fails, it can only be the struct hash.
async fn domain_separator(chain: &impl Provider) -> B256 {
    let output = redacted(
        chain
            .call(call_usdc(DOMAIN_SEPARATORCall {}.abi_encode()))
            .await,
        "read the USDC domain separator",
    );
    DOMAIN_SEPARATORCall::abi_decode_returns(&output).expect("DOMAIN_SEPARATOR returns a bytes32")
}

/// The account's USDC balance — the test's proof that value moved.
async fn usdc_balance(chain: &impl Provider, account: Address) -> U256 {
    let output = redacted(
        chain
            .call(call_usdc(balanceOfCall { account }.abi_encode()))
            .await,
        "read a USDC balance",
    );
    balanceOfCall::abi_decode_returns(&output).expect("balanceOf returns a uint256")
}

/// An `eth_call` aimed at the token contract.
fn call_usdc(calldata: Vec<u8>) -> TransactionRequest {
    TransactionRequest::default()
        .to(usdc())
        .input(calldata.into())
}

/// The token address as alloy sees it.
fn usdc() -> Address {
    USDC.parse().expect("the canonical USDC address is valid")
}

/// Builds the EIP-712 digest the payer signs, over a domain separator READ FROM THE
/// CHAIN.
///
/// Only the struct hash is assembled here — the `0x1901` prefix and the separator are
/// EIP-712 boilerplate — so this function is the single place a field-encoding
/// mistake could hide, and the claim recorded above must mirror it argument for
/// argument.
fn transfer_digest(
    domain_separator: B256,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    // Every EIP-712 member is a 32-byte word: addresses left-padded, uints
    // big-endian, and the nonce used verbatim because EIP-3009 does not re-hash it.
    let mut fields = Vec::with_capacity(7 * 32);
    for word in [
        keccak256(TRANSFER_TYPE.as_bytes()),
        from.into_word(),
        to.into_word(),
        value.into(),
        valid_after.into(),
        valid_before.into(),
        nonce,
    ] {
        fields.extend_from_slice(word.as_slice());
    }

    let mut preimage = [0u8; 66];
    preimage[0] = 0x19;
    preimage[1] = 0x01;
    preimage[2..34].copy_from_slice(domain_separator.as_slice());
    preimage[34..66].copy_from_slice(keccak256(fields).as_slice());
    keccak256(preimage)
}

/// Whether the claim is still owed, read through the same public query the settler
/// uses.
///
/// `settled_at` has no getter, so a row's disappearance from `settleable` is the only
/// observation of settlement the ledger's API offers — the same trick the hermetic
/// suite uses.
async fn still_owed(ledger: &tollgate_ledger::PgClaimLedger, claim: &Claim) -> bool {
    ledger
        .settleable(0, 50)
        .await
        .expect("read settleable claims")
        .iter()
        .any(|c| c.nonce.as_str() == claim.nonce.as_str())
}

/// The transaction hash the worker logged beside this claim's nonce.
///
/// Taken from the LOG rather than from an API because that is where it actually
/// lives: `settle_batch` returns counts, and `mark_settled` stores no hash, so the log
/// line is the operator's only route from a ledger row to a block explorer. Fetching a
/// real receipt for it is what proves that route is not decorative.
fn logged_tx_hash(nonce: &str) -> String {
    let logs = logged();
    let line = logs
        .lines()
        .find(|line| line.contains(nonce) && line.contains("claim settled on-chain"))
        .expect("the worker must log the settlement with the claim's nonce");
    let tail = line
        .split("tx_hash=")
        .nth(1)
        .expect("the settlement log line must carry a tx_hash field");
    // The field may or may not be quoted depending on how `tracing` renders it, so the
    // hash is taken as the leading run of hex-ish characters either way.
    tail.trim_start_matches('"')
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect()
}

/// An address as `0x` + 40 lowercase hex.
///
/// `Display` for alloy's `Address` emits an EIP-55 checksum; the ledger's primary key
/// is lowercased (`Claim::from_payment`), so fixtures must be too or a claim recorded
/// here would not match one the gateway recorded.
fn lowercase_hex(address: Address) -> String {
    format!("0x{}", alloy::hex::encode(address))
}

/// Wall-clock unix seconds. The authorization's validity window is real time, not the
/// hermetic suite's fixed clock, because a real contract checks it against the real
/// block timestamp.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is after the unix epoch")
        .as_secs()
}
