//! M5b — one settlement sweep, end to end, with nothing stubbed below the socket.
//!
//! Each test drives the REAL [`settle_batch`] over a REAL `PgClaimLedger` (a
//! throwaway Postgres) and a REAL `SettlementClient` (alloy's provider, fillers and
//! signing wallet), with only the far side of the wire replaced by a local
//! JSON-RPC fake reached through the production `TOLLGATE_RPC_URL` seam. So the ABI
//! encoding, the signature split, the transaction signing and the SQL are all the
//! shipping code; what varies is only what the chain answers.
//!
//! The eleven tests are the eleven branches of the sweep's state machine — settled by
//! redemption, settled by discovering someone already redeemed, CANCELLED by the
//! payer, spent by an authorization that paid someone else, bundled into a
//! transaction that paid a DIFFERENT claim, proved by a log that names no
//! transaction, answered with a log for another nonce entirely, pointed at an event
//! nothing followed, reverted, too close to expiry, wrong chain — and each asserts BOTH the
//! ledger consequence and what did or did not reach the chain. The negative half matters most: "no transaction was sent"
//! is the only observable difference between a claim that was skipped and one that was
//! attempted and refused.
//!
//! ## Runtime / environment
//! Needs a container runtime reachable via `DOCKER_HOST` (Docker or a rootless
//! Podman socket). It needs no network beyond loopback and no chain.

mod support;

use support::rpc_fake::{FakeChain, FakeConfig, Redeemed, TX_HASH};
use support::{
    capture_logs, claim, connect_to, is_still_owed, logged, start_migrated_ledger, NOW, PAYEE,
    PAYER, VALUE,
};

use tollgate_core::x402::Network;
use tollgate_ledger::PgClaimLedger;
use tollgate_settler::{settle_batch, Shutdown, SweepReport};

/// Comfortably beyond `MIN_LEAD`, so the expiry filter admits the claim and the test
/// observes only the dimension it is actually about.
const LIVE: u64 = NOW + 3_600;

/// Branch 1: a fresh authorization is redeemed and the row is marked settled.
///
/// This is the whole point of the worker — everything else is a way of NOT doing
/// this — so it asserts the full round trip: exactly one broadcast reached the
/// chain, and the claim left the work queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redeemed_claim_is_marked_settled() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, '1', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig::base_sepolia()).await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 1,
            failed: 0,
            skipped: 0
        },
        "a redeemable claim must be reported settled"
    );
    assert_eq!(
        fake.call_count("eth_sendRawTransaction"),
        1,
        "exactly one settlement transaction must be broadcast for one claim"
    );
    assert!(
        !is_still_owed(&ledger, '1').await,
        "a settled claim must leave the work queue, or the next sweep pays to redeem it again"
    );
}

/// Branch 2: an authorization the chain already knows is spent is recorded as
/// settled WITHOUT sending a transaction.
///
/// This is the crash-window proof, and the reason the pre-flight `eth_call` exists.
/// A worker that dies between broadcasting and writing `settled_at` leaves a claim
/// that WAS paid still marked owed; without the pre-flight it would be resubmitted
/// every minute until expiry, burning revert gas each time. The zero-broadcast
/// assertion is what distinguishes "asked first" from "tried and reverted".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_already_used_authorization_is_settled_without_a_transaction() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, '2', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        authorization_used: true,
        // Spent AND redeemed, paying this claim exactly: the `AuthorizationUsed` log
        // and the transfer beside it are what make the spent nonce mean "we were
        // paid" rather than "the payer cancelled".
        redeemed: &[Redeemed {
            nonce_suffix: '2',
            to: PAYEE,
            value: VALUE,
        }],
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 1,
            failed: 0,
            skipped: 0
        },
        "an authorization already used on-chain means we were paid: the row must be settled"
    );
    assert_eq!(
        fake.call_count("eth_sendRawTransaction"),
        0,
        "a claim the chain reports as already redeemed must never be broadcast again"
    );
    assert!(
        !is_still_owed(&ledger, '2').await,
        "the row must be reconciled, not left owed forever"
    );
}

/// Branch 3: an authorization whose nonce is spent but which was CANCELLED, not
/// redeemed, leaves the claim owed — and never sends a transaction.
///
/// This is the branch that separates `authorizationState` from payment.
/// `cancelAuthorization` writes the identical `_authorizationStates` slot that
/// `transferWithAuthorization` does, so a payer can be served, cancel their own
/// authorization for ~50k gas, and — for a worker that trusts the flag — have the
/// operator's ledger record revenue that never existed. Only the `AuthorizationUsed`
/// event distinguishes the two, so here the flag is `true` and the log is ABSENT.
///
/// All three assertions matter. The row must stay owed (the money never moved), the
/// report must count it FAILED rather than settled, and nothing may be broadcast —
/// re-redeeming a spent nonce is a guaranteed revert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_authorization_is_never_recorded_as_settled() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, '6', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        // The nonce is spent...
        authorization_used: true,
        // ...but no transfer ever emitted an event for it: it was cancelled.
        redeemed: &[],
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 1,
            skipped: 0
        },
        "a cancelled authorization moved no money: it must never be counted as settled"
    );
    assert_eq!(
        fake.call_count("eth_sendRawTransaction"),
        0,
        "a spent nonce must not be re-broadcast — redeeming it is a guaranteed revert"
    );
    assert!(
        is_still_owed(&ledger, '6').await,
        "a cancelled claim was never paid, so the row must stay owed rather than \
         record revenue the operator never received"
    );

    // An operator must be able to tell "the payer walked" from "the RPC is flaky",
    // so the cancellation is logged at ERROR with its own wording.
    let nonce = format!("0x{}", "6".repeat(64));
    assert!(
        logged().lines().any(|line| line.contains("ERROR")
            && line.contains(&nonce)
            && line.contains("CANCELLED")),
        "a cancellation must be reported at ERROR, distinctly from an ordinary failure"
    );
}

/// Branch 4: a nonce spent by an authorization that paid SOMEONE ELSE is never
/// recorded as settled, even though its `AuthorizationUsed` event is genuine.
///
/// `AuthorizationUsed(authorizer indexed, nonce indexed)` names the NONCE, not the
/// claim: the recipient and the amount are nowhere in it. So a payer can sign two
/// authorizations under one nonce — a $10 one presented to the gateway, a 1-wei one
/// paid to themselves — get served, then broadcast the cheap one for ~60k gas. The
/// event that lands is real and matches the settler's filter exactly; only the ERC-20
/// `Transfer` inside that same transaction says who was actually paid.
///
/// Here the log is present and the transaction's transfer goes to a stranger for the
/// wrong amount. The row must stay owed, the sweep must count it FAILED, and the line
/// must be distinguishable from an RPC fault — otherwise the operator's ledger records
/// $10 of revenue that never arrived, silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nonce_spent_on_another_transfer_is_never_recorded_as_settled() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, '7', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        // The nonce is spent and a genuine `AuthorizationUsed` was emitted for it...
        authorization_used: true,
        // ...but the transfer that came with it went somewhere else entirely.
        redeemed: &[Redeemed {
            nonce_suffix: '7',
            to: "0xdddddddddddddddddddddddddddddddddddddddd",
            value: 1,
        }],
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 1,
            skipped: 0
        },
        "an event that names only the nonce is not proof of payment: this claim was never paid"
    );
    assert_eq!(
        fake.call_count("eth_sendRawTransaction"),
        0,
        "the nonce is spent either way, so re-broadcasting it would only burn revert gas"
    );
    assert!(
        is_still_owed(&ledger, '7').await,
        "the operator is still owed this money, so the row must stay in the work queue"
    );

    // Distinct wording, at ERROR: "the payer reused a nonce on a transfer that was not
    // ours" is a permanent fact about one claim, not the transient RPC fault that
    // shares the failed bucket.
    let nonce = format!("0x{}", "7".repeat(64));
    assert!(
        logged().lines().any(|line| line.contains("ERROR")
            && line.contains(&nonce)
            && line.contains("did not pay this claim")),
        "a nonce spent on someone else's transfer must be reported at ERROR, distinctly \
         from both a cancellation and an RPC fault"
    );
}

/// Branch 5: one payment settles ONE claim. A second claim whose nonce was spent in
/// the SAME transaction, beside its own 1-wei transfer, stays owed.
///
/// This is the bundle attack, and it is what makes the transfer check a per-EVENT
/// check rather than a per-transaction one. A payer served k times on one route holds
/// k claims with the same payee, asset and value — `verify_payment` only requires
/// `value >= maxAmountRequired`, so identical amounts are the normal case. They sign k
/// fresh authorizations reusing those k nonces, each paying themselves 1 wei, and send
/// ONE transaction (Multicall3 is canonical on Base, and `transferWithAuthorization`
/// is signature-authenticated, so `msg.sender` is irrelevant) carrying one genuine
/// payment plus all k cheap redemptions.
///
/// Every claim's `AuthorizationUsed` log then points at that one transaction, whose
/// receipt does contain a correct transfer — one of them. A settler that scans the
/// receipt for "a transfer that matches" books all k. Pairing each event with the
/// transfer IMMEDIATELY AFTER IT — the order real USDC emits them in — is what keeps
/// the count honest: paid once, booked once. The direction matters as much as the
/// adjacency: the genuine transfer sits immediately BEFORE the bundled claim's event,
/// so a settler that accepted either neighbour would settle this claim anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_bundled_beside_a_genuine_payment_is_not_settled_by_it() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, '8', LIVE, Network::BaseSepolia).await;
    seed(&ledger, '9', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        // Both nonces are spent, by one transaction that paid this operator once...
        authorization_used: true,
        redeemed: &[
            Redeemed {
                nonce_suffix: '8',
                to: PAYEE,
                value: VALUE,
            },
            // ...and paid the payer themselves 1 wei for the second nonce.
            Redeemed {
                nonce_suffix: '9',
                to: PAYER,
                value: 1,
            },
        ],
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 1,
            failed: 1,
            skipped: 0
        },
        "one payment may settle exactly one claim, however many nonces its transaction spent"
    );
    assert!(
        !is_still_owed(&ledger, '8').await,
        "the claim the transfer actually paid must leave the work queue"
    );
    assert!(
        is_still_owed(&ledger, '9').await,
        "the bundled claim was paid 1 wei to the payer's own account: the operator is \
         still owed it, so the row must stay in the queue"
    );

    let bundled = format!("0x{}", "9".repeat(64));
    assert!(
        logged().lines().any(|line| line.contains("ERROR")
            && line.contains(&bundled)
            && line.contains("did not pay this claim")),
        "the bundled claim must be reported at ERROR as a nonce spent on someone else's \
         transfer, not silently settled off the payment beside it"
    );
}

/// Branch 6: an `AuthorizationUsed` log that names no transaction is INCONCLUSIVE —
/// the claim stays owed, and the payer is not accused of anything.
///
/// A log with no transaction hash (a pending one, or an endpoint that elided the
/// field) leaves no route from the event to the money: there is no receipt to read,
/// so nothing is proved either way. Reporting it as "the payer signed two
/// authorizations under one nonce" would put a specific, permanent accusation in the
/// operator's audit trail on the strength of a missing field. The claim must fail the
/// way an RPC fault does — quietly, and retried next sweep.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_that_names_no_transaction_accuses_nobody() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, 'a', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        authorization_used: true,
        // A redemption that WOULD have paid this claim in full, so nothing but the
        // missing transaction hash stands between the settler and a confirmation.
        redeemed: &[Redeemed {
            nonce_suffix: 'a',
            to: PAYEE,
            value: VALUE,
        }],
        log_names_no_transaction: true,
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 1,
            skipped: 0
        },
        "an untraceable log proves no payment: the claim must not be settled"
    );
    assert!(
        is_still_owed(&ledger, 'a').await,
        "the question is unanswered, so the row must stay owed for the next sweep to re-ask"
    );

    let nonce = format!("0x{}", "a".repeat(64));
    assert!(
        !logged()
            .lines()
            .any(|line| line.contains(&nonce) && line.contains("signed two authorizations")),
        "a log that proves nothing must never be reported as the payer having reused a nonce"
    );
    assert!(
        logged()
            .lines()
            .any(|line| line.contains("WARN") && line.contains(&nonce)),
        "the inconclusive outcome must still be visible to an operator, as a degraded \
         read rather than a verdict"
    );
}

/// Branch 7: a mined-but-reverted settlement leaves the claim owed and says so at
/// ERROR.
///
/// A revert is the one on-chain answer that costs gas and moves no money, so it must
/// never be mistaken for success. It is logged at ERROR rather than WARN because,
/// unlike a transport blip, it will reproduce identically on every sweep until
/// something outside the worker changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reverted_settlement_leaves_the_claim_owed() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, '3', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        receipt_succeeds: false,
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 1,
            skipped: 0
        },
        "a reverted transaction settles nothing"
    );
    assert!(
        is_still_owed(&ledger, '3').await,
        "a claim whose redemption reverted is still owed and must stay in the queue"
    );

    // Matched on the nonce (unique to this test) plus the transaction hash: an
    // operator's only route from a reverted row to the block explorer.
    let nonce = format!("0x{}", "3".repeat(64));
    assert!(
        logged()
            .lines()
            .any(|line| line.contains("ERROR") && line.contains(&nonce) && line.contains(TX_HASH)),
        "a revert must be reported at ERROR with the nonce and the transaction hash"
    );
}

/// Branch 8: a claim expiring inside `MIN_LEAD` is never even fetched.
///
/// Redemption is not instantaneous, so an authorization with seconds left will
/// expire in the mempool and revert. The assertion is on the RPC log rather than on
/// the report: the claim must not merely fail, it must never reach the chain at all,
/// which is what proves the cutoff is applied to the QUERY and not after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_too_close_to_expiry_is_never_fetched() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    // Ten seconds of life left: genuinely unexpired, but inside the lead time.
    seed(&ledger, '4', NOW + 10, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig::base_sepolia()).await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport::default(),
        "a claim inside the expiry lead time is not work: the sweep must be empty"
    );
    assert_eq!(
        fake.calls(),
        Vec::<String>::new(),
        "a claim about to expire must cost no RPC call at all"
    );
    assert!(
        is_still_owed(&ledger, '4').await,
        "the row is left alone — it is neither settled nor rewritten"
    );
}

/// Branch 9: a claim minted for another chain is SKIPPED, not failed, and never
/// touches the RPC.
///
/// `SettlementClient` refuses a foreign claim on its own, so the worker's pre-filter
/// would be redundant if the counts did not matter — but they do. Another
/// deployment settles that claim, so counting it as a failure would put a permanent
/// non-zero `failed` in the liveness line of a perfectly healthy worker. The zero
/// RPC calls prove it never went near the chain either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_for_another_chain_is_skipped_without_touching_the_chain() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    // Base mainnet, while the endpoint below reports Base Sepolia.
    seed(&ledger, '5', LIVE, Network::Base).await;

    let fake = FakeChain::spawn(FakeConfig::base_sepolia()).await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 0,
            skipped: 1
        },
        "a claim for another chain is skipped, never counted as a failure of this worker"
    );
    assert_eq!(
        fake.calls(),
        Vec::<String>::new(),
        "a claim for another chain must be filtered out before any RPC call"
    );
    assert!(
        is_still_owed(&ledger, '5').await,
        "a skipped claim stays owed — it is simply not ours to settle"
    );
}

/// Branch 10: a log the endpoint returned for the WRONG nonce proves nothing, however
/// genuine the payment behind it.
///
/// The `eth_getLogs` filter pins the asset, the payer and the nonce server-side, so an
/// honest endpoint cannot answer with anything else. A buggy, compromised or
/// intercepted one can — and the log it hands back may be a completely real payment
/// for a DIFFERENT nonce, whose transaction contains a transfer of exactly this
/// claim's value to exactly this claim's payee. Every downstream check then passes and
/// a second claim is booked off one payment, permanently: with no settlement
/// transaction recorded in the ledger, nothing afterwards can tell the two apart.
///
/// The endpoint is the money oracle and it has no other anchor, so what it returns is
/// re-checked against the filter it was given rather than trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_log_returned_for_another_nonce_never_settles_this_claim() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, 'b', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        authorization_used: true,
        // A genuine, correct, fully-paying redemption — of somebody else's nonce.
        redeemed: &[Redeemed {
            nonce_suffix: 'c',
            to: PAYEE,
            value: VALUE,
        }],
        // ...which the endpoint hands back for every query, including this claim's.
        logs_ignore_the_filter: true,
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 1,
            skipped: 0
        },
        "a log for another nonce is not this claim's payment, whatever the endpoint says"
    );
    assert!(
        is_still_owed(&ledger, 'b').await,
        "the claim was never paid, so the row must stay owed rather than book a second \
         claim off one payment"
    );

    // An endpoint that ignores the filter is an INFRASTRUCTURE fault, and the payer had
    // no part in it. Reporting it as a reused nonce would be the same false, permanent
    // accusation the emission-order branch exists to avoid — so this must read like an
    // untraceable log: a WARN the next sweep re-asks, never a verdict.
    let nonce = format!("0x{}", "b".repeat(64));
    assert!(
        !logged()
            .lines()
            .any(|line| line.contains(&nonce) && line.contains("signed two authorizations")),
        "an endpoint that answered with someone else's log must never be reported as the \
         payer having reused a nonce"
    );
    assert!(
        logged()
            .lines()
            .any(|line| line.contains("WARN") && line.contains(&nonce)),
        "the provider fault must still be visible to an operator, as a degraded read"
    );
}

/// Branch 11: an `AuthorizationUsed` with NO log after it inside its own transaction is
/// INCONCLUSIVE and blames the token, not the payer.
///
/// The pairing rests on Circle's `FiatTokenV2` marking the nonce used and THEN
/// transferring. The proxy behind that address is upgradeable, and a `FiatTokenV3` that
/// restored EIP-3009's reference order would leave every genuine redemption's event as
/// its transaction's last log. Money stays safe — the rows stay owed — but if that read
/// as "the payer signed two authorizations under one nonce", 100% of collected revenue
/// would silently stop being recorded while every honest payer was accused at ERROR in
/// the operator's audit trail.
///
/// So "no successor at all" is a fact about the TOKEN and is reported the way an
/// untraceable log is: a WARN, still owed, nobody accused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_with_no_following_log_blames_the_token_not_the_payer() {
    capture_logs();
    let (_container, ledger) = start_migrated_ledger().await;
    seed(&ledger, 'd', LIVE, Network::BaseSepolia).await;

    let fake = FakeChain::spawn(FakeConfig {
        authorization_used: true,
        // A redemption that paid this claim in full...
        redeemed: &[Redeemed {
            nonce_suffix: 'd',
            to: PAYEE,
            value: VALUE,
        }],
        // ...emitted in the order the settler does NOT pair on, so its event is the
        // transaction's last log.
        reference_emission_order: true,
        ..FakeConfig::base_sepolia()
    })
    .await;
    let client = connect_to(&fake).await;

    let report = settle_batch(&ledger, &client, NOW, &Shutdown::never()).await;

    assert_eq!(
        report,
        SweepReport {
            settled: 0,
            failed: 1,
            skipped: 0
        },
        "an event the settler cannot pair proves no payment: the claim must not be settled"
    );
    assert!(
        is_still_owed(&ledger, 'd').await,
        "the question is unanswered, so the row must stay owed"
    );

    let nonce = format!("0x{}", "d".repeat(64));
    assert!(
        !logged()
            .lines()
            .any(|line| line.contains(&nonce) && line.contains("signed two authorizations")),
        "a token that emits its events in another order must never be reported as the \
         payer having reused a nonce"
    );
    assert!(
        logged()
            .lines()
            .any(|line| line.contains("WARN") && line.contains(&nonce)),
        "the operator must still see it, as a degraded read rather than a verdict"
    );
}

/// Records one claim and asserts it really landed, so a test can never pass because
/// its fixture was silently missing.
async fn seed(ledger: &PgClaimLedger, nonce_suffix: char, valid_before: u64, network: Network) {
    assert!(
        ledger
            .record(&claim(nonce_suffix, valid_before, network))
            .await
            .expect("seed a claim"),
        "the fixture claim must insert"
    );
}
