//! The sweep loop: the settler's policy layer.
//!
//! [`chain`](crate::chain) knows how to redeem ONE claim and
//! [`PgClaimLedger`] knows what is still owed; this module is the only place that
//! decides which claim is attempted, in what order, and what a given on-chain
//! answer means for the ledger row behind it.
//!
//! Two properties are load-bearing and neither is an accident:
//!
//! * **Sequential.** One claim is redeemed and its receipt awaited before the next
//!   one starts. That is what makes alloy's nonce filler correct with no nonce
//!   bookkeeping of our own — a parallel loop would hand two transactions the same
//!   nonce and drop one of them on the floor.
//! * **No claim aborts the batch.** Every outcome below is recorded and the loop
//!   moves on, because one payer's unredeemable authorization must never stop the
//!   operator from collecting the rest.
//!
//! There is no lease, lock or "in flight" column anywhere. EIP-3009 makes the
//! on-chain nonce itself the mutex: a second attempt at an already-redeemed
//! authorization simply reverts, and [`SettlementClient::is_authorization_used`]
//! turns that revert into a free read BEFORE any gas is spent.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tollgate_core::x402;
use tollgate_ledger::{Claim, PgClaimLedger};

use crate::chain::{Redemption, SettleError, SettlementClient};
use crate::config::SettlerConfig;

/// How long the worker idles between sweeps. Claims live for minutes at least, so
/// a minute of latency costs nothing and keeps the RPC bill and the log volume of
/// an idle deployment near zero.
const POLL_INTERVAL: Duration = Duration::from_mins(1);

/// How many claims one sweep may pull. Bounds the memory of a single read and the
/// backlog one pass will chew through, soonest-expiring first; a larger backlog is
/// simply drained over several sweeps.
///
/// It does NOT bound how long a sweep takes. Claims are settled sequentially and
/// each may wait a full `RECEIPT_TIMEOUT` for its receipt, so the worst case is
/// `BATCH_LIMIT` × that timeout — hours, not minutes. Two consequences are handled
/// explicitly rather than assumed away: every claim's expiry is re-checked against
/// the elapsed clock immediately before it is redeemed, and [`Shutdown`] is observed
/// between claims so a container's grace period does not expire mid-sweep.
const BATCH_LIMIT: u32 = 50;

/// Seconds of headroom a claim must still have before its `validBefore` to be worth
/// attempting.
///
/// Redeeming is not instantaneous — the transaction has to be signed, broadcast and
/// MINED — and an authorization that expires while the transaction sits in the
/// mempool reverts, burning gas for nothing. Claims inside this window are left for
/// no one: they are already lost, and the only choice is whether to pay to discover
/// that.
const MIN_LEAD: u64 = 30;

/// What one sweep did, counted per claim.
///
/// Returned rather than logged-and-forgotten so a test can drive [`settle_batch`]
/// directly and assert on outcomes. There is deliberately no `scanned` field: it
/// would always equal `settled + failed + skipped`, and a derived counter is one
/// more thing that can disagree with itself.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Claims whose ledger row is now marked settled — whether this sweep redeemed
    /// them or discovered a previous one already had.
    pub settled: usize,
    /// Claims still owed after this sweep. Two kinds share the bucket because the
    /// ledger consequence is identical — the row stays owed and is re-examined next
    /// pass: the retryable (a revert, an RPC fault, a lost receipt) and the
    /// unpayable (the payer cancelled, or spent the nonce on a transfer that was not
    /// this claim's), which simply age out at their `validBefore`. The log lines tell
    /// them apart; the count deliberately does not.
    pub failed: usize,
    /// Claims this worker did not attempt: they belong to another chain, or they
    /// ran out of usable validity while the sweep ahead of them was in flight.
    /// Never attempted, so they are not failures of this worker.
    pub skipped: usize,
}

/// A cooperative stop flag, read by a sweep BETWEEN claims.
///
/// A flag rather than a future threaded into the per-claim path, because a claim
/// that has been broadcast MUST run to its `mark_settled` — cutting one short is
/// precisely how a paid claim ends up recorded as owed. Checking at claim
/// boundaries bounds shutdown latency to ONE claim (at worst the receipt timeout)
/// instead of a whole `BATCH_LIMIT`-long sweep, which is what makes SIGTERM
/// handling worth anything inside a container grace period.
///
/// Built on `watch` rather than an `AtomicBool` because [`run`] needs both halves
/// of the same signal: a non-blocking read between claims, and something it can
/// `select!` on to cut its poll interval short.
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// A signal that never fires.
    ///
    /// For every caller that drives ONE sweep and returns — the tests, and any
    /// future one-shot invocation. The sender is dropped immediately, so
    /// [`Shutdown::requested`] stays `false` and [`Shutdown::wait`] never resolves.
    #[must_use]
    pub fn never() -> Self {
        Self(watch::channel(false).1)
    }

    /// Whether shutdown has been requested. Never blocks: it is called once per
    /// claim and must not become part of the sweep's cost.
    #[must_use]
    pub fn requested(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves once shutdown has been requested — immediately if it already has.
    ///
    /// The `borrow` check is load-bearing: `changed()` only reports values sent
    /// AFTER it is awaited, so a flag set while a sweep was running would otherwise
    /// leave the worker sleeping through its own shutdown.
    async fn wait(&mut self) {
        while !*self.0.borrow() {
            if self.0.changed().await.is_err() {
                // No sender left and the flag was never set: nothing can ever
                // request shutdown, so this future must not resolve. Only
                // [`Shutdown::never`] reaches here — `run`'s watcher always sends.
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Runs ONE sweep and reports what happened.
///
/// Deliberately free of timers and signals: `now_unix` is a parameter and the
/// function returns as soon as the batch is drained, so a test can call it directly
/// with a fixed clock instead of racing [`run`]'s interval.
///
/// A ledger read that fails is logged and yields an EMPTY sweep rather than an
/// error: the caller's only sane response would be to try again next minute, which
/// is what returning does.
///
/// `shutdown` is consulted between claims — see [`Shutdown`]. A caller that wants
/// one uninterruptible sweep passes [`Shutdown::never`].
pub async fn settle_batch(
    ledger: &PgClaimLedger,
    client: &SettlementClient,
    now_unix: u64,
    shutdown: &Shutdown,
) -> SweepReport {
    // Saturating because `now_unix` comes from a system clock: a nonsense reading
    // near `u64::MAX` must hand out no work, never wrap into a cutoff of zero that
    // would admit every expired claim in the table.
    let cutoff = now_unix.saturating_add(MIN_LEAD);
    let batch = match ledger.settleable(cutoff, BATCH_LIMIT).await {
        Ok(claims) => claims,
        Err(err) => {
            tracing::error!(error = %err, "claims ledger read failed; sweeping nothing");
            Vec::new()
        }
    };

    let mut report = SweepReport::default();
    // The cutoff above was computed once, before a sweep that may run for hours.
    // Measuring from here lets each claim be judged against the clock as it is when
    // its turn comes, without reaching for the system clock again — which would make
    // the `now_unix` parameter (and every test's fixed clock) a lie.
    let started = Instant::now();
    // Sequential BY CONTRACT, not by convenience: see this module's header. Each
    // `settle_one` awaits its receipt before the next claim is signed.
    for claim in &batch {
        // Between claims only. A claim already on the wire owns the loop until its
        // ledger row is written; see [`Shutdown`].
        if shutdown.requested() {
            tracing::info!("shutdown requested; ending this sweep between claims");
            break;
        }

        let now = now_unix.saturating_add(started.elapsed().as_secs());
        if !is_worth_attempting(claim, now) {
            // The claim was admitted by the query and then aged out while the claims
            // ahead of it were settled. Redeeming now would revert on `validBefore`,
            // so it is left for the next sweep's query to drop.
            tracing::warn!(
                nonce = claim.nonce.as_str(),
                "claim ran out of validity during the sweep; not attempted"
            );
            report.skipped += 1;
            continue;
        }

        match settle_one(ledger, client, claim).await {
            Outcome::Settled => report.settled += 1,
            Outcome::Failed => report.failed += 1,
            Outcome::Skipped => report.skipped += 1,
        }
    }

    // Exactly one line per sweep, always emitted — including for an empty batch.
    // This is the worker's liveness signal: an operator watching for it can tell a
    // healthy idle settler from a wedged one, which no per-claim log can show.
    tracing::info!(
        settled = report.settled,
        failed = report.failed,
        skipped = report.skipped,
        "settlement sweep complete"
    );
    report
}

/// Connects the ledger and the chain, then sweeps every [`POLL_INTERVAL`] until a
/// shutdown signal arrives.
///
/// # Errors
/// Returns an error if the ledger cannot be reached, its migrations cannot be
/// applied, or the RPC endpoint is unreachable or on an unsupported chain. Those
/// are startup faults: like the gateway, the worker refuses to run half-wired
/// rather than discovering it on the first claim.
pub async fn run(cfg: SettlerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let ledger = PgClaimLedger::connect(&cfg.database_url).await?;
    ledger.migrate().await?;

    // The signer's address is read out BEFORE the signer is moved into the client:
    // it is the account that pays the gas, so an operator needs it in the logs to
    // fund it. It is a public key, unlike everything else in `cfg`.
    let settler_address = cfg.signer.address();
    let client = SettlementClient::connect(&cfg.rpc_url, cfg.signer).await?;
    tracing::info!(
        chain_id = client.chain_id(),
        settler = %settler_address,
        "settlement worker started"
    );

    // The signal is watched by its OWN task, not polled by this loop: a future
    // polled only between sweeps cannot notice a SIGTERM that arrives during one,
    // and a sweep may run for hours (see [`BATCH_LIMIT`]). The task flips a flag the
    // sweep reads between claims, which is what bounds shutdown to one claim.
    let (requested, mut shutdown) = shutdown_watch();
    tokio::spawn(async move {
        if let Err(err) = shutdown_signal().await {
            tracing::error!(error = %err, "failed to install a shutdown signal handler");
        }
        // Sent even when the handler could not be installed: a worker that cannot
        // hear a signal must stop, not become unstoppable.
        let _ = requested.send(true);
    });

    loop {
        settle_batch(&ledger, &client, now_unix(), &shutdown).await;

        // Between sweeps the loop can afford to wait on the flag directly, so a
        // shutdown never costs a full poll interval of latency.
        tokio::select! {
            () = tokio::time::sleep(POLL_INTERVAL) => {}
            () = shutdown.wait() => break,
        }
    }

    tracing::info!("settlement worker shutting down");
    Ok(())
}

/// What one claim's attempt did to its ledger row. Private: callers see only the
/// counts in [`SweepReport`].
enum Outcome {
    /// The row is now marked settled.
    Settled,
    /// The row is still owed and will be retried.
    Failed,
    /// The row was never attempted and is not this worker's to settle.
    Skipped,
}

/// Settles one claim, mapping every on-chain answer onto its ledger consequence.
///
/// Nothing here logs a signature, a payer, a value or an endpoint — only the nonce,
/// the transaction hash and the chain id, which are the three things already public
/// on-chain and the only three an operator needs to correlate a row with a block
/// explorer (ADR-0020/0034).
async fn settle_one(ledger: &PgClaimLedger, client: &SettlementClient, claim: &Claim) -> Outcome {
    let connected = client.chain_id();
    if x402::chain_id(&claim.network) != Some(connected) {
        // A pre-filter, not a duplicate of the client's own guard: it keeps a claim
        // minted for another chain out of the FAILED count (it is not a failure —
        // another deployment settles it) and off the RPC entirely.
        tracing::error!(
            nonce = claim.nonce.as_str(),
            chain_id = connected,
            "claim belongs to another chain; skipping"
        );
        return Outcome::Skipped;
    }

    // The pre-flight is not an optimisation and must not be elided. A crash between
    // broadcasting a redemption and writing `settled_at` — or a receipt that times
    // out — leaves a claim that WAS paid still marked owed; without this read the
    // worker would resubmit it every minute until expiry, paying revert gas each
    // time.
    match client.is_authorization_used(claim).await {
        // `true` means "redeeming would revert", NOT "we were paid": EIP-3009's
        // `cancelAuthorization` sets the same bit. Marking settled on this flag alone
        // would let a payer be served and then take the money back for ~50k gas,
        // while the operator's ledger recorded revenue that never arrived. Only the
        // `AuthorizationUsed` event AND the transfer inside the transaction that
        // emitted it separate the two.
        Ok(true) => confirm_redeemed(ledger, client, claim).await,
        Ok(false) => match client.redeem(claim).await {
            Ok(tx_hash) => {
                tracing::info!(
                    nonce = claim.nonce.as_str(),
                    tx_hash,
                    "claim settled on-chain"
                );
                mark_settled(ledger, claim).await
            }
            // Mined and reverted: terminal for this attempt, and the gas is spent.
            // `error!` rather than `warn!` because unlike an RPC blip this will
            // happen again identically on the next sweep until something changes.
            Err(SettleError::Reverted { tx_hash }) => {
                tracing::error!(
                    nonce = claim.nonce.as_str(),
                    tx_hash,
                    "settlement transaction reverted; claim still owed"
                );
                Outcome::Failed
            }
            // Everything else — a refused broadcast, a receipt that never arrived —
            // is UNKNOWN, not failed: the transaction may well be mined already.
            // Leaving the row owed is safe precisely because the next sweep's
            // pre-flight resolves it; re-redeeming here would not.
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    nonce = claim.nonce.as_str(),
                    "settlement attempt did not complete; claim still owed"
                );
                Outcome::Failed
            }
        },
        Err(err) => {
            tracing::warn!(
                error = %err,
                nonce = claim.nonce.as_str(),
                "could not read authorization state; claim still owed"
            );
            Outcome::Failed
        }
    }
}

/// Decides what a spent `authorizationState` bit actually meant, and acts on it.
///
/// Reached only when the pre-flight said the authorization can no longer be
/// redeemed. [`Redemption::Confirmed`] means the money really moved — through an
/// earlier sweep, or a crashed one whose receipt was never written — so the row is
/// reconciled without spending gas. The other two variants mean nothing was ever paid
/// to us, and the row stays owed.
///
/// An authorization that can never pay is re-examined (a few cheap reads, no gas) on
/// every sweep until its `validBefore` passes and the ledger query stops returning it.
/// That is deliberate for M5b: a terminal "unpayable" state means a new column, and
/// this milestone ships no schema change.
///
/// All three negative outcomes are logged DIFFERENTLY on purpose. A cancellation and a
/// reused nonce are permanent facts about one payer that an operator may want to act
/// on — and they are different facts; a failed query is a transient fact about the RPC.
/// Collapsing them into one line would make "a payer is walking on our invoices"
/// indistinguishable from "the endpoint is flaky".
async fn confirm_redeemed(
    ledger: &PgClaimLedger,
    client: &SettlementClient,
    claim: &Claim,
) -> Outcome {
    match client.redemption_status(claim).await {
        Ok(Redemption::Confirmed) => {
            tracing::info!(
                nonce = claim.nonce.as_str(),
                "authorization already redeemed on-chain; recording settlement"
            );
            mark_settled(ledger, claim).await
        }
        Ok(Redemption::Cancelled) => {
            tracing::error!(
                nonce = claim.nonce.as_str(),
                "authorization was CANCELLED by the payer; nothing was ever paid and \
                 this claim can never be settled"
            );
            Outcome::Failed
        }
        Ok(Redemption::OtherAuthorization) => {
            tracing::error!(
                nonce = claim.nonce.as_str(),
                "the nonce was spent by a transfer that did not pay this claim; the payer \
                 signed two authorizations under one nonce and this one can never be settled"
            );
            Outcome::Failed
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                nonce = claim.nonce.as_str(),
                "could not confirm whether the authorization was redeemed, cancelled or \
                 spent elsewhere; claim still owed"
            );
            Outcome::Failed
        }
    }
}

/// Records the settlement in the ledger.
///
/// `Ok(false)` — the row was already settled by a concurrent worker — is still a
/// settled claim from this sweep's point of view; the interlock lives in the SQL.
/// A ledger write that fails counts as failed, which is literally true: the money
/// moved but the row is still owed, so the next sweep's pre-flight finds the
/// authorization spent, [`confirm_redeemed`] finds its `AuthorizationUsed` log, and
/// the row is marked without spending gas again.
async fn mark_settled(ledger: &PgClaimLedger, claim: &Claim) -> Outcome {
    match ledger.mark_settled(&claim.payer, &claim.nonce).await {
        Ok(_) => Outcome::Settled,
        Err(err) => {
            tracing::warn!(
                error = %err,
                nonce = claim.nonce.as_str(),
                "settled on-chain but the ledger write failed; claim still marked owed"
            );
            Outcome::Failed
        }
    }
}

/// Whether `claim` still has enough life left, as of `now`, to be worth redeeming.
///
/// The same [`MIN_LEAD`] test the ledger query applies, re-asked per claim because
/// the query's cutoff was computed once for a sweep that can outlive it. Today this
/// only saves a wasted `eth_estimateGas` round-trip — estimation catches the expiry
/// before anything is broadcast — but it makes the invariant true rather than
/// approximately true, and it costs one comparison.
///
/// A `validBefore` too large for a `u64` saturates to "never expires", which is what
/// the value literally means and is safe: the contract, not this check, is the thing
/// that ultimately enforces the deadline.
fn is_worth_attempting(claim: &Claim, now: u64) -> bool {
    let valid_before = claim
        .valid_before
        .as_str()
        .parse::<u64>()
        .unwrap_or(u64::MAX);
    now.saturating_add(MIN_LEAD) < valid_before
}

/// Creates the shutdown flag and the handle that sets it.
///
/// Split out so [`Shutdown`]'s inner channel stays private to this module while
/// [`run`] can still hand the sender to its watcher task.
fn shutdown_watch() -> (watch::Sender<bool>, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (tx, Shutdown(rx))
}

/// Resolves on the first signal that means "stop".
///
/// SIGTERM as well as ctrl-c, because `docker stop` and Kubernetes send SIGTERM and
/// its default disposition kills the process outright — landing in exactly the
/// broadcast-before-`mark_settled` window graceful shutdown exists to protect.
///
/// # Errors
/// Returns an error if a handler cannot be installed, which the caller treats as a
/// reason to shut down rather than run unstoppable.
#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = signal(SignalKind::terminate())?;
    tokio::select! {
        res = tokio::signal::ctrl_c() => res,
        // `recv` yields `None` only once the handler is dropped, which cannot happen
        // while this future owns it, so either arm means "stop".
        _ = term.recv() => Ok(()),
    }
}

/// Ctrl-c only: there is no SIGTERM off unix. Kept so the crate still builds
/// everywhere, though the worker is only ever deployed on unix.
///
/// # Errors
/// Returns an error if the ctrl-c handler cannot be installed.
#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

/// Wall-clock unix seconds, for the expiry cutoff.
///
/// A clock before the epoch is not a reading a settler can act on, so it saturates
/// to 0 — which admits nothing that is not genuinely still redeemable, since the
/// ledger's own filter is the one that decides.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{is_worth_attempting, shutdown_watch, MIN_LEAD};

    use tollgate_core::x402::Network;
    use tollgate_ledger::Claim;

    /// A fixed "now" for the expiry arithmetic, so nothing here reads a clock.
    const NOW: u64 = 1_700_000_000;

    /// A claim that differs from every other only in when it expires — the single
    /// field [`is_worth_attempting`] looks at. `valid_before` is a string because the
    /// ledger column is a `uint256`: values too large for a `u64` are exactly the
    /// interesting case.
    fn claim(valid_before: &str) -> Claim {
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
            valid_before: valid_before.parse().expect("fixture valid_before"),
            signature: format!("0x{}{}1b", "11".repeat(32), "22".repeat(32)),
            asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
                .parse()
                .expect("fixture asset"),
            network: Network::BaseSepolia,
        }
    }

    #[test]
    fn a_shutdown_request_becomes_visible_without_waiting_for_it() {
        // The flag is read between claims, in the middle of a sweep that may run for
        // hours. If a request made while the sweep is running were invisible until
        // something awaited it, SIGTERM handling would do nothing inside a container's
        // grace period — the process would be killed mid-claim instead.
        let (requested, shutdown) = shutdown_watch();
        assert!(
            !shutdown.requested(),
            "a worker nobody has asked to stop must keep sweeping"
        );

        requested
            .send(true)
            .expect("the sweep still holds the flag");
        assert!(
            shutdown.requested(),
            "a request made during a sweep must be visible to the very next claim boundary"
        );
    }

    #[test]
    fn a_claim_is_worth_attempting_only_while_more_than_min_lead_is_left() {
        // The boundary is the whole content of this function: redeeming takes time to
        // sign, broadcast and MINE, so a claim without that much life left will expire
        // in the mempool and revert, burning gas to discover what this comparison knows
        // for free.
        assert!(
            is_worth_attempting(&claim(&(NOW + MIN_LEAD + 1).to_string()), NOW),
            "a claim with more than the lead time left is still worth gas"
        );
        assert!(
            !is_worth_attempting(&claim(&(NOW + MIN_LEAD).to_string()), NOW),
            "a claim with exactly the lead time left is already lost"
        );
        assert!(
            !is_worth_attempting(&claim(&NOW.to_string()), NOW),
            "a claim expiring now is not work"
        );

        // A sweep that has been running long enough re-asks this question with a LATER
        // `now`, which is the case the ledger's one-off query cannot cover.
        assert!(
            !is_worth_attempting(&claim(&(NOW + MIN_LEAD + 1).to_string()), NOW + 1),
            "a claim that aged out during the sweep must stop being attempted"
        );

        // A `validBefore` too large for a `u64` means "never expires", which is what
        // the value literally says; the contract is the thing that ultimately enforces
        // the deadline, so erring towards attempting is safe.
        assert!(
            is_worth_attempting(&claim(&"9".repeat(78)), NOW),
            "an unrepresentably distant deadline must not read as an expired one"
        );
    }
}
