//! M5a — `PgClaimLedger` against a REAL Postgres, in a throwaway container.
//!
//! The ledger is pure I/O: every guarantee it makes belongs to the database, not
//! to Rust, so there is nothing meaningful to unit-test in isolation. Each test
//! below states one of those guarantees — that the schema applies and re-applies,
//! that a claim survives the round trip byte-for-byte (including a uint256 that
//! overflows BIGINT), that the primary key makes a duplicate a no-op, that the
//! work queue holds only claims that are still owed AND still redeemable and is
//! ordered NUMERICALLY, that settling a claim is idempotent, and that a dead
//! backend fails closed.
//!
//! ## Container strategy: one per test (not shared)
//! Same reasoning as `redis_nonce_store.rs`: `ContainerAsync`'s Drop hands cleanup
//! back to the runtime that started it and each `#[tokio::test]` gets its own, so a
//! shared `static` container would be dropped by a foreign runtime. The fail-closed
//! test additionally *stops* its container, which would poison a shared instance.
//! Per-test containers also give every test a virgin schema, so no test can see
//! another's rows.
//!
//! ## Runtime / environment
//! These tests need a container runtime reachable via `DOCKER_HOST` (Docker or a
//! rootless Podman socket).

use std::time::Duration;

use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;

use tollgate_ledger::{Claim, PgClaimLedger};

/// Postgres' port INSIDE the container; the module's image publishes it on an
/// ephemeral host port, and its default database/user/password are all `postgres`.
const PG_PORT: u16 = 5432;

/// A `min_valid_before` below every fixture's `valid_before`, so `settleable`'s
/// expiry filter admits every seeded row and a test observes only the dimension it
/// is actually about.
const NO_CUTOFF: u64 = 0;

const PAYER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PAYEE: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ASSET: &str = "0xcccccccccccccccccccccccccccccccccccccccc";

/// Starts a fresh Postgres container and returns the handle plus its connection
/// URL. The handle MUST be kept alive for the test's duration — dropping it stops
/// and removes the container.
async fn start_postgres() -> (ContainerAsync<Postgres>, String) {
    let container = Postgres::default()
        .start()
        .await
        .expect("start postgres container (is DOCKER_HOST / a container runtime available?)");
    let host = container.get_host().await.expect("resolve container host");
    // 5432 inside the container is published on an ephemeral host port.
    let port = container
        .get_host_port_ipv4(PG_PORT)
        .await
        .expect("resolve mapped postgres port");
    (
        container,
        format!("postgres://postgres:postgres@{host}:{port}/postgres"),
    )
}

/// Starts a container and returns a ledger with the schema already applied.
async fn start_migrated_ledger() -> (ContainerAsync<Postgres>, PgClaimLedger) {
    let (container, url) = start_postgres().await;
    let ledger = PgClaimLedger::connect(&url)
        .await
        .expect("connect to postgres");
    ledger.migrate().await.expect("apply migrations");
    (container, ledger)
}

/// A claim distinguished only by its nonce suffix and `valid_before`, so tests can
/// seed several rows that differ in exactly the dimension under test.
fn claim(nonce_suffix: char, valid_before: &str) -> Claim {
    Claim {
        payer: PAYER.parse().expect("valid payer fixture"),
        nonce: format!("0x{}", String::from(nonce_suffix).repeat(64))
            .parse()
            .expect("valid nonce fixture"),
        payee: PAYEE.parse().expect("valid payee fixture"),
        value: "10000".parse().expect("valid value fixture"),
        valid_after: "0".parse().expect("valid validAfter fixture"),
        valid_before: valid_before.parse().expect("valid validBefore fixture"),
        signature: "0xdeadbeef".to_owned(),
        asset: ASSET.parse().expect("valid asset fixture"),
        network: tollgate_core::x402::Network::BaseSepolia,
    }
}

/// Guarantee 1: the migration creates the schema on a virgin database and is safe
/// to re-run — every process start calls it, so a second call must be a no-op
/// rather than a "relation already exists" failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migrate_creates_schema_and_is_rerunnable() {
    let (_container, url) = start_postgres().await;
    let ledger = PgClaimLedger::connect(&url)
        .await
        .expect("connect to postgres");

    ledger
        .migrate()
        .await
        .expect("first migrate on a virgin db");
    ledger
        .migrate()
        .await
        .expect("re-running migrate is a no-op");

    // The table really exists and is usable — the only way to observe that through
    // the public API.
    assert!(
        ledger
            .record(&claim('1', "1700000000"))
            .await
            .expect("insert into the migrated schema"),
        "a fresh claim must insert into the migrated schema"
    );
}

/// Guarantee 2: a recorded claim reads back with EVERY field byte-identical.
///
/// These bytes are replayed on-chain later, so a lossy column (a truncated
/// signature, a re-cased address, a value squeezed through a Rust integer) yields a
/// claim that cannot be redeemed. The 78-digit `value` is the widest a `UintStr`
/// admits — the boundary where a numeric column would start losing digits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn record_then_settleable_round_trips_every_field() {
    let (_container, ledger) = start_migrated_ledger().await;

    let max_value = "9".repeat(78);
    let signature = format!("0x{}1b", "ab".repeat(64));
    let mut original = claim('1', "1893456000");
    original.value = max_value.parse().expect("78-digit value fixture");
    original.signature.clone_from(&signature);

    assert!(ledger.record(&original).await.expect("record the claim"));

    let owed = ledger
        .settleable(NO_CUTOFF, 10)
        .await
        .expect("read settleable claims");
    assert_eq!(owed.len(), 1, "exactly the one recorded claim is owed");
    let read = &owed[0];
    assert_eq!(read.payer.as_str(), original.payer.as_str());
    assert_eq!(read.nonce.as_str(), original.nonce.as_str());
    assert_eq!(read.payee.as_str(), original.payee.as_str());
    assert_eq!(read.value.as_str(), max_value);
    assert_eq!(read.valid_after.as_str(), "0");
    assert_eq!(read.valid_before.as_str(), "1893456000");
    assert_eq!(read.signature, signature);
    assert_eq!(read.asset.as_str(), original.asset.as_str());
    assert_eq!(read.network, original.network);
}

/// Guarantee 3: a `valid_before` of 2^200 survives exactly.
///
/// This is the counter-case that justifies `NUMERIC(78,0)`: `validBefore` is a
/// uint256 on the wire, so a perfectly valid authorization can name a deadline that
/// overflows BIGINT. A BIGINT column would reject or wrap this row.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn valid_before_beyond_bigint_round_trips_exactly() {
    let (_container, ledger) = start_migrated_ledger().await;

    // 2^200, written out: ~61 digits, far beyond BIGINT's 19.
    let huge = "1606938044258990275541962092341162602522202993782792835301376";
    assert!(ledger
        .record(&claim('1', huge))
        .await
        .expect("record a uint256 validBefore"));

    let owed = ledger
        .settleable(NO_CUTOFF, 10)
        .await
        .expect("read settleable claims");
    assert_eq!(owed.len(), 1);
    assert_eq!(
        owed[0].valid_before.as_str(),
        huge,
        "a uint256 validBefore must survive the round trip digit-for-digit"
    );
}

/// Guarantee 4: `(payer, nonce)` is the replay identity — recording the same claim
/// twice inserts once.
///
/// The gate's nonce store already rejects a replay, but its keys EXPIRE while a
/// ledger row is forever; the primary key is the second, durable line of defence
/// against the same authorization being owed (and settled) twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_payer_nonce_records_once() {
    let (_container, ledger) = start_migrated_ledger().await;

    let first = claim('1', "1700000000");
    // Same (payer, nonce), different everything else: the key alone decides.
    let mut again = claim('1', "1800000000");
    again.value = "99999".parse().expect("valid value fixture");

    assert!(
        ledger.record(&first).await.expect("first record"),
        "the first sighting must insert (Ok(true))"
    );
    assert!(
        !ledger.record(&again).await.expect("duplicate record"),
        "a duplicate (payer, nonce) must be a no-op (Ok(false))"
    );

    let owed = ledger
        .settleable(NO_CUTOFF, 10)
        .await
        .expect("read settleable claims");
    assert_eq!(owed.len(), 1, "the duplicate must not add a second row");
    assert_eq!(
        owed[0].valid_before.as_str(),
        "1700000000",
        "the duplicate must not overwrite the original row either"
    );
}

/// Guarantee 5: the work queue is ordered NUMERICALLY by `valid_before`, not
/// lexicographically.
///
/// `valid_before` is a settlement deadline, so "soonest-expiring first" has to mean
/// the smallest NUMBER. The seed values are chosen so the two orderings disagree:
/// as text, "10" sorts before "9". A text column — or a text projection captured by
/// a bare `ORDER BY` — would hand the settler its work in the wrong order and let
/// the soonest-expiring claim lapse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settleable_orders_numerically_not_lexicographically() {
    let (_container, ledger) = start_migrated_ledger().await;

    // Recorded in an order that matches neither expectation, so the assertion can
    // only pass because of the ORDER BY.
    for (suffix, valid_before) in [('1', "10"), ('2', "9"), ('3', "100")] {
        assert!(ledger
            .record(&claim(suffix, valid_before))
            .await
            .expect("seed a claim"));
    }

    let owed = ledger
        .settleable(NO_CUTOFF, 10)
        .await
        .expect("read settleable claims");
    let order: Vec<&str> = owed.iter().map(|c| c.valid_before.as_str()).collect();
    assert_eq!(
        order,
        ["9", "10", "100"],
        "claims must come back soonest-expiring first by NUMBER (lexicographic \
         order would be 10, 100, 9)"
    );
}

/// Guarantee 6: a claim whose authorization has EXPIRED is not settleable.
///
/// An EIP-3009 authorization past its `validBefore` reverts on-chain forever, so an
/// expired row is not work — it is a permanent failure. Worse, it sorts FIRST under
/// the soonest-expiring-first ordering, so without this filter a handful of expired
/// claims would fill every batch and starve the live ones out. The boundary is
/// strict (`>`): a claim expiring exactly AT the cutoff is already dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settleable_excludes_claims_that_have_expired() {
    let (_container, ledger) = start_migrated_ledger().await;

    for (suffix, valid_before) in [
        ('1', "1699999999"),
        ('2', "1700000000"),
        ('3', "1700000001"),
    ] {
        assert!(ledger
            .record(&claim(suffix, valid_before))
            .await
            .expect("seed a claim"));
    }

    let owed = ledger
        .settleable(1_700_000_000, 10)
        .await
        .expect("read settleable claims");
    let live: Vec<&str> = owed.iter().map(|c| c.valid_before.as_str()).collect();
    assert_eq!(
        live,
        ["1700000001"],
        "only a claim expiring strictly AFTER the cutoff is still redeemable"
    );
}

/// Guarantee 7: the surviving claims are still ordered by NUMBER once the expiry
/// filter is applied.
///
/// Guarantee 5 pins the ordering on small seeds; this one pins it on realistic
/// unix timestamps above a real cutoff, where the lexicographic trap is the other
/// way round: as text "2000000000" sorts BEFORE "999999999" (a `2` beats a `9` on
/// the first character), so a bare `ORDER BY valid_before` — which binds to the
/// `::TEXT` projection — would hand the settler the claim with 30 more years of life
/// ahead of one expiring in weeks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn settleable_orders_live_claims_numerically_under_a_real_cutoff() {
    let (_container, ledger) = start_migrated_ledger().await;

    for (suffix, valid_before) in [('1', "2000000000"), ('2', "999999999"), ('3', "1700000000")] {
        assert!(ledger
            .record(&claim(suffix, valid_before))
            .await
            .expect("seed a claim"));
    }

    let owed = ledger
        .settleable(999_999_998, 10)
        .await
        .expect("read settleable claims");
    let order: Vec<&str> = owed.iter().map(|c| c.valid_before.as_str()).collect();
    assert_eq!(
        order,
        ["999999999", "1700000000", "2000000000"],
        "live claims must come back soonest-expiring first by NUMBER \
         (lexicographic order would be 1700000000, 2000000000, 999999999)"
    );
}

/// Guarantee 8: settling a claim is idempotent — the FIRST call owns the row.
///
/// `mark_settled` reports whether THIS call performed the transition, and that
/// boolean is the settler's only interlock: two workers (or one worker retrying
/// after a lost response) may both reach a claim, and exactly one may be told it
/// won. A second `true` would licence a second on-chain redemption attempt and
/// would overwrite the timestamp that records when the money actually arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mark_settled_transitions_a_claim_exactly_once() {
    let (_container, ledger) = start_migrated_ledger().await;

    let owed = claim('1', "1700000000");
    assert!(ledger.record(&owed).await.expect("record the claim"));

    assert!(
        ledger
            .mark_settled(&owed.payer, &owed.nonce)
            .await
            .expect("first settle"),
        "the first call must report that IT settled the claim"
    );
    assert!(
        !ledger
            .mark_settled(&owed.payer, &owed.nonce)
            .await
            .expect("repeated settle"),
        "a repeated (or concurrent) call must be a no-op, not a second win"
    );
}

/// Guarantee 9: a settled claim leaves the work queue.
///
/// `settled_at` is the whole status field, so this is the only observable proof
/// that `mark_settled` wrote the column the `settleable` predicate reads. A claim
/// that stayed in the queue after settlement would be redeemed again on the next
/// batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_settled_claim_is_no_longer_settleable() {
    let (_container, ledger) = start_migrated_ledger().await;

    let settled = claim('1', "1700000000");
    let still_owed = claim('2', "1700000000");
    assert!(ledger.record(&settled).await.expect("record the claim"));
    assert!(ledger
        .record(&still_owed)
        .await
        .expect("record the second claim"));

    assert!(ledger
        .mark_settled(&settled.payer, &settled.nonce)
        .await
        .expect("settle the first claim"));

    let owed = ledger
        .settleable(NO_CUTOFF, 10)
        .await
        .expect("read settleable claims");
    let nonces: Vec<&str> = owed.iter().map(|c| c.nonce.as_str()).collect();
    assert_eq!(
        nonces,
        [still_owed.nonce.as_str()],
        "a settled claim must drop out of the queue, and only that one"
    );
}

/// Guarantee 10: an unreachable backend fails CLOSED.
///
/// We connect to a live container, confirm a write lands, then STOP the container
/// out from under the ledger — the faithful model of a production outage — and
/// assert the next call yields `Err`. A ledger that cannot reach its database must
/// never fabricate an `Ok`: an `Ok(false)` would be read as "already recorded" and
/// an `Ok(true)` as "safely persisted", and both silently forgive lost money.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_backend_fails_closed() {
    let (container, ledger) = start_migrated_ledger().await;

    assert!(
        ledger
            .record(&claim('1', "1700000000"))
            .await
            .expect("record works while postgres is up"),
        "sanity: the ledger must work before we kill the backend"
    );

    container.stop().await.expect("stop the postgres container");

    // Budgeted above sqlx's default 30s pool acquire timeout: a dead backend must
    // surface as an error rather than hang forever, and the timeout turns a
    // hypothetical hang into a loud test failure instead of a stalled suite.
    let outcome = tokio::time::timeout(
        Duration::from_mins(1),
        ledger.record(&claim('2', "1700000000")),
    )
    .await
    .expect("record must return after the backend dies, not hang");

    assert!(
        outcome.is_err(),
        "a write against a dead backend must fail CLOSED (Err), never a bogus Ok"
    );
}
