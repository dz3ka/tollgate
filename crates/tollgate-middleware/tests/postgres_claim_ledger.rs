//! M5a — `PgClaimLedger` against a REAL Postgres, in a throwaway container.
//!
//! The ledger is pure I/O: every guarantee it makes belongs to the database, not
//! to Rust, so there is nothing meaningful to unit-test in isolation. Each test
//! below states one of those guarantees — that the schema applies and re-applies,
//! that a claim survives the round trip byte-for-byte (including a uint256 that
//! overflows BIGINT), that the primary key makes a duplicate a no-op, that the
//! work queue is ordered NUMERICALLY, and that a dead backend fails closed.
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

use tollgate_middleware::{Claim, PgClaimLedger};

/// Postgres' port INSIDE the container; the module's image publishes it on an
/// ephemeral host port, and its default database/user/password are all `postgres`.
const PG_PORT: u16 = 5432;

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
async fn record_then_unsettled_round_trips_every_field() {
    let (_container, ledger) = start_migrated_ledger().await;

    let max_value = "9".repeat(78);
    let signature = format!("0x{}1b", "ab".repeat(64));
    let mut original = claim('1', "1893456000");
    original.value = max_value.parse().expect("78-digit value fixture");
    original.signature.clone_from(&signature);

    assert!(ledger.record(&original).await.expect("record the claim"));

    let owed = ledger.unsettled(10).await.expect("read unsettled claims");
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

    let owed = ledger.unsettled(10).await.expect("read unsettled claims");
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

    let owed = ledger.unsettled(10).await.expect("read unsettled claims");
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
async fn unsettled_orders_numerically_not_lexicographically() {
    let (_container, ledger) = start_migrated_ledger().await;

    // Recorded in an order that matches neither expectation, so the assertion can
    // only pass because of the ORDER BY.
    for (suffix, valid_before) in [('1', "10"), ('2', "9"), ('3', "100")] {
        assert!(ledger
            .record(&claim(suffix, valid_before))
            .await
            .expect("seed a claim"));
    }

    let owed = ledger.unsettled(10).await.expect("read unsettled claims");
    let order: Vec<&str> = owed.iter().map(|c| c.valid_before.as_str()).collect();
    assert_eq!(
        order,
        ["9", "10", "100"],
        "claims must come back soonest-expiring first by NUMBER (lexicographic \
         order would be 10, 100, 9)"
    );
}

/// Guarantee 6: an unreachable backend fails CLOSED.
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
