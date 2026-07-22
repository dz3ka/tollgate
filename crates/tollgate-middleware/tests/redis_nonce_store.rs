//! WP4 — `RedisNonceStore` against a REAL Redis, in a throwaway container.
//!
//! The in-memory backend is unit-tested in `store.rs`; those tests can't prove the
//! guarantees that only a real server provides: that `SET NX` is atomic across
//! genuinely-parallel claimants, that `PX` actually expires the key, and that a
//! dead backend surfaces as `Err` (fail-CLOSED) rather than a bogus `Ok`. Each
//! test below is an executable statement of one of those guarantees.
//!
//! ## Container strategy: one per test (not shared)
//! `testcontainers`' `ContainerAsync` is bound to the tokio runtime that started
//! it (its Drop hands cleanup back to that runtime), and each `#[tokio::test]`
//! gets its OWN runtime — so a single container shared through a `static` would
//! be dropped by a foreign runtime. On top of that the fail-closed test must
//! *stop* its container, which would poison a shared instance for everyone. So we
//! pay for one lightweight Redis container per test. The redis image is pulled
//! once and reused; the marginal cost of an extra container is small. Each test
//! also uses a UNIQUE key, so even a shared server would not cross-contaminate.
//!
//! ## Runtime / environment
//! These tests need a container runtime reachable via `DOCKER_HOST` (Docker or a
//! rootless Podman socket). They are `multi_thread` where real parallelism is the
//! whole point (the atomicity proof), so the claims run on separate OS threads
//! rather than being cooperatively interleaved on one.

use std::time::{Duration, Instant};

use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::redis::{Redis, REDIS_PORT};

use tollgate_middleware::{NonceStore, RedisNonceStore};

/// Starts a fresh Redis container and returns the handle plus a `redis://host:port`
/// URL pointing at its mapped port. The handle MUST be kept alive for the duration
/// of the test — dropping it stops and removes the container.
async fn start_redis() -> (ContainerAsync<Redis>, String) {
    let container = Redis::default()
        .start()
        .await
        .expect("start redis container (is DOCKER_HOST / a container runtime available?)");
    let host = container.get_host().await.expect("resolve container host");
    // The internal 6379 is published on an ephemeral host port; we must ask for the
    // mapped port rather than assume 6379 is reachable from the test process.
    let port = container
        .get_host_port_ipv4(REDIS_PORT)
        .await
        .expect("resolve mapped redis port");
    (container, format!("redis://{host}:{port}"))
}

/// Guarantee 1: accept-then-replay against a real server.
///
/// A fresh key's first claim is new (`Ok(true)` = accept the payment); an
/// immediate re-claim of the SAME key is a replay (`Ok(false)` = reject). This is
/// the Redis analogue of `InMemoryNonceStore::record_if_new`'s core behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_claim_then_replay() {
    let (_container, url) = start_redis().await;
    let store = RedisNonceStore::connect(&url)
        .await
        .expect("connect to redis");

    // A generous TTL: this test is about accept-then-replay, not expiry, so the
    // nonce must stay remembered for the whole (immediate) re-claim.
    let ttl = Duration::from_mins(1);
    let key = "single_claim_then_replay-key";
    assert!(
        store
            .claim(key, ttl)
            .await
            .expect("first claim reaches redis"),
        "first claim of a fresh key must be accepted (Ok(true))"
    );
    assert!(
        !store
            .claim(key, ttl)
            .await
            .expect("second claim reaches redis"),
        "immediate re-claim of the same key must be a replay (Ok(false))"
    );
}

/// Guarantee 2: `SET NX` is atomic — exactly one winner under real parallelism.
///
/// We fire N genuinely-concurrent claims for the SAME key across a multi-thread
/// runtime. Redis serialises the N `SET key 1 NX` commands on the server, so
/// exactly one can find the key absent (`Ok(true)`) and every other must see it
/// present (`Ok(false)`); none may error. This is THE proof that the store admits
/// a single payment even when many requests race with the identical nonce.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_key_yields_exactly_one_winner() {
    const N: usize = 100;

    let (_container, url) = start_redis().await;
    let store = RedisNonceStore::connect(&url)
        .await
        .expect("connect to redis");

    let key = "concurrent_same_key-key";
    // Long enough that none of the N racing claims can expire mid-race.
    let ttl = Duration::from_mins(1);

    // Spawn N tasks, each with its own cheap clone of the store (they all share the
    // one multiplexed connection). `JoinSet` lets us await all outcomes without an
    // extra dev-dependency.
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..N {
        let store = store.clone();
        tasks.spawn(async move { store.claim(key, ttl).await });
    }

    let mut winners = 0usize;
    let mut replays = 0usize;
    while let Some(joined) = tasks.join_next().await {
        // A join error (task panic) or a claim `Err` both fail the test: the
        // atomicity contract permits only `Ok(true)`/`Ok(false)`.
        match joined.expect("claim task did not panic") {
            Ok(true) => winners += 1,
            Ok(false) => replays += 1,
            Err(e) => panic!("claim errored under concurrency (must not happen): {e}"),
        }
    }

    assert_eq!(winners, 1, "exactly one concurrent claim may win");
    assert_eq!(
        replays,
        N - 1,
        "every other concurrent claim must observe a replay"
    );
}

/// Guarantee 3: the `PX` TTL expires the key, making the nonce reclaimable.
///
/// With a short TTL, the first claim wins and subsequent claims are replays UNTIL
/// the key expires on the server, after which the key is gone and a claim wins
/// again. We prove this with a BOUNDED poll rather than a naked `sleep(ttl)`:
/// polling is robust to scheduling jitter and to the container clock, and it
/// asserts the *flip* rather than a single timing-sensitive sample.
///
/// Note: `SET NX` never writes to an existing key, so the failing polls below do
/// NOT refresh the TTL — the original `PX` deadline stands, and the key really does
/// lapse within the budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ttl_expiry_makes_key_reclaimable() {
    // The short TTL now rides on the individual `claim` calls (per-claim TTL), not
    // on `connect` — the store no longer holds a fixed TTL.
    let ttl = Duration::from_millis(500);
    let (_container, url) = start_redis().await;
    let store = RedisNonceStore::connect(&url)
        .await
        .expect("connect to redis");

    let key = "ttl_expiry-key";
    assert!(
        store
            .claim(key, ttl)
            .await
            .expect("first claim reaches redis"),
        "first claim of a fresh key must be accepted"
    );

    // Poll for the key to become reclaimable. Budget generously above the TTL so a
    // slow CI box does not flake; the poll gap is small so we catch the flip
    // promptly once it happens.
    let budget = Duration::from_secs(5);
    let poll_gap = Duration::from_millis(50);
    let deadline = Instant::now() + budget;

    loop {
        let reclaimed = store
            .claim(key, ttl)
            .await
            .expect("poll claim reaches redis");
        if reclaimed {
            // The key expired and we re-claimed it: the TTL guarantee holds.
            break;
        }
        assert!(
            Instant::now() < deadline,
            "key was still un-expired after {budget:?}: PX TTL did not lapse (or was refreshed)"
        );
        tokio::time::sleep(poll_gap).await;
    }
}

/// Guarantee 4: fail-CLOSED when the backend is unreachable.
///
/// Mechanism: we `connect` to a *live* container, confirm a claim succeeds, then
/// STOP the container out from under the store and assert the next claim yields
/// `Err(_)`. This is deliberately the "was healthy, backend then died" path — the
/// most faithful model of a production Redis outage — rather than a connect-time
/// failure to a dead address. A replay guard that cannot reach its store must
/// never fabricate an `Ok`: `Err` is the only safe outcome (the gate maps it to
/// 503, already unit-tested in WP2).
///
/// The claim is wrapped in a timeout so a hypothetical hang (instead of a prompt
/// I/O error) fails loudly as a test failure rather than stalling the suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_backend_fails_closed() {
    let (container, url) = start_redis().await;
    let store = RedisNonceStore::connect(&url)
        .await
        .expect("connect to redis");

    let ttl = Duration::from_mins(1);
    let key = "fail_closed-key";
    assert!(
        store
            .claim(key, ttl)
            .await
            .expect("claim works while redis is up"),
        "sanity: the store must work before we kill the backend"
    );

    // Kill the backend. Stopping tears down the published port, so the store's
    // existing multiplexed socket breaks and the next command must surface an error.
    container.stop().await.expect("stop the redis container");

    let outcome = tokio::time::timeout(Duration::from_secs(10), store.claim(key, ttl))
        .await
        .expect("claim must return promptly after the backend dies, not hang");

    assert!(
        outcome.is_err(),
        "claim against a dead backend must fail CLOSED (Err), never a bogus Ok: got {outcome:?}"
    );
}

/// Guarantee 5 (H1 regression): a long per-claim TTL keeps the nonce remembered
/// across an interval that a short/fixed TTL would have expired.
///
/// This is the store-level proof of the H1 fix's core property. The gate derives
/// the TTL from the authorization's own `validBefore` (`gate.rs`), so an auth with
/// a distant `validBefore` yields a long TTL. Under the OLD fixed-TTL design a
/// nonce would `PX`-expire after a short store-wide window while `verify_payment`
/// still accepted the (longer-dated) authorization — the replay hole. Here we pass
/// a long TTL and prove the key is STILL claimed after an interval that comfortably
/// exceeds the 500ms short TTL used by `ttl_expiry_makes_key_reclaimable`, so a
/// replay within the authorization window is rejected.
///
/// Coverage boundary: this exercises the store honouring a long TTL, not the gate's
/// arithmetic `validBefore - now` itself (that derivation is plain, panic-free code
/// in `gate.rs`); a full gate+signing+Redis path is out of scope for this slice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_ttl_keeps_nonce_remembered_within_window() {
    let (_container, url) = start_redis().await;
    let store = RedisNonceStore::connect(&url)
        .await
        .expect("connect to redis");

    // A "distant validBefore" TTL: far longer than the 500ms short TTL, so the
    // nonce must survive the wait below.
    let long_ttl = Duration::from_mins(1);
    let key = "long_ttl_remembered-key";

    assert!(
        store
            .claim(key, long_ttl)
            .await
            .expect("first claim reaches redis"),
        "first claim of a fresh key must be accepted"
    );

    // Wait past the short-TTL horizon (500ms) that WOULD have expired the old
    // fixed-TTL store; a small margin over it keeps the test fast but unambiguous.
    tokio::time::sleep(Duration::from_millis(800)).await;

    assert!(
        !store
            .claim(key, long_ttl)
            .await
            .expect("replay claim reaches redis"),
        "with a TTL matching the authorization window, a replay within that window \
         must still be rejected (Ok(false)) — the H1 fix"
    );
}
