//! Nonce replay stores: the in-memory M3 seam plus the M4 `NonceStore` trait and
//! its in-memory / Redis backends.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// In-memory nonce replay store for M3. A committed seam: M4 replaces this with a
/// Redis-backed store behind a `NonceStore` trait extracted from THIS type — do not
/// add the trait now (one impl = no trait, rule-of-three). Clone shares state (Arc),
/// so every per-connection clone of the gate sees the same recorded-nonce set.
#[derive(Clone, Default)]
pub struct InMemoryNonceStore {
    // `Arc` gives every clone a handle to the *same* set; `Mutex` serialises the
    // check-and-record so two concurrent requests carrying the same nonce cannot
    // both observe it as new. The set owns each key as a `String`.
    seen: Arc<Mutex<HashSet<String>>>,
}

impl InMemoryNonceStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically record `key`. Returns `true` if this is the FIRST time the key is
    /// seen (accept the payment), `false` if it was already recorded (replay -> reject).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned (a prior holder panicked while
    /// mutating the set); see the inline note on why failing loudly is safe here.
    #[must_use]
    pub fn record_if_new(&self, key: &str) -> bool {
        // `HashSet::insert` returns `true` when the value was newly inserted and
        // `false` when it was already present — that single call under the lock
        // IS the atomic check-and-record, with no check-then-act race window.
        //
        // A poisoned mutex means another thread panicked mid-update. For M3 we
        // treat that as unrecoverable rather than papering over possibly-corrupt
        // replay state — a corrupted replay set is a security-relevant fault, so
        // failing loudly is the safe default.
        let mut seen = self.seen.lock().expect("nonce store mutex poisoned");
        seen.insert(key.to_owned())
    }
}

/// A backend failure while claiming a nonce. There is exactly one variant today
/// (Redis I/O); it exists as an enum, not a bare alias, so a second backend can
/// add its own error without churning every caller's `match`. Callers MUST treat
/// `Err` as fail-CLOSED — a backend we cannot reach can neither confirm nor deny a
/// replay, and accepting on doubt is the one outcome a replay guard must never have.
#[derive(Debug, thiserror::Error)]
pub enum NonceStoreError {
    #[error("nonce store backend error")]
    Backend(#[from] redis::RedisError),
}

/// A replay-nonce store. `claim` is the atomic check-and-record — the async,
/// fallible generalisation of [`InMemoryNonceStore::record_if_new`]:
/// `Ok(true)` = first time seen (accept), `Ok(false)` = already seen (replay),
/// `Err` = backend failure (caller must fail CLOSED, never accept).
///
/// `ttl` is the PER-CLAIM lifetime the caller wants this specific nonce remembered
/// for — the gate derives it from the authorization's own `validBefore` (see
/// `gate.rs`), so a nonce is remembered at least as long as its authorization could
/// still be validly presented. Over-remembering is always replay-safe; only
/// under-remembering re-opens a replay, so a backend that cannot honour a TTL (the
/// in-memory one never evicts) is free to remember LONGER — never shorter.
///
/// The method is a return-position `impl Future` (RPITIT), not `async fn`, so we
/// can pin the `+ Send` bound the tower service needs to hold the future across an
/// `.await`. That expressiveness costs dyn-safety: there is no `dyn NonceStore`, so
/// runtime backend choice goes through the [`NonceBackend`] enum, not a trait object.
pub trait NonceStore: Send + Sync {
    fn claim(
        &self,
        key: &str,
        ttl: std::time::Duration,
    ) -> impl std::future::Future<Output = Result<bool, NonceStoreError>> + Send;
}

// In-memory: the check-and-record is sync + infallible, so `claim` just wraps
// `record_if_new` in an already-resolved future. The sync work runs eagerly —
// before the `async move` — so the lock is taken and released here, not deferred
// into a future that a caller might never poll.
impl NonceStore for InMemoryNonceStore {
    fn claim(
        &self,
        key: &str,
        // The in-memory store NEVER evicts, so it necessarily remembers a nonce for
        // at least as long as any requested `ttl` — the safe (over-remembering)
        // direction — and the parameter is therefore ignored. Unbounded memory is
        // the accepted tradeoff of this non-production backend; the Redis backend is
        // the one that honours a TTL to bound memory.
        _ttl: std::time::Duration,
    ) -> impl std::future::Future<Output = Result<bool, NonceStoreError>> + Send {
        let hit = self.record_if_new(key);
        async move { Ok(hit) }
    }
}

/// Redis-backed store — the durable, cross-instance replacement for
/// [`InMemoryNonceStore`] (the M3 seam this trait was extracted from).
///
/// `MultiplexedConnection` multiplexes many logical requests over one real socket
/// and is cheap to `clone` (each clone shares that socket), so we hold a single one
/// and clone per `claim` rather than managing a connection pool.
#[derive(Clone)]
pub struct RedisNonceStore {
    conn: redis::aio::MultiplexedConnection,
}

impl RedisNonceStore {
    /// Eagerly opens a multiplexed connection (so a bad URL / down Redis fails at
    /// wiring time, not on the first request). The TTL is NOT fixed at connect time:
    /// each [`claim`](NonceStore::claim) carries its own, derived by the gate from
    /// the authorization's `validBefore`, so a nonce lives in Redis exactly as long
    /// as its authorization could still be validly presented — and no longer.
    ///
    /// # Errors
    /// Returns [`NonceStoreError::Backend`] if the URL is malformed or the initial
    /// connection to Redis cannot be established.
    pub async fn connect(url: &str) -> Result<Self, NonceStoreError> {
        let client = redis::Client::open(url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(Self { conn })
    }
}

impl NonceStore for RedisNonceStore {
    fn claim(
        &self,
        key: &str,
        ttl: std::time::Duration,
    ) -> impl std::future::Future<Output = Result<bool, NonceStoreError>> + Send {
        // Clone the cheap connection handle and own the inputs so the returned
        // future is `'static` + `Send` — nothing borrows from `self` past this point.
        let mut conn = self.conn.clone();
        // `as_millis` is u128; a TTL that overflows u64 milliseconds (~584M years)
        // is absurd for a payment-auth window, so saturate rather than truncate —
        // the exact value past that bound is irrelevant, and truncation could
        // silently produce a tiny TTL (which would under-remember and re-open a replay).
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        let key = key.to_owned();
        async move {
            // SET key "1" NX PX <ttl_ms>: one round-trip, atomic on the server. NX =
            // only set if absent, so among concurrent claimants for the same key
            // exactly one gets `Some(())` (accept) and every other gets nil = `None`
            // (replay). PX bounds memory and ties the record to the auth window. The
            // value "1" is an inert placeholder — no signature or secret goes to Redis.
            let set: Option<()> = redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("NX")
                .arg("PX")
                .arg(ttl_ms)
                .query_async(&mut conn)
                .await?;
            Ok(set.is_some())
        }
    }
}

/// Runtime backend selection. The operator picks in-memory or Redis via config;
/// a closed enum gives static dispatch through an exhaustive `match` — no
/// `Arc<dyn NonceStore>` (the RPITIT trait above is not dyn-safe) and no new
/// dependency. Adding a backend is a new variant plus one arm here, caught at
/// compile time by exhaustiveness.
#[derive(Clone)]
pub enum NonceBackend {
    InMemory(InMemoryNonceStore),
    Redis(RedisNonceStore),
}

impl NonceStore for NonceBackend {
    // Kept in the explicit `impl Future + Send` form (not `async fn`) to stay
    // visually parallel with the sibling impls and to make the `+ Send` the tower
    // service relies on explicit at the delegation point.
    #[allow(clippy::manual_async_fn)]
    fn claim(
        &self,
        key: &str,
        ttl: std::time::Duration,
    ) -> impl std::future::Future<Output = Result<bool, NonceStoreError>> + Send {
        async move {
            match self {
                NonceBackend::InMemory(s) => s.claim(key, ttl).await,
                NonceBackend::Redis(s) => s.claim(key, ttl).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryNonceStore, NonceStore};

    #[test]
    fn first_record_is_new_then_replay() {
        let store = InMemoryNonceStore::new();
        assert!(store.record_if_new("nonce-a"), "first sighting must be new");
        assert!(
            !store.record_if_new("nonce-a"),
            "second sighting must be a replay"
        );
    }

    #[test]
    fn distinct_keys_are_independent() {
        let store = InMemoryNonceStore::new();
        assert!(store.record_if_new("nonce-a"));
        assert!(store.record_if_new("nonce-b"));
    }

    #[test]
    fn clones_share_state() {
        // Cloning shares the underlying set via `Arc`, mirroring how each
        // per-connection clone of the gate must see the same recorded nonces.
        let a = InMemoryNonceStore::new();
        let b = a.clone();
        assert!(a.record_if_new("nonce-shared"));
        assert!(
            !b.record_if_new("nonce-shared"),
            "clone must observe the sibling's record as a replay"
        );
    }

    // The async `NonceStore::claim` on the in-memory backend must mirror the sync
    // `record_if_new` exactly: first claim is new (accept), second is a replay.
    // This is the only backend we exercise in unit tests — Redis is covered by
    // WP4's testcontainers integration test, not here.
    #[tokio::test]
    async fn claim_mirrors_record_if_new() {
        let store = InMemoryNonceStore::new();
        // The in-memory backend ignores the ttl (it never evicts); a nominal value
        // documents the call shape without affecting the outcome.
        let ttl = std::time::Duration::from_mins(1);
        assert!(
            store
                .claim("nonce-a", ttl)
                .await
                .expect("in-memory claim is infallible"),
            "first claim must be new"
        );
        assert!(
            !store
                .claim("nonce-a", ttl)
                .await
                .expect("in-memory claim is infallible"),
            "second claim must be a replay"
        );
    }
}
