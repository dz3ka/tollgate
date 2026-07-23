# Tollgate

*An x402 agentic-payments facilitator & gateway — self-hostable, written in Rust.*

> ⚠️ **Portfolio & learning project.** Tollgate is a Rust-learning and portfolio
> project. It runs on **testnet only (Base Sepolia)**, handles **no real funds**,
> and is **not audited** — do not point it at mainnet. It is also honest about its
> market: the headline x402 transaction numbers sit on **thin real commercial
> volume**, so Tollgate is positioned as **infrastructure engineering** — a
> correct, observable facilitator — not a bet on the x402 narrative.

## Status

**M3 (gateway middleware + reverse proxy) complete.** On top of the M2
offline verifier, the new `tollgate-middleware` crate is a tower `Layer`/`Service`
that gates an axum app via the x402 flow — 402 + `Challenge` on a missing/invalid
`X-PAYMENT`, and `verify_payment` + an in-memory nonce replay-check on a valid one —
and `tollgate-gateway` is now an axum server that mounts the middleware and
reverse-proxies accepted requests to a configured upstream (SSRF-guarded, with
hop-by-hop/`X-PAYMENT`/`Host` hygiene). An end-to-end integration test drives the
full 402 → sign EIP-3009 → 200-relayed → replay-402 path over real TCP. The
**M4 nonce-store slice** is now in: a `NonceStore` trait with a Redis backend
(atomic `SET NX PX` claim, per-claim TTL from each authorization's `validBefore`,
store-error → fail-closed non-leaking 503), operator-selected via
`TOLLGATE_REDIS_URL` and proven under concurrency by testcontainers. The
**M5a claims-ledger slice** follows the same shape: set `TOLLGATE_DATABASE_URL` to
a Postgres URL and every accepted payment is recorded durably (schema migrated at
startup, ledger-error → the same fail-closed 503) so a settlement worker can redeem
it later; leave it **unset and claims are not recorded at all** — the gate still
gates, but accepted payments leave nothing to settle from. The **M5b settlement
slice** is that later: `tollgate-settler` is a standalone worker that sweeps the
ledger every minute and redeems each claim's EIP-3009 authorization on Base Sepolia
via `transferWithAuthorization`, marking the row settled only once the receipt says
success. The M4 policy engine and milestones **M6–M7** (demo kit and benchmarks) are
planned — see the [Roadmap](#roadmap).

## Highlights

What M0 actually ships:

- **Cargo workspace** — three crates at M0 (`tollgate-core` lib,
  `tollgate-middleware` lib, `tollgate-gateway` bin), room for the planned crates.
  Five as of M5b — see the crate table below.
- **`#![forbid(unsafe_code)]`** across the workspace.
- **CI gate** — a single `make ci` step runs fmt-check → build → clippy
  (pedantic, `-D warnings`) → test on every push and pull request.
- **Pinned toolchain** — `rust-toolchain.toml` fixes the exact Rust version so
  local and CI builds match; `rustup` auto-installs it.

## Architecture at a glance

One Cargo workspace. Five crates exist as of M5b (`tollgate-core`,
`tollgate-middleware`, `tollgate-ledger`, `tollgate-gateway`, `tollgate-settler`);
more are planned as the milestones land. Postgres owns the claims ledger, Redis
holds nonces and velocity windows, and settlement targets Base Sepolia (per PRD §7).

| Crate | Kind | Status | Purpose |
|-------|------|--------|---------|
| `tollgate-core` | lib | present | x402 types, spec constants, payload parsing & verification |
| `tollgate-gateway` | bin | present | axum reverse proxy that gates upstreams and issues 402 challenges |
| `tollgate-middleware` | lib | present | tower `Layer`/`Service` for embedding the gate in a host app |
| `tollgate-ledger` | lib | present | Postgres claims ledger: records accepted payments, hands out what is still owed |
| `tollgate-settler` | bin | present | settlement worker: sweeps owed claims and redeems them on Base Sepolia |
| `tollgate-admin` | bin | *planned (later)* | admin API: claims, batches, per-agent spend, Prometheus metrics |
| `xtask` | bin | *planned* | in-workspace dev automation |

See [`docs/architecture.md`](docs/architecture.md) for the C4 context and
container diagrams.

## Quickstart

**Prerequisites:** `make` and a Git checkout. Rust is pinned via
`rust-toolchain.toml`, so `rustup` auto-installs the correct toolchain (plus
rustfmt and clippy) on the first cargo call — no manual version juggling.

```bash
# 1. Build the whole workspace against the committed lockfile.
make build

# 2. Run the test suite.
make test

# 3. Run the full CI gate locally (fmt-check → build → clippy → test).
make ci
```

## Configuration

Everything is read from the environment at startup; nothing is read from a config
file. The gateway defaults to a local Base Sepolia testnet setup, while the settler
defaults **nothing** — it moves money, so a missing knob is a startup error rather
than an assumed testnet.

| Variable | Binary | Required | Purpose |
|----------|--------|----------|---------|
| `TOLLGATE_LISTEN` | gateway | no (`127.0.0.1:8080`) | address the gateway binds to |
| `TOLLGATE_UPSTREAM` | gateway | no (`http://127.0.0.1:8081`) | absolute `http://` base the gateway proxies accepted requests to |
| `TOLLGATE_PAY_TO` | gateway | no (placeholder) | EVM address the 402 challenge asks payers to pay |
| `TOLLGATE_REDIS_URL` | gateway | no | Redis URL for the nonce store; unset falls back to the in-memory store |
| `TOLLGATE_DATABASE_URL` | gateway, settler | gateway no / settler **yes** | Postgres URL of the claims ledger; unset in the gateway means accepted payments are not recorded |
| `TOLLGATE_RPC_URL` | settler | **yes** | JSON-RPC endpoint of the settlement chain (must report chain id 8453 or 84532) |
| `TOLLGATE_SIGNER_KEY` | settler | **yes** | hex secp256k1 key of the account that signs and pays gas for settlements — a **secret**; parsed once at startup and never logged |
| `TOLLGATE_TENDERLY_RPC_URL` | tests only | no | forked Base Sepolia endpoint that enables the settler's on-chain end-to-end test; unset and that test skips |

Values are credentials as often as not (`TOLLGATE_SIGNER_KEY` is a private key, and
both URL knobs can carry a password or an API key), so no configuration type in the
workspace derives `Debug` and no error message repeats one back.

## Repository layout

```
Cargo.toml            workspace manifest
Cargo.lock            committed lockfile
rust-toolchain.toml   pinned Rust version
Makefile              build / test / lint / ci targets
crates/
  tollgate-core/       library crate (x402 types, spec, verification)
  tollgate-middleware/ tower Layer/Service that gates an axum app via x402
  tollgate-ledger/     Postgres claims ledger (schema + queries)
  tollgate-gateway/    axum reverse-proxy binary crate
  tollgate-settler/    settlement worker binary crate (on-chain redemption)
docs/
  architecture.md     C4 context + container diagrams (Mermaid)
.github/
  workflows/ci.yml    single-job CI (make ci)
```

## Roadmap

Milestone titles from PRD §8. Each milestone is one `/ship` cycle.

| Milestone | Scope |
|-----------|-------|
| **M0** ✅ | Workspace, CI, clippy/fmt, C4 diagram, first 3 ADRs |
| **M1** ✅ | x402 types + 402 challenge + payload parsing with full test suite |
| **M2** ✅ | Signature verification (EIP-712/EIP-3009 via alloy) |
| **M3** ✅ | Tower middleware + axum gateway (happy path, in-memory nonce) |
| **M4** ◐ | Redis nonce store ✅ (atomic `SET NX PX`, per-claim TTL, fail-closed 503); policy engine deferred |
| **M5** ✅ | Postgres claims ledger (every accepted payment recorded, `TOLLGATE_DATABASE_URL`) + settlement worker (EIP-3009 redemption on Base Sepolia) |
| **M6** ⬜ | Demo kit: paying agent + gated MCP-style tool server |
| **M7** ⬜ | Benchmarks, fuzzing, load test, performance writeup |

## License

[MIT](LICENSE).
