# Architecture

Tollgate is an [x402](https://www.x402.org/) payments facilitator and gateway: it
gates HTTP endpoints behind a machine-readable 402 challenge, verifies signed
payment authorizations, protects against replay, and settles batched USDC claims
on Base Sepolia. These C4 diagrams describe the **target** system; only the parts
marked *present* exist today. As of **M3**, `tollgate-core`,
`tollgate-middleware`, and `tollgate-gateway` are built (offline verification, the
tower gate, and the axum reverse proxy); the **M4 nonce-store slice** then made
**Redis** a real backend — the gate claims nonces atomically against Redis for
replay protection — and the **M5a claims-ledger slice** made **Postgres** one too:
every accepted payment is recorded durably in the claims ledger. The rest of M4
(the policy engine: per-payer velocity and spend caps), settlement (M5b), and
everything downstream remain planned containers that later milestones (M4–M7)
will fill in.

The diagrams below render natively on GitHub via `mermaid` code fences — no build
step required.

## System context

The context diagram shows who uses Tollgate and the external systems it depends
on. Two human/agent actors drive it: an **API provider (merchant)** wraps their
endpoints and receives settlements, and an **Agent developer** whose agent pays
per request. Tollgate itself is a single system boundary here; it settles on
**Base Sepolia**, claims replay-protection state from **Redis**, and persists the
claims ledger in **Postgres**. The **Redis nonce-claim** (M4) and **Postgres
claims-ledger** (M5a) integrations are wired — the gate claims nonces atomically
and records every accepted claim; velocity windows, the outbox, and Base Sepolia
settlement remain the shape the later milestones build toward.

```mermaid
C4Context
    title System context — Tollgate (target)

    Person(agentDev, "Agent developer", "Builds an agent that pays per request: hits an endpoint, gets a 402, signs an authorization, retries with X-PAYMENT.")
    Person(merchant, "API provider (merchant)", "Wraps existing endpoints with Tollgate, sets per-route prices, receives batched USDC settlements.")

    System(tollgate, "Tollgate", "x402 facilitator & gateway: 402 challenge, payload verification, replay protection, batched settlement.")

    System_Ext(baseSepolia, "Base Sepolia", "EVM testnet: USDC settlement and batch redemption.")
    System_Ext(redis, "Redis", "Nonce acceptance [present, M4]; velocity windows [planned].")
    System_Ext(postgres, "Postgres", "Claims ledger [present, M5a]; transactional outbox [planned].")

    Rel(agentDev, tollgate, "Requests gated resources, submits signed payments", "HTTP / X-PAYMENT")
    Rel(merchant, tollgate, "Configures routes/prices, reads claims & settlement status", "HTTP / config")
    Rel(tollgate, redis, "Atomic nonce claim [present, M4]; velocity checks [planned]")
    Rel(tollgate, postgres, "Records verified claims [present, M5a]; outbox events [planned]")
    Rel(tollgate, baseSepolia, "Batches and redeems USDC claims", "JSON-RPC")
```

## Container view

The container diagram breaks Tollgate into its Cargo workspace crates. As of M3,
**`tollgate-core`** (library), **`tollgate-middleware`** (library), and
**`tollgate-gateway`** (binary) are built and marked *[present]*; the remaining
containers are *[planned]* and shown as boxes only — no internal detail is
invented for unbuilt crates. The label on each container carries its
present/planned marker, and the legend restates the convention.

```mermaid
C4Container
    title Container view — Tollgate workspace (M3–M5a present vs. planned)

    Person(agentDev, "Agent developer")
    Person(merchant, "API provider (merchant)")

    System_Ext(baseSepolia, "Base Sepolia")
    System_Ext(redis, "Redis [present, M4 nonce]")
    System_Ext(postgres, "Postgres [present, M5a ledger]")

    System_Boundary(tollgate, "Tollgate") {
        Container(core, "tollgate-core", "Rust lib [present]", "x402 types, spec constants, payload parsing & verification.")
        Container(gateway, "tollgate-gateway", "Rust bin (axum) [present]", "Reverse proxy: gates upstreams, issues 402 challenges.")
        Container(middleware, "tollgate-middleware", "Rust lib [present]", "tower Layer/Service to embed the gate in a host app.")
        Container(settler, "tollgate-settler", "Rust bin [planned M5b]", "Settlement worker: batches claims, redeems on-chain.")
        Container(admin, "tollgate-admin", "Rust bin [planned]", "Admin API: claims, batches, per-agent spend, metrics.")
        Container(xtask, "xtask", "Rust bin [planned]", "In-workspace dev automation / tooling.")
    }

    Rel(agentDev, gateway, "Pays for gated resources", "HTTP / X-PAYMENT")
    Rel(merchant, admin, "Views claims & settlement", "HTTP")
    Rel(gateway, core, "Uses types & verification")
    Rel(middleware, core, "Uses types & verification")
    Rel(settler, core, "Uses claim types")
    Rel(gateway, redis, "Atomic nonce claim [present, M4]; velocity [planned]")
    Rel(gateway, postgres, "Records verified claims [present, M5a]")
    Rel(settler, postgres, "Reads claims, writes settlement state")
    Rel(settler, baseSepolia, "Batch redemption", "JSON-RPC")

    UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")
```

**Legend.** `[present]` = shipped (M0–M3, plus the M4 Redis nonce-claim and M5a
claims-ledger slices).
`[planned M<n>]` = scheduled for that
milestone (see the [Roadmap](../README.md#roadmap)); `[planned]` with no number is
scheduled but unscoped. Planned containers are placeholders — their internals are
defined when their milestone lands.
