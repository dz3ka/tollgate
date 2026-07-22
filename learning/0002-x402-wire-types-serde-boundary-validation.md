# 0002 — x402 wire types: serde boundary validation, forward-compat enums, and layered error composition (M1, Rust)

## 1. What we built

Milestone M1 gives `tollgate-core` its first real domain surface: the **x402 wire
layer**. x402 is an HTTP-native micropayment protocol — a server answers a gated
request with `402 Payment Required` and a JSON body of *offers*, and the client
retries with an `X-PAYMENT` header carrying a signed authorization. This milestone
implements three things and, deliberately, nothing more:

1. **Wire types** — the Rust structs/enums that serialize to and from the exact JSON
   the protocol defines (`PaymentRequirements`, `Challenge`, `PaymentPayload`, plus
   the value types `Scheme`, `Network`, `EvmAddress`, `Nonce`, `UintStr`).
2. **A 402-challenge builder** — `Challenge::new` plus a fluent
   `PaymentRequirementsBuilder` so higher layers can construct offers without
   fighting a twelve-field struct literal.
3. **Untrusted `X-PAYMENT` decoding** — `decode_payment_header(&str)` runs the
   pipeline `size-check -> base64 -> UTF-8 -> JSON -> field validation -> protocol
   checks`, returning a validated `PaymentPayload` or a typed error.

The hard rule for M1 is **no cryptography**. The client's `signature` field is
carried through as an opaque `String`; verifying it (EIP-3009 / EIP-712 recovery) is
M2's job. So this milestone is entirely about *shape and trust boundaries*: turning
bytes from a hostile network into a strongly-typed value you can reason about, and
refusing anything that does not fit — without yet claiming the payment is *real*.

That framing is why this is a good Rust lesson. The whole file set is an exercise in
the language's central trick: **make illegal states unrepresentable, and push
validation to the type-system boundary** so the rest of the codebase never re-checks
what the types already guarantee.

## 2. The design decision

The problem: JSON from the wire is untyped and untrusted, and the x402 spec is
*churning* (a v2 prose spec has drifted away from the v1 zod schemas that clients
actually ship). We need types that (a) reject garbage hard, (b) survive the spec
adding new networks tomorrow without a recompile-or-die failure, and (c) keep the
"is this a real payment" question cleanly separable for M2. Four decisions carry the
design.

### Decision A — Pin the spec to a git revision, as a const

`SPEC_REVISION = "coinbase/x402@dd927a26…"` and `X402_VERSION: u8 = 1` are compiled
into the crate. The authoritative contract is the **legacy zod schemas** at that
commit, not the prose v2 spec.

- **Chosen:** treat the code clients actually run as the source of truth, and record
  *which* revision in a const so the pin is greppable and shows up in any serialized
  diagnostic.
- **Rejected — follow the prose v2 spec:** the prose had drifted ahead of every
  deployed client. Implementing v2 would be interoperable with nobody today.
- **Rejected — leave the pin in a comment or a wiki:** a `const` is discoverable from
  code, survives refactors, and can be asserted against in tests. Documentation rots;
  a symbol the compiler tracks does not.

This is the **anti-corruption layer** idea from DDD, applied at the version level: you
name the exact external contract you conform to so that "the spec changed" becomes a
visible, deliberate edit rather than silent drift.

### Decision B — Forward-compatible enums: tolerant deserialize, strict decode

`Scheme` and `Network` are *closed* Rust enums, but each carries an `Unknown(String)`
catch-all variant. Unknown wire strings **deserialize successfully** into `Unknown`,
and are then **rejected** by an exhaustive `match` in `decode_payment_header` that has
**no `_` wildcard arm**.

- **Chosen:** split "can I parse this?" from "will I accept this?". Deserialization is
  total (never fails on an unknown network string); the *policy* decision to reject
  lives in one auditable place.
- **Rejected — strict enums (no `Unknown`):** an unrecognized network would fail at
  the serde layer as a generic "malformed JSON" error, indistinguishable from a
  truncated body. You lose the ability to say `unsupported network: ethereum` and you
  lose the ability to, later, *tolerate-and-log* an unknown value in a context where
  that is the right call.
- **Rejected — open representation (store everything as `String`):** then every
  consumer re-parses the string and the type system stops helping. The enum gives you
  exhaustive matching for the 17 known networks *and* a controlled escape hatch.

The subtle, deliberate part: the decoder's `match` on `Network` lists all 17 known
variants explicitly and handles `Unknown` by erroring. There is **no `_`**. That means
the day someone adds `Network::Optimism`, this file **stops compiling** until a human
decides whether Optimism is supported. The missing wildcard is a *compile-time
tripwire* — the type system nagging you to make a policy decision you would otherwise
forget. (See the deep-dive; this is the single most instructive line in the diff.)

### Decision C — Validating newtypes at the boundary; don't validate the impossible

`EvmAddress`, `Nonce`, and `UintStr` are `struct Foo(String)` with a **private** field
and `#[serde(try_from = "String")]`. You cannot construct one except through
`TryFrom<String>`, which enforces the format (`0x` + 40 hex, `0x` + 64 hex, decimal
digits ≤ 78). Because serde is told to build them via `try_from`, **a malformed field
anywhere in the JSON tree fails the whole deserialization** — validation is not a
second pass you might forget to call.

But `signature` stays a plain `String`. That is not laziness; it is the **"don't
validate what you can't yet meaningfully check"** principle. A signature's only real
validity test is cryptographic recovery, which is M2. A regex on its shape would give
false confidence — it would reject some invalid signatures and accept most, buying
nothing. So the boundary validates exactly what it can *fully* decide (structural
format) and defers what it cannot (cryptographic truth).

- **Chosen:** parse, don't validate — the return type `EvmAddress` is itself the proof
  that validation happened, carried in the type for the rest of the program's life.
- **Rejected — validate-on-use:** scatter `assert_is_address(&s)` calls at call sites.
  Every new call site is a chance to forget one; the type says nothing.
- **Rejected — public field + a `validate()` method:** you can then mint an invalid
  `EvmAddress` by hand and the "validated" type is a lie. Private fields + `try_from`
  make the invariant unforgeable.

### Decision D — DoS cap before decode

`decode_payment_header` checks `header.len() > MAX_PAYMENT_HEADER_BYTES` (8 KiB)
**before** touching base64. serde_json's default 128-level recursion depth is kept
(not raised), and the target type is the concrete `PaymentPayload`, so no
`serde_json::Value` is ever allocated from attacker input on the payment path.

- **Chosen:** bound the work an attacker can force *before* doing any of it. Base64 of
  a 1 GiB header would allocate ~750 MiB before you even reach the JSON parser; the
  length gate makes that impossible.
- **Rejected — decode first, size-check the result:** you have already paid the
  allocation cost by then. The cheap check must come first.

## 3. Language deep-dive

Four snippets, chosen because each teaches a Rust idiom a senior engineer coming from
Java/TS/Go would not reach for by default.

### 3.1 The validating newtype: private field + `try_from`, invariant unforgeable

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EvmAddress(String);          // <- field is private (no `pub`)

impl TryFrom<String> for EvmAddress {
    type Error = FieldFormatError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if is_hex_with_prefix(&value, 40) {
            Ok(Self(value))             // <- takes ownership of `value`, no copy
        } else {
            Err(FieldFormatError::InvalidAddress)
        }
    }
}
```

Line by line:

- `pub struct EvmAddress(String);` is a **tuple struct** with one field. Because the
  `String` inside has no `pub`, it is private to the module. Outside `types.rs`, the
  *only* way to get an `EvmAddress` is a constructor that lives in this module — and
  every constructor here routes through `try_from`. This is the enforcement mechanism.
  There is no "back door" literal `EvmAddress(bad)` from another file. In Java you'd
  approximate this with a final class, a private constructor, and a static factory;
  Rust gets it from module-level field privacy with zero boilerplate.
- `#[serde(try_from = "String", into = "String")]` is the load-bearing attribute. It
  tells serde: *don't* derive field-by-field (de)serialization for this type; instead,
  to **deserialize**, first deserialize a `String`, then call `EvmAddress::try_from` on
  it, and if that `Result` is `Err`, fail the whole deserialization; to **serialize**,
  convert into `String` first. So the JSON representation is a plain string, but the
  in-memory value is validated. The `try_` prefix is what lets construction *fail*;
  `Network` below uses the infallible `from` instead precisely because it never fails.
- `Ok(Self(value))` **moves** `value` into the struct. `value: String` was passed by
  value (owned), we validated it by borrowing (`&value` inside `is_hex_with_prefix`),
  and on success we hand the same heap allocation to `Self`. No clone, no copy of the
  string bytes. This is the ownership payoff: the function *consumes* the input and
  *produces* the validated wrapper over the same buffer.
- `type Error = FieldFormatError;` wires a domain error into the standard `TryFrom`
  trait. serde will surface this through its own error type (see 3.3).

Why idiomatic: the pattern is called the **newtype pattern**, and combined with a
private field it is Rust's canonical "smart constructor". The invariant ("this string
is a well-formed EVM address") is established once, at the boundary, and thereafter
*the type itself is the proof*. Nothing downstream re-checks.

Note the deliberate asymmetry with `Nonce` and `UintStr`: same pattern, different
predicate, and `UintStr` returns *three distinct* error variants (`Empty`,
`NotDecimal`, `TooLong { max }`) so the failure is diagnosable. `signature` gets none
of this — it's a bare `String`, because M1 cannot meaningfully validate it.

### 3.2 Forward-compat enum with a `From<String>` bridge

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]   // note: `from`, not `try_from`
pub enum Network {
    Base,
    BaseSepolia,
    // … 15 more …
    Unknown(String),                          // catch-all keeps deserialize total
}

impl From<String> for Network {
    fn from(value: String) -> Self {
        match value.as_str() {
            "base" => Self::Base,
            "base-sepolia" => Self::BaseSepolia,
            // …
            _ => Self::Unknown(value),         // never fails
        }
    }
}
```

- `#[serde(from = "String", …)]` (no `try_`) means deserialization is **infallible**:
  every JSON string maps to *some* `Network`, falling into `Unknown` if unrecognized.
  This is the "tolerant deserialize" half of Decision B. Contrast 3.1, where
  `try_from` makes deserialization *fallible* on purpose — the two attributes encode
  two different trust policies, and choosing between them is the design.
- `match value.as_str()` borrows the `String` as a `&str` to compare against string
  literals (`&str`), then in the fallthrough `_ => Self::Unknown(value)` **moves the
  owned `value`** into the `Unknown` variant. Borrow to inspect, move to store — no
  allocation for the unknown case. If you'd matched on `value` directly you'd have
  consumed it before the arm that needs it; `as_str()` sidesteps that.
- The `From<Network> for String` direction has a wrinkle worth seeing:

  ```rust
  fn from(value: Network) -> Self {
      match value {
          Network::Base => "base",
          // … all &'static str …
          Network::Unknown(s) => return s,   // early return: `s` is already String
      }
      .to_owned()                            // applies to the &str arms only
  }
  ```
  The known arms evaluate to `&'static str` and share one `.to_owned()` after the
  `match`. The `Unknown(s)` arm holds an *owned* `String` already, so it `return`s
  early to avoid a pointless `&str -> String` round-trip. This is a small idiom: a
  `match` that is an expression whose value flows into a trailing method call, with one
  arm bailing out via `return` because it doesn't fit the common type. A newcomer often
  writes `.to_string()` in every arm; this is tighter and shows you understand that
  `match` is an expression.

### 3.3 The decode pipeline: `?` + `#[from]` collapse five failure modes into one type

```rust
pub fn decode_payment_header(header: &str) -> Result<PaymentPayload, PaymentDecodeError> {
    if header.len() > MAX_PAYMENT_HEADER_BYTES {
        return Err(PaymentDecodeError::Oversized { len: header.len(), max: MAX_PAYMENT_HEADER_BYTES });
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(header)?; // DecodeError -> PaymentDecodeError
    let json  = std::str::from_utf8(&bytes)?;                              // Utf8Error   -> PaymentDecodeError
    let payload: PaymentPayload = serde_json::from_str(json)?;             // serde_json::Error -> PaymentDecodeError
    // … protocol checks …
    Ok(payload)
}
```

paired with the error enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum PaymentDecodeError {
    #[error("X-PAYMENT header too large: {len} bytes exceeds maximum of {max}")]
    Oversized { len: usize, max: usize },
    #[error("X-PAYMENT header is not valid base64: {0}")]
    Base64(#[from] base64::DecodeError),      // <- #[from] generates From impl
    #[error("X-PAYMENT payload is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("X-PAYMENT payload is malformed: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported x402 version: found {found}, expected 1")]
    UnsupportedVersion { found: u8 },
    // …
}
```

What the language is doing:

- The `?` operator after `.decode(header)` means: if `Err(e)`, `return Err(From::from(e))`
  from the enclosing function; if `Ok(v)`, evaluate to `v`. The *type conversion* is
  the crucial bit — `decode` yields `base64::DecodeError` but the function returns
  `PaymentDecodeError`, and `?` bridges them by calling `From<base64::DecodeError> for
  PaymentDecodeError`.
- That `From` impl is exactly what `#[from]` on the `Base64` variant generates. This is
  `thiserror` doing macro codegen: `#[from]` on a variant with one field emits both the
  `From` conversion *and* wires that field in as the error's `source()` in the standard
  `Error` trait. So three different library error types funnel into three variants with
  three lines of attribute, and the pipeline reads as a clean linear sequence of `?`s
  with no `match e { … }` noise.
- `#[error("… {0}")]` is the `Display` string. `{0}` interpolates the tuple field (the
  wrapped source error); `{len}`/`{max}`/`{found}` interpolate named struct fields.
  `thiserror` generates the `Display` impl from these — you write the format string, it
  writes the boilerplate. This is the library-error idiom: `thiserror` for *typed*
  errors a caller might match on (this crate), `anyhow` for *opaque* errors in
  application code that just bubbles up. A library exposes `thiserror`; a `main.rs`
  reaches for `anyhow`.
- Note what is *not* automatic: `Oversized`, `UnsupportedVersion`, `UnsupportedScheme`
  are constructed by hand with explicit `return Err(…)` because they arise from *our*
  logic, not from a foreign error type. `#[from]` is only for wrapping someone else's
  error.

Ownership trace through the pipeline (the "&str in, owned struct out" story):
`header: &str` is borrowed — the caller keeps ownership. `decode` allocates a fresh
`Vec<u8>` (`bytes`, owned locally). `from_utf8(&bytes)` *borrows* those bytes and
returns a `&str` (`json`) pointing into `bytes` — no copy, but now `json`'s lifetime is
tied to `bytes`, so `bytes` must outlive it (it does; both are locals). `from_str(json)`
reads that borrowed text and *allocates* an owned `PaymentPayload` (the strings inside
are fresh `String`s copied out of the JSON). When the function returns `payload`, it is
moved to the caller; `bytes` and `json` are dropped. So the returned value owns all its
data and has **no borrow of the input** — the caller can drop `header` freely. That
independence is the whole point of returning an owned struct from a decoder.

### 3.4 The wildcard-free exhaustive match: a compile-time tripwire

```rust
match payload.network {
    Network::Base
    | Network::BaseSepolia
    // … all 15 others …
    | Network::SkaleBaseSepolia => {}                     // accept: do nothing
    Network::Unknown(ref s) => {
        return Err(PaymentDecodeError::UnsupportedNetwork(s.clone()));
    }
}
```

- Every accepted network is listed explicitly, OR-combined with `|` into one arm whose
  body is `{}` (accept, fall through). The only *other* arm is `Unknown`. **There is no
  `_ => …` catch-all.**
- `Network::Unknown(ref s)` uses a **`ref` binding**: it borrows the inner `String`
  rather than moving it out of `payload.network`. Without `ref` you'd try to move `s`
  out of `payload`, partially moving `payload` and making it unusable — the compiler
  would reject the later `Ok(payload)`. `ref s` gives `s: &String`, and `s.clone()`
  makes the owned copy the error needs while leaving `payload` intact. (On modern Rust
  the default binding mode would often infer this, but writing `ref` makes the borrow
  explicit and is a good habit when the matched value is used again afterward.)
- The payoff: `match` in Rust is **exhaustive**. Because there's no `_`, when someone
  later adds `Network::Optimism`, this match no longer covers all variants and the crate
  **fails to compile** with `non-exhaustive patterns: Network::Optimism not covered`.
  That forces a human to open this decoder and decide: is Optimism supported (add it to
  the accept arm) or not (it falls to `Unknown` at deserialize time and errors here
  anyway)? Either way the decision is *made*, not *defaulted*. A `_ => accept` would
  silently wave the new network through; a `_ => reject` would silently block a network
  you meant to support. The absence of the wildcard is doing real safety work — it
  converts "spec added a network" from a runtime surprise into a compile error at the
  exact site that must change.

## 4. What would break (and the bugs a Rust newcomer would ship here)

- **Unvalidated fields leaking downstream.** The classic bug: parse into
  `struct { pay_to: String }`, then discover at settlement time (M2) that `pay_to` is
  `"0xnothex"`. The newtype + `try_from` makes that unrepresentable — the address is
  validated the instant the JSON is parsed, and the `field_validation_failures_are_malformed`
  test pins it (a bad address surfaces as `Malformed`, not as a later panic).
- **`unwrap()` on attacker input.** A newcomer might `serde_json::from_str(json).unwrap()`
  or `String::from_utf8(bytes).unwrap()`. On a hostile `X-PAYMENT` header those are
  denial-of-service panics. The code uses `?` into a typed error every time; there is no
  `unwrap`/`expect` on the decode path. (The `unwrap`s in the code are all in `#[cfg(test)]`
  and in `.parse().unwrap()` test helpers, where panicking *is* the assertion.)
- **Unbounded allocation before validation.** Base64-decoding before the length check
  would let a client force a huge allocation. The 8 KiB gate runs first; the
  `rejects_oversized` test locks the ordering.
- **`serde_json::Value` reachable from untrusted input.** If the target type were
  `Value` (or contained one on the hot path), an attacker could feed deeply nested or
  huge JSON. The concrete `PaymentPayload` target plus serde_json's retained 128-depth
  limit closes this. (`output_schema`/`extra` are `Option<Value>` but live only on the
  *outbound* `PaymentRequirements`, not on the decoded `PaymentPayload` — so no `Value`
  is built from `X-PAYMENT` input.)
- **Enum churn silently changing behavior.** Covered in 3.4 — the wildcard-free match
  turns it into a compile error instead.
- **Partial move in the match.** Writing `Network::Unknown(s) =>` without `ref` (and
  then still using `payload`) is the borrow-checker fight a newcomer hits here; the code
  sidesteps it with `ref s` + `.clone()`.
- **`deny_unknown_fields` brittleness.** The code deliberately does *not* set it, and
  `tolerates_unknown_authorization_key` proves an extra JSON key parses fine. For a
  churning spec this is correct: a v1.1 field addition shouldn't break a v1 decoder.
  The trade-off (stated honestly): you won't catch a *typo'd* field name — `"noce"`
  instead of `"nonce"` deserializes as "nonce missing" rather than "unknown field". For
  this protocol, forward-compat wins; for a closed internal API you might choose the
  opposite.

## 5. Compared to what you know

- **Newtype with private field ≈** a Java value object with a private constructor and a
  static `of(String)` factory that throws, or a TypeScript *branded type*
  (`type EvmAddress = string & { __brand: 'EvmAddress' }`) — **except** the Rust version
  is enforced by the compiler with no runtime wrapper object in the branded-TS sense,
  and (unlike TS brands, which are erased and bypassable with a cast) genuinely
  unforgeable because the field is module-private. Closest analogy overall: Scala's
  `AnyVal`/refined types.
- **`#[serde(try_from)]` ≈** a Jackson `@JsonCreator` factory or a custom deserializer,
  or `zod`'s `.transform()`/`.refine()` on a string schema — **except** it's wired by an
  attribute on the type, not registered in a mapper, and validation failure is a typed
  `Result`, not a thrown exception.
- **`?` + `#[from]` ≈** checked exceptions that auto-*convert* as they propagate. Imagine
  Java where `throws PaymentDecodeError` and a thrown `DecodeError` were *automatically*
  wrapped into `PaymentDecodeError` at the call site with no `try/catch`. **Where it
  breaks down:** there's no stack unwinding — `?` is an early `return`, fully explicit in
  the type signature, zero hidden control flow.
- **`thiserror` vs `anyhow` ≈** custom exception hierarchy vs `RuntimeException`-carrying-
  a-message. Libraries expose the former (callers match on it); apps use the latter.
- **Forward-compat `Unknown(String)` enum ≈** a Java enum plus an `UNKNOWN` sentinel, or
  a TS discriminated union with a `{ kind: 'unknown', raw: string }` fallback — **except**
  Rust's exhaustive `match` means the *acceptance* logic can't accidentally forget a
  case, which the Java/TS versions can (a `switch` with no `default` warning, at best).
- **Exhaustive `match` (no `_`) ≈** a Kotlin `when` on a sealed class used as an
  expression, which the compiler forces to be exhaustive. Go has *no* equivalent — a Go
  `switch` on a string is never checked for completeness, which is precisely the class of
  bug this design engineers away.

## 6. Gotchas & idioms in this diff

- **`from` vs `try_from` in serde is a policy choice, not a style choice.** `Scheme`/
  `Network` use `from` (deserialize can't fail → unknown becomes `Unknown`).
  `EvmAddress`/`Nonce`/`UintStr` use `try_from` (deserialize *should* fail on malformed
  input). Same crate, two attributes, two trust postures. Picking the wrong one is a
  real bug.
- **`String` literals in `match` need `.as_str()`.** You can't `match value { "base" => … }`
  on a `String` directly against `&str` patterns; `match value.as_str()` is the idiom.
- **`ref` in a match arm** avoids partially moving out of the scrutinee when you use it
  afterward. Here it's the difference between compiling and not.
- **`impl Into<String>` parameters** (`resource: impl Into<String>`, `with_error(msg: impl
  Into<String>)`) let callers pass `&str` *or* `String` without an explicit `.to_owned()`
  at every call site — ergonomic generics via monomorphization, the Rust analog of an
  overload set.
- **`#[must_use]` on builder methods** makes ignoring the returned `self` a warning — it
  catches the "I called `.description(...)` but forgot it returns a new value" mistake
  that trips people used to mutating builders.
- **`#[serde(skip_serializing_if = "Option::is_none", default)]`** on `output_schema`/
  `extra`/`error`/`payer`: omit the key entirely when `None` (not `null`), and default to
  `None` when absent on the way in. The `builder_serializes_expected_keys` and
  `challenge_new_omits_optionals` tests assert the key is *absent*, which matters for
  spec-exact JSON.
- **`rename_all = "camelCase"`** on the structs vs the explicit kebab-case strings in
  `Network`'s `From` impls: field names get cased by the derive (`max_amount_required` →
  `maxAmountRequired`), but the *enum values* are hand-mapped because network slugs like
  `base-sepolia` are kebab, not camel, and don't follow a single mechanical rule.
- **Tuple-struct field access is `self.0`**, and `From<Nonce> for String` is just
  `value.0` — moving the inner string out, no clone, because we own the `Nonce`.

## 7. Check yourself

1. Why does `EvmAddress` use `#[serde(try_from = "String")]` while `Network` uses
   `#[serde(from = "String")]`? What would change on the wire, and in the error
   behavior, if you swapped them?
2. Someone adds `Network::Optimism`. List every file/function that stops compiling, and
   explain why that's the *intended* outcome rather than an annoyance.
3. In the `Network::Unknown(ref s)` arm, delete the `ref`. What's the exact compiler
   error, and which later line triggers it?
4. The `signature` field is a bare `String` while `nonce` is a validated `Nonce`.
   Articulate the principle that justifies validating one and not the other *in M1*.
5. Trace ownership of the input `header: &str` through `decode_payment_header`. At which
   line is the first heap allocation the attacker can influence, and why is the size
   check placed before it?
6. Remove `#[from]` from the `Base64` variant. What breaks, and what's the minimal
   hand-written code that restores the `?`-on-`decode` behavior?

<details>
<summary>Answers</summary>

1. `try_from` makes deserialization *fallible*: a malformed address string fails the
   whole parse (surfacing as `PaymentDecodeError::Malformed`). `from` is *infallible*:
   an unknown network string becomes `Network::Unknown(...)` and parsing succeeds, with
   rejection deferred to the decoder's match. Swapping them would (a) make an unknown
   network a generic "malformed JSON" error, losing the specific `UnsupportedNetwork`
   message and the ability to tolerate-and-log; and (b) make a malformed address
   *deserialize successfully* into some `Unknown`-less type — you'd need a strict enum,
   and there's no natural way, so the swap doesn't even typecheck without also
   redesigning the types. The wire JSON stays a plain string either way.
2. `payment.rs::decode_payment_header`'s `match payload.network` — because it's
   exhaustive with no `_`, `Optimism` is now uncovered → `non-exhaustive patterns`
   compile error. The `From/Into<String>` impls in `types.rs` won't break (they have a
   `_`/`Unknown` fallthrough), and `network_known_variants_round_trip` won't *fail to
   compile* but you'd want to extend it. Intended: the compiler forces a human to decide
   Optimism's support status at the one site where policy lives.
3. `cannot move out of \`payload.network\` … which is behind a shared/owned reference`
   (a partial-move error): matching `Unknown(s)` by value tries to move the `String` out
   of `payload`, and the subsequent `Ok(payload)` at the end of the function then fails
   with "use of partially moved value `payload`". `ref s` borrows instead, so `payload`
   stays whole.
4. "Don't validate what you can't yet meaningfully check." A `Nonce`'s validity is fully
   decidable from its shape (`0x` + 64 hex), so validate it at the boundary. A
   signature's only meaningful validity test is cryptographic recovery (M2); a
   shape-check would give false confidence — accepting most invalid signatures — so M1
   carries it verbatim as `String` and defers the real check.
5. `header: &str` is borrowed, no allocation. First attacker-influenced heap allocation
   is `base64::…decode(header)?` producing `bytes: Vec<u8>` (roughly ¾ the header size).
   The `header.len() > MAX_PAYMENT_HEADER_BYTES` check runs *before* it so an attacker
   can't force a large allocation — you bound the work before doing it. `from_utf8`
   borrows `bytes` (no alloc); `from_str` allocates the owned `PaymentPayload`.
6. Removing `#[from]` deletes the generated `impl From<base64::DecodeError> for
   PaymentDecodeError`, so `?` on `.decode(header)` no longer compiles ("the trait
   `From<DecodeError>` is not implemented"). Minimal fix: write it by hand —
   `impl From<base64::DecodeError> for PaymentDecodeError { fn from(e: base64::DecodeError)
   -> Self { Self::Base64(e) } }` — which is exactly what the attribute generated.

</details>

## 8. Further reading

- Alexis King, *Parse, Don't Validate* — the essay behind the newtype-at-the-boundary
  design: https://lexi-lambda.github.io/blog/2019/11/05/parse-don-t-validate/
- serde container/field attributes (`from`, `try_from`, `rename_all`,
  `skip_serializing_if`): https://serde.rs/container-attrs.html and
  https://serde.rs/field-attrs.html
- `thiserror` crate docs (`#[error]`, `#[from]`, `#[source]`):
  https://docs.rs/thiserror/latest/thiserror/
- The Rust Book, ch. 6 (enums & `match`) and ch. 9 (`Result`, the `?` operator):
  https://doc.rust-lang.org/book/ch06-00-enums.html and
  https://doc.rust-lang.org/book/ch09-00-error-handling.html
