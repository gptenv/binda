# binda (bind10)

[![CI](https://github.com/gptenv/binda/actions/workflows/ci.yml/badge.svg)](https://github.com/gptenv/binda/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/gptenv/binda/branch/main/graph/badge.svg)](https://codecov.io/gh/gptenv/binda)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust: nightly](https://img.shields.io/badge/rust-nightly-orange.svg)](rust-toolchain.toml)

> BINDA is an independent FOSS DNS resolver project. The name is derived
> from hexadecimal notation for "bind10" and is unrelated to any
> commercial brands. It is not affiliated with, endorsed by, or derived
> from the BIND/BIND9 project or ISC (Internet Systems Consortium) —
> BINDA's codebase is entirely independent and unique from that project.

BINDA is a Rust-native DNS resolver and naming system designed to make
traditional domain registrars unnecessary: anyone can register a free
domain name and keep it for as long as they answer a liveliness probe
within a 1-minute window.

- **Free-for-life registration** — a domain stays yours as long as you
  respond to a liveness probe within a minute; miss the window and it
  falls back into the pool. (Originally a stricter 3 seconds; relaxed to
  give room for ordinary reconfiguration downtime.)
- **Squatting resistance** — a maximum of 5 live registrations per client,
  where a client is identified by an Ed25519 signature combined with its
  reverse-DNS hostname. That hostname isn't just asserted: every
  registration is checked with a real, forward-confirmed reverse DNS
  (FCrDNS) lookup against the request's actual source IP — the claimed
  hostname's PTR record must name it, and its A/AAAA record must resolve
  back to that same IP (see
  [`fcrdns`](crates/binda-core/src/fcrdns.rs)) — so the cap applies to a
  real, distinctly-controlled host rather than to a free-to-mint keypair.
- **Full Unicode names, no length limit** — domain labels may use any
  printable Unicode scalar value: emoji, combining-mark ("zalgo")
  sequences, and mixed right-to-left/left-to-right scripts (intermixed
  within a single label, not just adjacent) are all valid. Unlike classic
  DNS's 255-octet/63-byte-label ceiling, there is no length cap at all —
  a name is only as long as available memory and the transport's own
  datagram size allow.
- **Mutual collision arbitration** — when two nodes learn of simultaneous
  claims on the same name, neither unilaterally decides the tie-break rule;
  they each randomly propose "higher wins" or "lower wins" every round
  until they agree, and that agreed rule decides the winner.
- **Gossip propagation** — nodes exchange registration state via
  epidemic/anti-entropy gossip. No node is marked trusted or distrusted;
  every information pull bundles a small behavioural test (a
  [`ConformanceChallenge`](crates/binda-core/src/gossip.rs) — two
  synthetic tokens and a win condition), answerable only by actually
  running BINDA's own deterministic collision-resolution logic, and a
  peer's rumors are adopted only if it answers that correctly. Getting it
  wrong, or being malformed at all, means the same thing either way: for
  that exchange, we assume we're not talking to a real BINDA node and
  ignore everything it sent — with no memory of the failure carried into
  the next exchange.
- **TOML zone files** — the same information a BIND9 zone file carries
  (SOA, records), expressed as TOML.

## Workspace layout

- [`crates/binda-core`](crates/binda-core) — the library crate: domain
  names, client identity, liveness/registration rules, the gossip message
  types, collision resolution, the zone file format, the resolver
  query/answer types, and the JSON wire encoding shared by all of them.
- [`crates/binda`](crates/binda) — the `binda` binary crate: a UDP gossip
  daemon plus a UDP resolver query daemon built on top of `binda-core`.

## Building

Requires Rust nightly (see `rust-toolchain.toml`).

```bash
cargo build --workspace
cargo test --workspace
cargo doc --workspace --no-deps --open
```

### Test coverage

Coverage is measured with [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)
and reported to [Codecov](https://codecov.io/gh/gptenv/binda) on every push
via [`.github/workflows/coverage.yml`](.github/workflows/coverage.yml) (the
badge above needs a `CODECOV_TOKEN` repository secret to actually upload —
add one from codecov.io's project settings for it to go live). To check
locally:

```bash
cargo install cargo-llvm-cov  # once
cargo llvm-cov --workspace --summary-only   # terminal summary
cargo llvm-cov --workspace --html --open    # browsable per-line report
```

## Running a node

```bash
binda --gossip 0.0.0.0:9530 --resolver 0.0.0.0:9531 --api 0.0.0.0:9532 \
      [--dns 0.0.0.0:9533] [--peer <host:port> ...]
```

- `--gossip` — UDP address to listen on for anti-entropy gossip with peers.
- `--resolver` — UDP address to listen on for BINDA's own
  `ResolveQuery`/`ResolveAnswer` lookups.
- `--api` — UDP address to listen on for the client-facing registration
  API: signed `Probe` / `Register` / `SetRecords` requests (see
  [`client_api`](crates/binda-core/src/client_api.rs)).
- `--dns` — optional UDP address to also speak BINDA's own native,
  DNS-shaped name-lookup protocol on (see
  [`dns`](crates/binda-core/src/dns.rs)): same message framing as classic
  DNS, but every label is raw UTF-8 on the wire. It is **not** RFC 1035
  wire-compatible and never produces or accepts Punycode/ASCII-compatible
  encoding — that translation step is exactly what BINDA exists to make
  unnecessary. Omit the flag to skip this listener entirely.
- `--peer` — a known peer's gossip address; repeatable. Peers also learn
  about each other dynamically from inbound gossip, so only one bootstrap
  peer per new node is typically needed.

A node's clock is disciplined against public NTP servers
([`ntp::NtpTimeSource`](crates/binda-core/src/ntp.rs)) rather than trusting
the raw local clock, since the whole liveness model depends on every node
agreeing on roughly the same time.

See [`examples/client_demo.rs`](crates/binda/examples/client_demo.rs) for
a full walkthrough of a client: probe liveness, register a Unicode
domain, publish an A record, then resolve it both via BINDA's own
resolver protocol and via BINDA's native, DNS-shaped protocol — proving
the label crosses the wire as raw UTF-8, not Punycode.

```bash
cargo run -p binda --bin binda -- --gossip 127.0.0.1:9530 --resolver 127.0.0.1:9531 --api 127.0.0.1:9532 --dns 127.0.0.1:9533 &
cargo run -p binda --example client_demo
```

## Status

Core registration, liveness, collision, gossip, zone-file, client API,
NTP time, and native DNS-shaped wire-protocol types are implemented and
unit-tested, and networking is wired up end-to-end: nodes gossip via UDP
anti-entropy digests, and clients can probe/register/publish records over
the client API and resolve via either BINDA's own JSON resolver protocol
or its native DNS-shaped protocol — both fully Unicode-native, with no
Punycode/ASCII-compatibility step anywhere in BINDA. Overall test coverage
sits at ~98% (line/region across the whole workspace, 142 + 25 = 167
tests), including real end-to-end integration tests for the gossip
conformance-challenge protocol (a rogue peer answering incorrectly, a
peer answering correctly, and full convergence between two real nodes
over UDP), local fake-server tests exercising the actual network code
paths of NTP sync and FCrDNS verification without needing real internet
access, and coverage of every listener's bind-failure path. `main()`
itself is excluded from the coverage count (`#[coverage(off)]`) since
it's pure top-level wiring around already-covered pieces and, by design,
never returns in a real run.

Still missing/simplified, in rough priority order:

- The native DNS-shaped codec supports A/AAAA/CNAME/MX/TXT/NS over a
  single question, no compression on the way in, no EDNS0, no zone
  transfers, and — being intentionally not RFC 1035 compatible — no
  interoperability with legacy DNS resolvers (a translating gateway, if
  ever wanted, would be a separate, optional component).
- Gossip's "is this rumor newer" check compares timestamps only; it
  doesn't yet re-run collision resolution for rumors with an *equal or
  older* timestamp than a differing local claim, so some collisions only
  resolve one node at a time as digests keep exchanging.
- No persistence: every node's registry is purely in-memory and starts
  empty on restart, by design ("temporary... in-memory datastore"), but
  there's no snapshot/replay to speed up rejoining a network either.
- Every UDP listener (gossip, resolver, client API, native name-lookup)
  is now rate-limited per source address via a token bucket (see
  [`rate_limit`](crates/binda-core/src/rate_limit.rs)) rather than a hard
  message-size cap — a deliberate choice so a single large-but-legitimate
  message (an extravagant zalgo name, say) is never penalized, while a
  sender flooding a listener gets throttled. `MAX_DATAGRAM_BYTES` still
  exists, but only as the actual physical UDP payload ceiling
  (65,507 bytes), not a policy limit. Source addresses are still
  spoofable, so this doesn't stop a distributed flood; it's a first line
  of defense, not the whole story.
- The remaining ~2% is essentially irreducible without contrived tests:
  a handful of `node.rs` lines are the "kick off an infinite listener
  loop" statements inside tests that intentionally never let that loop
  finish (so the async state machine's completion path is never counted,
  even though the loop's real behavior is thoroughly exercised via real
  socket round-trips elsewhere in the same test); a couple of `fcrdns`/
  `ntp` lines are a test-helper's own defensive error arm that only fires
  if a background thread's socket read fails after the test has already
  gotten what it needed; and a few are error variants (like a JSON
  encode failure) that aren't reachable through this project's own types
  without constructing a deliberately-broken value.
