# binda (bind10)

BINDA is a Rust-native DNS resolver and naming system designed to make
traditional domain registrars unnecessary: anyone can register a free
domain name and keep it for as long as they answer a liveliness probe
within a 3-second window.

- **Free-for-life registration** — a domain stays yours as long as you
  respond to a liveness probe within 3 seconds; miss the window and it
  falls back into the pool.
- **Squatting resistance** — a maximum of 5 live registrations per client,
  where a client is identified by an Ed25519 signature combined with its
  reverse-DNS hostname.
- **Full Unicode names** — domain labels may use any printable Unicode
  scalar value: emoji, combining-mark ("zalgo") sequences, and mixed
  right-to-left/left-to-right scripts are all valid.
- **Mutual collision arbitration** — when two nodes learn of simultaneous
  claims on the same name, neither unilaterally decides the tie-break rule;
  they each randomly propose "higher wins" or "lower wins" every round
  until they agree, and that agreed rule decides the winner.
- **Gossip propagation** — nodes exchange registration state via
  epidemic/anti-entropy gossip. No node is marked trusted or distrusted;
  each message is judged on whether it is well-formed BINDA protocol, and
  malformed messages are simply ignored for that exchange.
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
- `--dns` — optional UDP address to also speak real RFC 1035 DNS wire
  format on, so legacy resolvers can query BINDA directly (omit to skip
  it; a production deployment would bind this to port 53).
- `--peer` — a known peer's gossip address; repeatable. Peers also learn
  about each other dynamically from inbound gossip, so only one bootstrap
  peer per new node is typically needed.

A node's clock is disciplined against public NTP servers
([`ntp::NtpTimeSource`](crates/binda-core/src/ntp.rs)) rather than trusting
the raw local clock, since the whole liveness model depends on every node
agreeing on roughly the same time.

See [`examples/client_demo.rs`](crates/binda/examples/client_demo.rs) for
a full walkthrough of a client: probe liveness, register a domain,
publish an A record, then resolve it both via BINDA's own protocol and
via a real DNS query.

```bash
cargo run -p binda --bin binda -- --gossip 127.0.0.1:9530 --resolver 127.0.0.1:9531 --api 127.0.0.1:9532 --dns 127.0.0.1:9533 &
cargo run -p binda --example client_demo
```

## Status

Core registration, liveness, collision, gossip, zone-file, client API,
NTP time, and RFC1035/punycode wire-compatibility types are implemented
and unit-tested, and networking is wired up end-to-end: nodes gossip via
UDP anti-entropy digests, and clients can probe/register/publish records
over the client API and resolve via either BINDA's own protocol or real
DNS wire format.

Still missing/simplified, in rough priority order:

- The DNS codec supports A/AAAA/CNAME/MX/TXT/NS over a single question,
  no compression on the way in, no EDNS0, no zone transfers.
- Gossip's "is this rumor newer" check compares timestamps only; it
  doesn't yet re-run collision resolution for rumors with an *equal or
  older* timestamp than a differing local claim, so some collisions only
  resolve one node at a time as digests keep exchanging.
- No persistence: every node's registry is purely in-memory and starts
  empty on restart, by design ("temporary... in-memory datastore"), but
  there's no snapshot/replay to speed up rejoining a network either.
- No rate limiting or proof-of-work on the client API or DNS listeners
  beyond the per-client registration cap; a network-facing deployment
  would want to add some before being exposed to the open internet.
