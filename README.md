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
binda --gossip 0.0.0.0:9530 --resolver 0.0.0.0:9531 [--peer <host:port> ...]
```

- `--gossip` — UDP address to listen on for anti-entropy gossip with peers.
- `--resolver` — UDP address to listen on for `ResolveQuery`/`ResolveAnswer`
  lookups (a simplified, non-RFC1035 protocol; real DNS wire compatibility
  is future work).
- `--peer` — a known peer's gossip address; repeatable. Peers also learn
  about each other dynamically from inbound gossip, so only one bootstrap
  peer per new node is typically needed.

On startup a node self-registers a demo domain (`example.binda`) so a
freshly booted pair of nodes has something to gossip and resolve
immediately; that stand-in will be replaced by a real client-facing
registration API.

## Status

Early scaffold. Core registration, liveness, collision, gossip, and
zone-file types are implemented and unit-tested. Networking is now wired
up: nodes gossip via UDP anti-entropy digests and answer resolver queries
over a separate UDP socket. Still missing: a client-facing registration
API (registration is currently only exercised via the demo code in
`main.rs`), NTP-verified liveness (the daemon currently trusts the local
system clock), and real RFC1035 DNS wire compatibility.
