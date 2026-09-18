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
  types, collision resolution, and the zone file format.
- [`crates/binda`](crates/binda) — the `binda` binary crate.

## Building

Requires Rust nightly (see `rust-toolchain.toml`).

```bash
cargo build --workspace
cargo test --workspace
cargo doc --workspace --no-deps --open
```

## Status

Early scaffold. The core registration, liveness, collision, gossip, and
zone-file types are implemented and unit-tested; the network transport
(actual gossip wire protocol and resolver query handling) is not yet
wired up.
