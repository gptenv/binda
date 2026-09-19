//! # binda-core
//!
//! Core types and logic for **BINDA** ("bind10"): a free, self-sovereign,
//! gossip-propagated DNS resolver and naming system intended to make
//! traditional domain registrars unnecessary.
//!
//! This crate is transport- and I/O-agnostic: it defines domain names,
//! client identities, the liveness/registration rules, the gossip message
//! types, the collision-resolution protocol, and the TOML zone file
//! format. The `binda` binary crate wires these into an actual network
//! daemon.
//!
//! ## Model
//!
//! - [`domain`] — Unicode-native domain names (emoji, combining marks,
//!   mixed bidirectional scripts all valid).
//! - [`client`] — a client's identity: an Ed25519 keypair plus RDNS.
//! - [`token`] — the timestamp + random-nonce token issued per
//!   registration.
//! - [`liveness`] — the 1-minute liveness window and 5-domain-per-client
//!   cap that a registration depends on.
//! - [`collision`] — the mutual coin-negotiation protocol used when two
//!   nodes learn of simultaneous claims on the same name.
//! - [`gossip`] — the anti-entropy message types nodes exchange, and the
//!   structural well-formedness check that stands in for a trust decision.
//! - [`store`] — the in-memory registration table that ties the above
//!   together.
//! - [`zone`] — BIND9-equivalent zone data, serialized as TOML.
//! - [`resolver`] — the query/answer types a client uses to resolve a name.
//! - [`wire`] — JSON wire encoding shared by every message type above,
//!   used by the `binda` binary's network transport.
//! - [`client_api`] — signed, replay-resistant requests an end-user client
//!   sends to probe liveness, register a domain, or publish records.
//! - [`api`] — glue applying an authenticated [`client_api::ClientRequest`]
//!   to a [`store::RegistryStore`].
//! - [`ntp`] — an NTP-disciplined [`liveness::TimeSource`].
//! - [`rate_limit`] — a per-key token-bucket limiter, used instead of a
//!   hard message-size cap to throttle abusive senders without punishing
//!   a single large-but-legitimate message.
//! - [`dns`] — BINDA's own name-lookup wire protocol: DNS-shaped framing
//!   (header/question/answer, the same record types) but with UTF-8
//!   labels carried natively on the wire. It is deliberately **not**
//!   RFC 1035 compatible: BINDA exists to make Unicode names a first-class
//!   citizen instead of forcing them through Punycode/IDNA ASCII
//!   compatibility encoding, so this protocol never produces or accepts a
//!   Punycode-encoded label. A legacy DNS resolver cannot speak it, by
//!   design — a translating gateway, if one is ever wanted, is a separate
//!   concern from this protocol's own wire format.

pub mod api;
pub mod client;
pub mod client_api;
pub mod collision;
pub mod dns;
pub mod domain;
pub mod gossip;
pub mod liveness;
pub mod ntp;
pub mod rate_limit;
pub mod resolver;
pub mod store;
pub mod token;
pub mod wire;
pub mod zone;

pub use client::ClientIdentity;
pub use domain::DomainName;
pub use store::RegistryStore;
pub use zone::ZoneFile;
