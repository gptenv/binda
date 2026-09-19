//! The (simplified, non-RFC1035) query/answer protocol a client speaks to
//! a BINDA node to resolve a domain name.
//!
//! This is intentionally not wire-compatible with classic DNS packets;
//! it exists so the resolver half of a node has something concrete to
//! serve while the project decides whether to also speak real DNS on
//! port 53 for legacy client compatibility.

use serde::{Deserialize, Serialize};

use crate::domain::DomainName;
use crate::zone::Record;

/// A request to resolve `domain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveQuery {
    pub domain: DomainName,
}

/// The answer to a [`ResolveQuery`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveAnswer {
    /// `None` if the domain is not currently registered anywhere this
    /// node knows about.
    pub owner_client_key: Option<String>,
    pub records: Vec<Record>,
}
