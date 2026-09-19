//! Gossip-based (epidemic anti-entropy) propagation between BINDA nodes.
//!
//! Nodes never mark a peer as "trusted" or "distrusted" — they simply
//! test each other for correct BINDA behaviour on every exchange, and if
//! that test fails, they assume they aren't actually talking to a BINDA
//! node and ignore the information exchange *for that exchange only*. A
//! later attempt from the same address is judged entirely on its own
//! merits, with no memory of the earlier failure.
//!
//! The test is not merely "did the message parse and stay within size
//! bounds" (that's [`is_well_formed`], and it's necessary but not
//! sufficient). Gossip also enforces the request/response contract: a
//! response may contain each requested domain at most once, and may not
//! smuggle in an unrequested domain. Finally, every
//! [`GossipMessage::Request`] carries a
//! [`ConformanceChallenge`]: two synthetic registration tokens and a win
//! condition. Real BINDA behaviour is a fully specified, deterministic
//! function of that input (the same [`crate::collision::resolve`] every
//! node runs to settle a real collision), so a peer answering a
//! [`GossipMessage::Rumors`] must include the correct
//! [`ConformanceChallenge::expected_answer`] alongside the rumors it's
//! offering. Getting that answer wrong — or leaving it out — is the same
//! signal as a malformed message: this exchange's data is dropped,
//! unconditionally, whether or not the rumors themselves look plausible.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::collision::{resolve, WinCondition};
use crate::domain::DomainName;
use crate::token::RegistrationToken;

/// A single fact a node can gossip about: a domain's current registration
/// state, as of a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationRumor {
    pub domain: DomainName,
    pub token: RegistrationToken,
    pub client_key: String,
}

/// A behavioural test bundled into a [`GossipMessage::Request`]: answering
/// it correctly requires actually running BINDA's own deterministic
/// collision-resolution logic, not just echoing well-formed JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceChallenge {
    pub token_a: RegistrationToken,
    pub token_b: RegistrationToken,
    pub condition: WinCondition,
}

impl ConformanceChallenge {
    /// Generate a fresh, unpredictable challenge for one gossip round.
    /// Each round gets its own, so an answer can't be recorded and
    /// replayed for a later round.
    pub fn random(issued_at_millis: u64) -> Self {
        Self {
            token_a: RegistrationToken::issue(issued_at_millis),
            token_b: RegistrationToken::issue(issued_at_millis),
            condition: WinCondition::random(),
        }
    }

    /// The one correct answer to this challenge: whichever token
    /// [`crate::collision::resolve`] declares the winner under this
    /// challenge's condition.
    pub fn expected_answer(&self) -> RegistrationToken {
        resolve(self.condition, self.token_a, self.token_b)
    }
}

/// Messages exchanged between BINDA peers during anti-entropy gossip
/// rounds. This is deliberately a small, closed set, but — unlike a
/// scheme that judges peers on message shape alone — a
/// [`GossipMessage::Rumors`] reply is only ever trusted alongside proof
/// (a correct [`ConformanceChallenge`] answer) that the sender actually
/// runs BINDA's protocol logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipMessage {
    /// "Here is a digest of what I know" — a peer announces the rumors it
    /// holds so the recipient can request only what it's missing.
    Digest { rumors: Vec<DigestEntry> },
    /// "Send me the full rumor for these domains," plus a behavioural
    /// test the responder must pass for its answer to be believed.
    Request {
        domains: Vec<DomainName>,
        challenge: ConformanceChallenge,
    },
    /// The full rumor payload answering a [`GossipMessage::Request`],
    /// together with that request's `challenge` answered correctly. A
    /// missing or incorrect `challenge_answer` means the rumors are
    /// discarded regardless of how plausible they look.
    Rumors {
        rumors: Vec<RegistrationRumor>,
        challenge_answer: RegistrationToken,
    },
}

/// A lightweight summary of one rumor, exchanged before the full payload
/// so peers don't re-send data the recipient already has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestEntry {
    pub domain: DomainName,
    pub issued_at_millis: u64,
}

/// A minimal behavioural check a node runs against every message it
/// receives before acting on it, standing in for a trust decision.
///
/// This is intentionally structural, not reputation-based: a node that
/// gossips one malformed message isn't blacklisted, it's simply ignored
/// *for that message*.
pub fn is_well_formed(message: &GossipMessage) -> bool {
    match message {
        GossipMessage::Digest { rumors } => {
            rumors.len() <= MAX_DIGEST_ENTRIES && unique_domains(rumors.iter().map(|r| &r.domain))
        }
        GossipMessage::Request { domains, .. } => {
            domains.len() <= MAX_REQUEST_ENTRIES && unique_domains(domains.iter())
        }
        GossipMessage::Rumors { rumors, .. } => {
            rumors.len() <= MAX_DIGEST_ENTRIES && unique_domains(rumors.iter().map(|r| &r.domain))
        }
    }
}

/// Check the semantic part of a gossip response: a peer may answer only for
/// domains that were requested, and at most once for each requested domain.
/// The caller still has to authenticate the exchange with the outstanding
/// [`ConformanceChallenge`] before applying the returned facts.
pub fn is_valid_rumor_response(requested: &[DomainName], rumors: &[RegistrationRumor]) -> bool {
    let requested: HashSet<&DomainName> = requested.iter().collect();
    rumors
        .iter()
        .map(|rumor| &rumor.domain)
        .all(|domain| requested.contains(domain))
        && unique_domains(rumors.iter().map(|rumor| &rumor.domain))
}

fn unique_domains<'a>(mut domains: impl Iterator<Item = &'a DomainName>) -> bool {
    let mut seen = HashSet::new();
    domains.all(|domain| seen.insert(domain))
}

/// Upper bound on how many entries a single digest or rumor batch may
/// carry, so a malformed/hostile peer can't force unbounded allocation.
pub const MAX_DIGEST_ENTRIES: usize = 4096;

/// Upper bound on how many domains may appear in a single request.
pub const MAX_REQUEST_ENTRIES: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_digest_is_rejected() {
        let rumors = (0..MAX_DIGEST_ENTRIES + 1)
            .map(|i| DigestEntry {
                domain: DomainName::new(format!("d{i}.binda")).unwrap(),
                issued_at_millis: 0,
            })
            .collect();
        let msg = GossipMessage::Digest { rumors };
        assert!(!is_well_formed(&msg));
    }

    #[test]
    fn normal_digest_is_accepted() {
        let msg = GossipMessage::Digest {
            rumors: vec![DigestEntry {
                domain: DomainName::new("example.binda").unwrap(),
                issued_at_millis: 0,
            }],
        };
        assert!(is_well_formed(&msg));
    }

    #[test]
    fn oversized_request_is_rejected() {
        let domains = (0..MAX_REQUEST_ENTRIES + 1)
            .map(|i| DomainName::new(format!("d{i}.binda")).unwrap())
            .collect();
        let msg = GossipMessage::Request {
            domains,
            challenge: ConformanceChallenge::random(0),
        };
        assert!(!is_well_formed(&msg));
    }

    #[test]
    fn normal_request_is_accepted() {
        let msg = GossipMessage::Request {
            domains: vec![DomainName::new("example.binda").unwrap()],
            challenge: ConformanceChallenge::random(0),
        };
        assert!(is_well_formed(&msg));
    }

    #[test]
    fn oversized_rumors_is_rejected() {
        let rumors = (0..MAX_DIGEST_ENTRIES + 1)
            .map(|i| RegistrationRumor {
                domain: DomainName::new(format!("d{i}.binda")).unwrap(),
                token: RegistrationToken::issue(0),
                client_key: "someone".to_string(),
            })
            .collect();
        let msg = GossipMessage::Rumors {
            rumors,
            challenge_answer: RegistrationToken::issue(0),
        };
        assert!(!is_well_formed(&msg));
    }

    #[test]
    fn normal_rumors_is_accepted() {
        let msg = GossipMessage::Rumors {
            rumors: vec![RegistrationRumor {
                domain: DomainName::new("example.binda").unwrap(),
                token: RegistrationToken::issue(0),
                client_key: "someone".to_string(),
            }],
            challenge_answer: RegistrationToken::issue(0),
        };
        assert!(is_well_formed(&msg));
    }

    #[test]
    fn duplicate_domains_are_not_well_formed() {
        let domain = DomainName::new("example.binda").unwrap();
        let digest = GossipMessage::Digest {
            rumors: vec![
                DigestEntry {
                    domain: domain.clone(),
                    issued_at_millis: 1,
                },
                DigestEntry {
                    domain,
                    issued_at_millis: 2,
                },
            ],
        };
        assert!(!is_well_formed(&digest));
    }

    #[test]
    fn rumor_response_must_be_request_scoped_and_unique() {
        let requested = vec![DomainName::new("requested.binda").unwrap()];
        let token = RegistrationToken::issue(1);
        let valid = vec![RegistrationRumor {
            domain: requested[0].clone(),
            token,
            client_key: "client".into(),
        }];
        assert!(is_valid_rumor_response(&requested, &valid));

        let unrequested = vec![RegistrationRumor {
            domain: DomainName::new("unrequested.binda").unwrap(),
            token,
            client_key: "client".into(),
        }];
        assert!(!is_valid_rumor_response(&requested, &unrequested));

        let duplicate = vec![valid[0].clone(), valid[0].clone()];
        assert!(!is_valid_rumor_response(&requested, &duplicate));
    }

    #[test]
    fn conformance_challenge_has_exactly_one_correct_answer() {
        let challenge = ConformanceChallenge::random(1_000);
        let answer = challenge.expected_answer();
        assert!(answer == challenge.token_a || answer == challenge.token_b);

        // Recomputing independently (as a real BINDA node would, to
        // check a peer's claimed answer) must land on the same token.
        let recomputed = resolve(challenge.condition, challenge.token_a, challenge.token_b);
        assert_eq!(answer, recomputed);
    }

    #[test]
    fn wrong_challenge_answer_is_distinguishable_from_correct() {
        // Run enough rounds that the correct answer lands on token_a at
        // least once and on token_b at least once, exercising both arms
        // of picking "the other one" deterministically rather than
        // leaving it to which way a single random challenge happened to
        // fall.
        let mut saw_a_correct = false;
        let mut saw_b_correct = false;
        for i in 0..200 {
            let challenge = ConformanceChallenge::random(i);
            let correct = challenge.expected_answer();
            let wrong = if correct == challenge.token_a {
                saw_a_correct = true;
                challenge.token_b
            } else {
                saw_b_correct = true;
                challenge.token_a
            };
            assert_ne!(correct, wrong);
            if saw_a_correct && saw_b_correct {
                break;
            }
        }
        assert!(saw_a_correct && saw_b_correct);
    }
}
