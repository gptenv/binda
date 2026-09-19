//! Collision arbitration between two BINDA nodes claiming the same domain
//! name on behalf of different clients.
//!
//! Neither side unilaterally decides "higher wins" or "lower wins": each
//! peer independently and randomly proposes a [`WinCondition`] on every
//! round, the two proposals are exchanged, and the *first round where both
//! peers proposed the same condition* is the one that decides the
//! registration — drawing straws, but requiring mutual agreement on which
//! straw is short before it counts.

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::token::RegistrationToken;

/// Which side of the token ordering wins a collision, once agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WinCondition {
    HigherWins,
    LowerWins,
}

impl WinCondition {
    /// Draw a uniformly random proposal for one round.
    pub fn random() -> Self {
        if rand::thread_rng().gen_bool(0.5) {
            WinCondition::HigherWins
        } else {
            WinCondition::LowerWins
        }
    }
}

/// One round's proposal from a single peer during collision negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundProposal {
    pub round: u32,
    pub condition: WinCondition,
}

/// Runs the negotiation from the point of view of a single peer: feed it
/// the peer's own proposals and the counterpart's, round by round, until
/// both sides agree.
#[derive(Debug, Default)]
pub struct Negotiation {
    round: u32,
}

impl Negotiation {
    pub fn new() -> Self {
        Self { round: 0 }
    }

    /// Produce this peer's proposal for the next round.
    pub fn propose(&mut self) -> RoundProposal {
        self.round += 1;
        RoundProposal {
            round: self.round,
            condition: WinCondition::random(),
        }
    }

    /// Given this peer's proposal and the counterpart's for the same
    /// round, decide whether they agree and, if so, on what condition.
    pub fn check_agreement(mine: RoundProposal, theirs: RoundProposal) -> Option<WinCondition> {
        if mine.round == theirs.round && mine.condition == theirs.condition {
            Some(mine.condition)
        } else {
            None
        }
    }
}

/// Given an agreed [`WinCondition`] and the two colliding tokens, return
/// the winning token.
pub fn resolve(
    condition: WinCondition,
    a: RegistrationToken,
    b: RegistrationToken,
) -> RegistrationToken {
    let (key_a, key_b) = (a.raw_ordering_key(), b.raw_ordering_key());
    match condition {
        WinCondition::HigherWins => {
            if key_a >= key_b {
                a
            } else {
                b
            }
        }
        WinCondition::LowerWins => {
            if key_a <= key_b {
                a
            } else {
                b
            }
        }
    }
}

/// Derive the mutually-random collision condition from *both* claims.
///
/// Each registration token contributes an unpredictable nonce, while this
/// symmetric reduction means every replica computes the same outcome from
/// the same pair.  This replaces the old local simulation of two remote
/// coin flips, which could make different gossip recipients retain
/// different winners.
pub fn mutually_derived_condition(a: RegistrationToken, b: RegistrationToken) -> WinCondition {
    let parity = a.nonce.iter().chain(b.nonce.iter()).fold(
        (a.issued_at_millis ^ b.issued_at_millis) as u8,
        |acc, byte| acc ^ byte,
    );
    if parity & 1 == 0 {
        WinCondition::HigherWins
    } else {
        WinCondition::LowerWins
    }
}

/// Resolve a collision in a way every node can reproduce from the two
/// registration tokens alone.
pub fn negotiate_locally(a: RegistrationToken, b: RegistrationToken) -> RegistrationToken {
    resolve(mutually_derived_condition(a, b), a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_terminates_and_is_deterministic_given_agreement() {
        let a = RegistrationToken::issue(1);
        let b = RegistrationToken::issue(2);
        let winner = negotiate_locally(a, b);
        assert!(winner == a || winner == b);
    }

    #[test]
    fn mutually_derived_outcome_is_symmetric_and_convergent() {
        let a = RegistrationToken {
            issued_at_millis: 1,
            nonce: [1; 8],
        };
        let b = RegistrationToken {
            issued_at_millis: 2,
            nonce: [2; 8],
        };
        assert_eq!(
            mutually_derived_condition(a, b),
            mutually_derived_condition(b, a)
        );
        assert_eq!(negotiate_locally(a, b), negotiate_locally(b, a));
    }

    #[test]
    fn resolve_higher_wins_picks_greater_key() {
        let a = RegistrationToken {
            issued_at_millis: 1,
            nonce: [0; 8],
        };
        let b = RegistrationToken {
            issued_at_millis: 2,
            nonce: [0; 8],
        };
        assert_eq!(resolve(WinCondition::HigherWins, a, b), b);
        assert_eq!(resolve(WinCondition::LowerWins, a, b), a);
    }

    #[test]
    fn resolve_is_reflexive_for_equal_tokens() {
        let a = RegistrationToken {
            issued_at_millis: 5,
            nonce: [1; 8],
        };
        assert_eq!(resolve(WinCondition::HigherWins, a, a), a);
        assert_eq!(resolve(WinCondition::LowerWins, a, a), a);
    }

    #[test]
    fn resolve_lower_wins_picks_lesser_key_regardless_of_argument_order() {
        let a = RegistrationToken {
            issued_at_millis: 2,
            nonce: [0; 8],
        };
        let b = RegistrationToken {
            issued_at_millis: 1,
            nonce: [0; 8],
        };
        // a > b here, so LowerWins must pick b even though it's the
        // second argument.
        assert_eq!(resolve(WinCondition::LowerWins, a, b), b);
    }

    #[test]
    fn negotiation_proposals_increment_round() {
        let mut negotiation = Negotiation::new();
        let first = negotiation.propose();
        let second = negotiation.propose();
        assert_eq!(first.round, 1);
        assert_eq!(second.round, 2);
    }

    #[test]
    fn check_agreement_requires_same_round_and_condition() {
        let same_round_same_condition = RoundProposal {
            round: 1,
            condition: WinCondition::HigherWins,
        };
        assert_eq!(
            Negotiation::check_agreement(same_round_same_condition, same_round_same_condition),
            Some(WinCondition::HigherWins)
        );

        let different_condition = RoundProposal {
            round: 1,
            condition: WinCondition::LowerWins,
        };
        assert_eq!(
            Negotiation::check_agreement(same_round_same_condition, different_condition),
            None
        );

        let different_round = RoundProposal {
            round: 2,
            condition: WinCondition::HigherWins,
        };
        assert_eq!(
            Negotiation::check_agreement(same_round_same_condition, different_round),
            None
        );
    }

    #[test]
    fn win_condition_random_produces_both_variants_eventually() {
        let mut saw_higher = false;
        let mut saw_lower = false;
        for _ in 0..200 {
            match WinCondition::random() {
                WinCondition::HigherWins => saw_higher = true,
                WinCondition::LowerWins => saw_lower = true,
            }
            if saw_higher && saw_lower {
                break;
            }
        }
        assert!(saw_higher && saw_lower);
    }
}
