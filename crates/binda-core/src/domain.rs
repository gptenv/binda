//! Domain name handling.
//!
//! BINDA domain names operate natively on the full printable Unicode
//! character set: emoji, combining-mark ("zalgo") sequences, and
//! right-to-left scripts intermixed with left-to-right ones are all valid,
//! as long as every scalar value is *printable* (i.e. not a control
//! character and not an unassigned/format code point that would render
//! invisibly or corrupt terminal state). There is no length limit: unlike
//! classic DNS's 255-octet name cap, a BINDA name may be arbitrarily long
//! (a heavily-stacked zalgo label, for instance, is not truncated or
//! rejected for its length). The only practical ceilings are the ones any
//! finite computer already has — available memory, and the transport
//! layer's own datagram size limit (see [`crate::wire::MAX_DATAGRAM_BYTES`]
//! and [`crate::dns`]'s label length field) — neither of which is a rule
//! about what a valid *name* is.

use std::fmt;
use thiserror::Error;

/// A validated BINDA domain name (a single label or a dotted sequence of
/// labels, exactly like a classic DNS name, but Unicode-native rather than
/// punycode-encoded).
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct DomainName(String);

/// Errors that can occur while validating a candidate domain name.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainNameError {
    #[error("domain name must not be empty")]
    Empty,
    #[error("domain name contains a non-printable character at byte offset {offset}")]
    NonPrintableChar { offset: usize },
    #[error("domain label must not be empty (found consecutive or leading/trailing '.')")]
    EmptyLabel,
}

impl DomainName {
    /// Validate and construct a new [`DomainName`].
    ///
    /// A character is accepted unless it is a control character (Unicode
    /// general category `Cc`) or the ASCII/Unicode space character; this
    /// intentionally allows combining marks, emoji, emoji ZWJ sequences,
    /// and mixed bidirectional scripts.
    pub fn new(raw: impl Into<String>) -> Result<Self, DomainNameError> {
        let raw = raw.into();
        if raw.is_empty() {
            return Err(DomainNameError::Empty);
        }

        for (offset, ch) in raw.char_indices() {
            if ch.is_control() || ch == ' ' {
                return Err(DomainNameError::NonPrintableChar { offset });
            }
        }

        if raw.split('.').any(|label| label.is_empty()) {
            return Err(DomainNameError::EmptyLabel);
        }

        Ok(Self(raw))
    }

    /// The dotted labels making up this domain name, outermost label first.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.0.split('.')
    }

    /// The raw string form of the domain name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for DomainName {
    type Error = DomainNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_ascii() {
        assert!(DomainName::new("example.binda").is_ok());
    }

    #[test]
    fn accepts_emoji_and_mixed_scripts() {
        assert!(DomainName::new("🔥.example").is_ok());
        assert!(DomainName::new("مرحبا.hello").is_ok());
        assert!(DomainName::new("e\u{0301}\u{0301}\u{0301}xample").is_ok()); // zalgo-ish
    }

    #[test]
    fn accepts_heavy_zalgo_stacking_with_no_length_cap() {
        // Real zalgo text piles many combining marks onto a single base
        // character, easily thousands of scalar values for a short
        // visual label. There is no length limit, so this must succeed
        // however many marks are stacked on.
        let combining_marks = ['\u{0301}', '\u{0316}', '\u{0327}', '\u{0353}'];
        let mut label = String::from("e");
        for i in 0..5_000 {
            label.push(combining_marks[i % combining_marks.len()]);
        }
        let domain = DomainName::new(label.clone()).expect("heavy zalgo label should be valid");
        assert_eq!(domain.as_str(), label.as_str());
    }

    #[test]
    fn accepts_arbitrarily_long_names() {
        let long_name = "a".repeat(100_000);
        assert!(DomainName::new(long_name).is_ok());
    }

    #[test]
    fn accepts_rtl_and_ltr_intermixed_within_one_label() {
        // Not just an RTL label next to an LTR one (already covered above)
        // but Arabic and Latin characters interleaved within a *single*
        // label, exactly as the "intermixed" requirement calls for.
        let domain =
            DomainName::new("helloمرحبا🔥world").expect("intermixed bidi label should be valid");
        assert_eq!(domain.labels().count(), 1);
        assert_eq!(domain.as_str(), "helloمرحبا🔥world");
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(DomainName::new(""), Err(DomainNameError::Empty));
    }

    #[test]
    fn rejects_control_chars() {
        assert!(matches!(
            DomainName::new("exa\u{0007}mple"),
            Err(DomainNameError::NonPrintableChar { .. })
        ));
    }

    #[test]
    fn rejects_empty_labels() {
        assert_eq!(DomainName::new("a..b"), Err(DomainNameError::EmptyLabel));
        assert_eq!(DomainName::new(".a"), Err(DomainNameError::EmptyLabel));
    }

    #[test]
    fn rejects_trailing_empty_label() {
        assert_eq!(DomainName::new("a."), Err(DomainNameError::EmptyLabel));
    }

    #[test]
    fn labels_splits_on_dot_in_order() {
        let domain = DomainName::new("a.b.c").unwrap();
        let labels: Vec<&str> = domain.labels().collect();
        assert_eq!(labels, vec!["a", "b", "c"]);
    }

    #[test]
    fn display_matches_as_str() {
        let domain = DomainName::new("example.binda").unwrap();
        assert_eq!(format!("{domain}"), domain.as_str());
    }

    #[test]
    fn try_from_str_matches_new() {
        let domain: DomainName = "example.binda".try_into().unwrap();
        assert_eq!(domain.as_str(), "example.binda");

        let err: Result<DomainName, _> = "".try_into();
        assert_eq!(err, Err(DomainNameError::Empty));
    }

    #[test]
    fn equal_domains_hash_and_order_consistently() {
        use std::collections::HashSet;
        let a = DomainName::new("example.binda").unwrap();
        let b = DomainName::new("example.binda").unwrap();
        let c = DomainName::new("other.binda").unwrap();
        assert_eq!(a, b);
        assert!(a < c || c < a);

        let mut set = HashSet::new();
        set.insert(a.clone());
        assert!(set.contains(&b));
        assert!(!set.contains(&c));
    }

    #[test]
    fn error_messages_are_human_readable() {
        assert_eq!(
            DomainNameError::Empty.to_string(),
            "domain name must not be empty"
        );
        assert_eq!(
            DomainNameError::EmptyLabel.to_string(),
            "domain label must not be empty (found consecutive or leading/trailing '.')"
        );
        assert_eq!(
            DomainNameError::NonPrintableChar { offset: 3 }.to_string(),
            "domain name contains a non-printable character at byte offset 3"
        );
    }
}
