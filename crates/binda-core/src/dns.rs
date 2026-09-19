//! BINDA's native name-lookup wire protocol.
//!
//! This reuses DNS's familiar message shape — a fixed header, a question
//! section, an answer section built from the same handful of record types
//! (A/AAAA/CNAME/MX/TXT/NS) — because that shape is a well-understood,
//! efficient design, not because this protocol is trying to interoperate
//! with RFC 1035 wire traffic. It deliberately is **not** RFC 1035
//! compatible: every domain label is carried as its raw UTF-8 bytes,
//! never as ASCII, and never as Punycode/IDNA ACE (`xn--...`). BINDA's
//! reason to exist is to make Unicode names first-class instead of
//! routing them through an ASCII-compatibility encoding, so this codec
//! has no code path that produces or accepts one. A legacy DNS resolver
//! cannot parse this protocol's messages, and that is intentional; a
//! translating gateway (if one is ever built) is a separate, optional
//! component layered on top, not part of this wire format.
//!
//! Unlike classic DNS, a label here is **not** capped at 63 bytes and a
//! full name is **not** capped at 255 bytes: each label is prefixed by a
//! 4-byte big-endian length rather than DNS's single length byte (whose
//! top two bits are reserved for compression pointers), so there is no
//! structural ceiling on how long a name — however extravagantly a zalgo
//! label stacks combining marks — can be. Answer names are always
//! re-encoded in full rather than using a DNS-style compression pointer
//! back to the question, since that trick only existed to save bytes
//! within a scheme this protocol has already abandoned. The only limits
//! left are the ones nothing gets around: available memory, and the
//! transport's own datagram size cap (see
//! [`crate::wire::MAX_DATAGRAM_BYTES`]).
//!
//! Scope: single-question queries, no message compression. EDNS0,
//! multi-question messages, and zone transfer opcodes are not supported.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use thiserror::Error;

use crate::domain::DomainName;
use crate::zone::{Record, RecordType};

/// Resource record TYPE values, reusing the standard DNS assignments
/// purely so the numbers are already meaningful to anyone who knows DNS —
/// this protocol does not otherwise follow RFC 1035.
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
/// QTYPE meaning "any type".
const QTYPE_ANY: u16 = 255;

const CLASS_IN: u16 = 1;

/// RCODE 3, "Name Error": the queried domain does not exist at all.
const RCODE_NXDOMAIN: u16 = 3;
/// RCODE 1, "Format Error": the request itself was malformed.
const RCODE_FORMERR: u16 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("message shorter than a header")]
    TooShort,
    #[error("message does not contain exactly one question")]
    UnsupportedQuestionCount,
    #[error("malformed domain name label in message")]
    MalformedLabel,
    #[error("label is not valid UTF-8")]
    InvalidUtf8,
    #[error("decoded domain name is invalid: {0}")]
    InvalidDomain(#[from] crate::domain::DomainNameError),
}

/// A parsed incoming query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: DomainName,
    pub qtype: u16,
    pub qclass: u16,
}

fn record_type_code(record_type: RecordType) -> u16 {
    match record_type {
        RecordType::A => TYPE_A,
        RecordType::Aaaa => TYPE_AAAA,
        RecordType::Cname => TYPE_CNAME,
        RecordType::Mx => TYPE_MX,
        RecordType::Txt => TYPE_TXT,
        RecordType::Ns => TYPE_NS,
    }
}

fn read_u16(bytes: &[u8], pos: usize) -> Result<u16, DnsError> {
    let slice: [u8; 2] = bytes
        .get(pos..pos + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or(DnsError::MalformedLabel)?;
    Ok(u16::from_be_bytes(slice))
}

fn read_u32(bytes: &[u8], pos: usize) -> Result<u32, DnsError> {
    let slice: [u8; 4] = bytes
        .get(pos..pos + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(DnsError::MalformedLabel)?;
    Ok(u32::from_be_bytes(slice))
}

/// Parse the question section out of a raw incoming message. Each label is
/// a 4-byte length followed by that many raw UTF-8 bytes — never Punycode,
/// and never capped at DNS's 63-byte label limit.
pub fn parse_query(bytes: &[u8]) -> Result<DnsQuery, DnsError> {
    if bytes.len() < 12 {
        return Err(DnsError::TooShort);
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    if qdcount != 1 {
        return Err(DnsError::UnsupportedQuestionCount);
    }

    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let len = read_u32(bytes, pos)? as usize;
        pos += 4;
        if len == 0 {
            break;
        }
        let label_bytes = bytes.get(pos..pos + len).ok_or(DnsError::MalformedLabel)?;
        let label = std::str::from_utf8(label_bytes).map_err(|_| DnsError::InvalidUtf8)?;
        labels.push(label.to_string());
        pos += len;
    }

    let qtype = read_u16(bytes, pos)?;
    pos += 2;
    let qclass = read_u16(bytes, pos)?;

    let domain = DomainName::new(labels.join("."))?;
    Ok(DnsQuery { id, domain, qtype, qclass })
}

fn encode_domain_labels(domain: &DomainName, out: &mut Vec<u8>) {
    for label in domain.labels() {
        let bytes = label.as_bytes();
        out.extend((bytes.len() as u32).to_be_bytes());
        out.extend(bytes);
    }
    out.extend(0u32.to_be_bytes());
}

fn encode_rdata(record: &Record) -> Result<Vec<u8>, DnsError> {
    match record.record_type {
        RecordType::A => {
            let addr = Ipv4Addr::from_str(&record.value).map_err(|_| DnsError::MalformedLabel)?;
            Ok(addr.octets().to_vec())
        }
        RecordType::Aaaa => {
            let addr = Ipv6Addr::from_str(&record.value).map_err(|_| DnsError::MalformedLabel)?;
            Ok(addr.octets().to_vec())
        }
        RecordType::Cname | RecordType::Ns => {
            let target = DomainName::new(record.value.clone())?;
            let mut buf = Vec::new();
            encode_domain_labels(&target, &mut buf);
            Ok(buf)
        }
        RecordType::Mx => {
            let (preference, exchange) = record
                .value
                .split_once(' ')
                .and_then(|(p, e)| p.parse::<u16>().ok().map(|p| (p, e)))
                .unwrap_or((0, record.value.as_str()));
            let target = DomainName::new(exchange)?;
            let mut buf = preference.to_be_bytes().to_vec();
            encode_domain_labels(&target, &mut buf);
            Ok(buf)
        }
        RecordType::Txt => {
            let mut buf = Vec::new();
            for chunk in record.value.as_bytes().chunks(255) {
                buf.push(chunk.len() as u8);
                buf.extend(chunk);
            }
            Ok(buf)
        }
    }
}

/// Build a response for `query`.
///
/// - `domain_exists`: whether the queried domain has any registration at
///   all (drives NXDOMAIN vs. an empty NOERROR answer).
/// - `matching`: the records to return, already filtered to those whose
///   type matches the query's QTYPE (or all of them, for QTYPE `ANY`).
pub fn build_response(query: &DnsQuery, domain_exists: bool, matching: &[Record]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend(query.id.to_be_bytes());

    let rcode: u16 = if !domain_exists { RCODE_NXDOMAIN } else { 0 };
    // QR=1 (response), Opcode=0 (query), AA=1 (we are authoritative for
    // names we hold), TC=0, RD=0, RA=0, RCODE as computed above.
    let flags: u16 = 0x8400 | rcode;
    out.extend(flags.to_be_bytes());

    out.extend(1u16.to_be_bytes()); // QDCOUNT
    out.extend((matching.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend(0u16.to_be_bytes()); // NSCOUNT
    out.extend(0u16.to_be_bytes()); // ARCOUNT

    // Echo the question section verbatim.
    encode_domain_labels(&query.domain, &mut out);
    out.extend(query.qtype.to_be_bytes());
    out.extend(query.qclass.to_be_bytes());

    for record in matching {
        // Always re-encode the name in full, rather than a DNS-style
        // compression pointer back to the question — that trick only
        // ever existed to save bytes within a length scheme this
        // protocol doesn't use.
        encode_domain_labels(&query.domain, &mut out);
        out.extend(record_type_code(record.record_type).to_be_bytes());
        out.extend(CLASS_IN.to_be_bytes());
        out.extend(record.ttl_secs.to_be_bytes());
        match encode_rdata(record) {
            Ok(rdata) => {
                // A 4-byte RDLENGTH, not DNS's 2-byte one, so an
                // arbitrarily long CNAME/NS/MX target name never
                // silently truncates.
                out.extend((rdata.len() as u32).to_be_bytes());
                out.extend(rdata);
            }
            Err(_) => continue,
        }
    }

    out
}

/// Build a minimal error response (e.g. FORMERR) for a message this node
/// couldn't parse into a [`DnsQuery`] at all, so the sender gets a
/// response instead of silence. `id` should be read directly from the
/// first two bytes of the offending message when possible.
pub fn build_error_response(id: u16, rcode: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend(id.to_be_bytes());
    out.extend((0x8000u16 | rcode).to_be_bytes());
    out.extend([0u8; 8]);
    out
}

/// RCODE 1, "Format Error": the request itself was malformed.
pub const RCODE_FORMAT_ERROR: u16 = RCODE_FORMERR;

/// Whether `record` should be included in the answer to a query with the
/// given QTYPE.
pub fn record_matches_qtype(record: &Record, qtype: u16) -> bool {
    qtype == QTYPE_ANY || record_type_code(record.record_type) == qtype
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(id.to_be_bytes());
        buf.extend(0x0100u16.to_be_bytes()); // flags: RD=1
        buf.extend(1u16.to_be_bytes()); // QDCOUNT
        buf.extend([0u8; 6]); // AN/NS/AR counts
        for label in name.split('.') {
            let bytes = label.as_bytes();
            buf.extend((bytes.len() as u32).to_be_bytes());
            buf.extend(bytes);
        }
        buf.extend(0u32.to_be_bytes());
        buf.extend(qtype.to_be_bytes());
        buf.extend(CLASS_IN.to_be_bytes());
        buf
    }

    #[test]
    fn parses_plain_ascii_query() {
        let bytes = build_query_bytes(0x1234, "example.binda", TYPE_A);
        let query = parse_query(&bytes).unwrap();
        assert_eq!(query.id, 0x1234);
        assert_eq!(query.domain.as_str(), "example.binda");
        assert_eq!(query.qtype, TYPE_A);
    }

    #[test]
    fn parses_unicode_query_as_native_utf8_no_punycode() {
        let bytes = build_query_bytes(1, "🔥.binda", TYPE_A);
        // The raw label bytes on the wire are the UTF-8 encoding of "🔥",
        // never an "xn--..." Punycode/ACE form.
        assert!(!bytes.windows(4).any(|w| w == b"xn--"));
        let query = parse_query(&bytes).unwrap();
        assert_eq!(query.domain.as_str(), "🔥.binda");
    }

    #[test]
    fn parses_mixed_script_query() {
        let bytes = build_query_bytes(2, "مرحبا.binda", TYPE_A);
        let query = parse_query(&bytes).unwrap();
        assert_eq!(query.domain.as_str(), "مرحبا.binda");
    }

    #[test]
    fn round_trips_intermixed_bidi_and_zalgo_label_on_the_wire() {
        // Arabic and Latin interleaved in one label, plus stacked
        // combining marks (zalgo), all as raw UTF-8 bytes end to end.
        let label = "helloمرحباe\u{0301}\u{0316}\u{0327}🔥world";
        let bytes = build_query_bytes(3, label, TYPE_A);
        let query = parse_query(&bytes).unwrap();
        assert_eq!(query.domain.as_str(), label);

        let response = build_response(&query, false, &[]);
        let reparsed = parse_query(&response).expect("response's echoed question should re-parse");
        assert_eq!(reparsed.domain.as_str(), label);
    }

    #[test]
    fn response_echoes_unicode_labels_as_raw_utf8() {
        let query = DnsQuery {
            id: 5,
            domain: DomainName::new("🔥.binda").unwrap(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let response = build_response(&query, false, &[]);
        assert!(!response.windows(4).any(|w| w == b"xn--"));
        // The question section (after the 12-byte header) should contain
        // the raw "🔥" UTF-8 bytes, prefixed by a 4-byte length.
        let fire = "🔥".as_bytes();
        let len_field = u32::from_be_bytes(response[12..16].try_into().unwrap());
        assert_eq!(len_field as usize, fire.len());
        assert_eq!(&response[16..16 + fire.len()], fire);
    }

    #[test]
    fn accepts_a_label_far_longer_than_dns_would_allow() {
        // Classic DNS caps a label at 63 bytes and a name at 255. Build
        // one label alone well past both to prove there's no such cap
        // here.
        let long_label = "a".repeat(10_000);
        let bytes = build_query_bytes(9, &format!("{long_label}.binda"), TYPE_A);
        let query = parse_query(&bytes).unwrap();
        assert_eq!(query.domain.labels().next().unwrap().len(), 10_000);

        let response = build_response(&query, false, &[]);
        let reparsed = parse_query(&response).unwrap();
        assert_eq!(reparsed.domain.labels().next().unwrap().len(), 10_000);
    }

    #[test]
    fn builds_nxdomain_response_for_unknown_domain() {
        let query = DnsQuery {
            id: 7,
            domain: DomainName::new("example.binda").unwrap(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let response = build_response(&query, false, &[]);
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert_eq!(flags & 0x000F, RCODE_NXDOMAIN);
    }

    #[test]
    fn builds_answer_with_a_record() {
        let query = DnsQuery {
            id: 7,
            domain: DomainName::new("example.binda").unwrap(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        let record = Record {
            name: "@".into(),
            record_type: RecordType::A,
            ttl_secs: 300,
            value: "203.0.113.10".into(),
        };
        let response = build_response(&query, true, &[record]);
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        assert_eq!(ancount, 1);
        assert!(response.ends_with(&[203, 0, 113, 10]));
    }
}
