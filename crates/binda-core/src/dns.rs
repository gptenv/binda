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
//! Scope: single-question queries, no message compression on the way in
//! (real clients don't compress the question section), and compressed
//! answer names pointing back at the question (the common case). EDNS0,
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

/// Parse the question section out of a raw incoming message. Each label is
/// a length byte followed by that many raw UTF-8 bytes — never Punycode.
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
        let len = *bytes.get(pos).ok_or(DnsError::MalformedLabel)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            // Compression pointers aren't valid in a question we parse.
            return Err(DnsError::MalformedLabel);
        }
        pos += 1;
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

fn encode_domain_labels(domain: &DomainName, out: &mut Vec<u8>) -> Result<(), DnsError> {
    for label in domain.labels() {
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(DnsError::MalformedLabel);
        }
        out.push(bytes.len() as u8);
        out.extend(bytes);
    }
    out.push(0);
    Ok(())
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
            encode_domain_labels(&target, &mut buf)?;
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
            encode_domain_labels(&target, &mut buf)?;
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
    if encode_domain_labels(&query.domain, &mut out).is_err() {
        // A domain that round-tripped through parse_query should always
        // re-encode; if it somehow can't, fail closed with FORMERR.
        return format_error_response(query.id);
    }
    out.extend(query.qtype.to_be_bytes());
    out.extend(query.qclass.to_be_bytes());

    for record in matching {
        out.extend([0xC0, 0x0C]); // pointer back to the question name
        out.extend(record_type_code(record.record_type).to_be_bytes());
        out.extend(CLASS_IN.to_be_bytes());
        out.extend(record.ttl_secs.to_be_bytes());
        match encode_rdata(record) {
            Ok(rdata) => {
                out.extend((rdata.len() as u16).to_be_bytes());
                out.extend(rdata);
            }
            Err(_) => continue,
        }
    }

    out
}

fn format_error_response(id: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend(id.to_be_bytes());
    out.extend((0x8000u16 | RCODE_FORMERR).to_be_bytes());
    out.extend([0u8; 8]);
    out
}

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
            buf.push(bytes.len() as u8);
            buf.extend(bytes);
        }
        buf.push(0);
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
        // the raw "🔥" UTF-8 bytes length-prefixed.
        let fire = "🔥".as_bytes();
        assert_eq!(response[12] as usize, fire.len());
        assert_eq!(&response[13..13 + fire.len()], fire);
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
