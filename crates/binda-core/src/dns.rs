//! A minimal RFC 1035-compatible DNS message codec, so legacy DNS clients
//! and resolvers (which speak ASCII-label DNS wire format on UDP port 53)
//! can query a BINDA node directly, without needing to speak BINDA's own
//! [`crate::resolver`] protocol.
//!
//! BINDA domains are natively Unicode; on the wire they're translated to
//! and from ASCII via [`crate::punycode`] (the same "xn--" ACE form real
//! DNS already uses for internationalized domain names), so this codec
//! never has to invent a non-standard encoding.
//!
//! Scope: single-question queries, no message compression on the way in
//! (real resolvers don't compress the question section), and compressed
//! answer names pointing back at the question (the common case). EDNS0,
//! multi-question messages, and zone transfer opcodes are not supported.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use thiserror::Error;

use crate::domain::DomainName;
use crate::punycode;
use crate::zone::{Record, RecordType};

/// Standard DNS resource record TYPE values BINDA understands.
const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
/// QTYPE meaning "any type", per RFC 1035 §3.2.3.
const QTYPE_ANY: u16 = 255;

const CLASS_IN: u16 = 1;

/// RCODE 3, "Name Error": the queried domain does not exist at all.
const RCODE_NXDOMAIN: u16 = 3;
/// RCODE 1, "Format Error": the request itself was malformed.
const RCODE_FORMERR: u16 = 1;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("message shorter than a DNS header")]
    TooShort,
    #[error("message does not contain exactly one question")]
    UnsupportedQuestionCount,
    #[error("malformed domain name label in message")]
    MalformedLabel,
    #[error("label failed punycode decoding: {0}")]
    Punycode(#[from] punycode::PunycodeError),
    #[error("decoded domain name is invalid: {0}")]
    InvalidDomain(#[from] crate::domain::DomainNameError),
}

/// A parsed incoming DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: DomainName,
    pub qtype: u16,
    pub qclass: u16,
}

fn read_u16(bytes: &[u8], pos: usize) -> Result<u16, DnsError> {
    let slice: [u8; 2] = bytes
        .get(pos..pos + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or(DnsError::MalformedLabel)?;
    Ok(u16::from_be_bytes(slice))
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

/// Parse the question section out of a raw incoming DNS message.
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
        let label_ascii = std::str::from_utf8(label_bytes).map_err(|_| DnsError::MalformedLabel)?;
        labels.push(punycode::label_from_ascii(label_ascii)?);
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
        let ascii = punycode::label_to_ascii(label)?;
        if ascii.len() > 63 {
            return Err(DnsError::MalformedLabel);
        }
        out.push(ascii.len() as u8);
        out.extend(ascii.as_bytes());
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

/// Build a DNS response for `query`.
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

    // Echo the question section verbatim (re-encoding it also normalizes
    // punycode casing).
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
            let ascii = punycode::label_to_ascii(label).unwrap();
            buf.push(ascii.len() as u8);
            buf.extend(ascii.as_bytes());
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
    fn parses_unicode_query_via_punycode() {
        let bytes = build_query_bytes(1, "🔥.binda", TYPE_A);
        let query = parse_query(&bytes).unwrap();
        assert_eq!(query.domain.as_str(), "🔥.binda");
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
