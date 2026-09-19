//! Forward-confirmed reverse DNS (FCrDNS) verification.
//!
//! A [`crate::client_api`] request carries a `rdns` field the client
//! simply asserts — nothing stops it from claiming any hostname it likes.
//! To make that claim mean something, every registration is checked
//! against the public DNS system itself:
//!
//! 1. **Reverse**: look up the PTR record(s) for the request's actual
//!    source IP address.
//! 2. **Forward-confirm**: the claimed hostname must be one of those PTR
//!    names, *and* a forward A/AAAA lookup of that hostname must include
//!    the same source IP.
//!
//! Both directions have to agree before a hostname claim is trusted. This
//! is the same check mail servers have used for decades to make a sender
//! claim mean something, applied here to make BINDA's "5 domains per live
//! socket" cap apply to a real, distinctly-controlled host rather than to
//! a free-to-mint keypair.
//!
//! This performs real, blocking network queries against the existing
//! (classic, RFC 1035) DNS system — deliberately: verifying a claim
//! against the pre-existing DNS hierarchy is a bootstrapping problem
//! BINDA doesn't try to solve itself, unlike name *resolution*, which is
//! entirely BINDA's own concern (see [`crate::dns`]).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Public resolvers queried for reverse/forward lookups, tried in order
/// until one answers.
pub const DEFAULT_RESOLVERS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"];

const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Something a [`FcrdnsVerifier`] (or a test double) can be asked: does
/// this source IP forward-confirm this claimed hostname?
pub trait RdnsVerifier: Send + Sync {
    fn verify(&self, source_ip: IpAddr, claimed_rdns: &str) -> bool;
}

/// The real verifier, backed by live queries against [`DEFAULT_RESOLVERS`].
#[derive(Debug, Default, Clone, Copy)]
pub struct FcrdnsVerifier;

impl RdnsVerifier for FcrdnsVerifier {
    fn verify(&self, source_ip: IpAddr, claimed_rdns: &str) -> bool {
        is_forward_confirmed(source_ip, claimed_rdns, DEFAULT_RESOLVERS)
    }
}

/// A verifier that accepts every claimed hostname without checking it
/// against anything.
///
/// **Never use this for a real deployment.** It exists purely so a node
/// can be run locally (on a laptop with no reverse DNS delegation, behind
/// NAT, on 127.0.0.1) for demos, examples, and manual testing, where no
/// claimed `rdns` could ever forward-confirm for real. With this
/// verifier installed, the "5 domains per live socket" cap once again
/// means nothing more than "5 domains per free keypair" — exactly the
/// gap [`FcrdnsVerifier`] exists to close. A node only uses this if it
/// was explicitly started with a flag that says so out loud (see the
/// `binda` binary's `--insecure-skip-rdns-verification`).
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAllVerifier;

impl RdnsVerifier for AllowAllVerifier {
    fn verify(&self, _source_ip: IpAddr, _claimed_rdns: &str) -> bool {
        true
    }
}

/// Full FCrDNS check: `claimed_rdns` must appear in `source_ip`'s PTR
/// records, and a forward lookup of `claimed_rdns` must resolve back to
/// `source_ip`.
pub fn is_forward_confirmed(source_ip: IpAddr, claimed_rdns: &str, resolvers: &[&str]) -> bool {
    let claimed = normalize(claimed_rdns);

    let ptr_names = match reverse_lookup(source_ip, resolvers) {
        Ok(names) => names,
        Err(_) => return false,
    };
    if !ptr_names.iter().any(|name| normalize(name) == claimed) {
        return false;
    }

    let forward_ips = match forward_lookup(claimed_rdns, resolvers) {
        Ok(ips) => ips,
        Err(_) => return false,
    };
    forward_ips.contains(&source_ip)
}

fn normalize(hostname: &str) -> String {
    hostname.trim_end_matches('.').to_ascii_lowercase()
}

/// Look up the PTR record(s) for `ip`.
pub fn reverse_lookup(ip: IpAddr, resolvers: &[&str]) -> io::Result<Vec<String>> {
    let name = ptr_query_name(ip);
    let response = query(&name, TYPE_PTR, resolvers)?;
    Ok(response
        .into_iter()
        .filter_map(|(rtype, data)| (rtype == TYPE_PTR).then_some(data))
        .filter_map(|data| String::from_utf8(data).ok())
        .collect())
}

fn parse_a(data: &[u8]) -> Option<IpAddr> {
    <[u8; 4]>::try_from(data)
        .ok()
        .map(|o| IpAddr::V4(Ipv4Addr::from(o)))
}

fn parse_aaaa(data: &[u8]) -> Option<IpAddr> {
    <[u8; 16]>::try_from(data)
        .ok()
        .map(|o| IpAddr::V6(Ipv6Addr::from(o)))
}

type RdataParser = fn(&[u8]) -> Option<IpAddr>;

/// Look up the A/AAAA record(s) for `hostname`.
pub fn forward_lookup(hostname: &str, resolvers: &[&str]) -> io::Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    let lookups: [(u16, RdataParser); 2] = [(TYPE_A, parse_a), (TYPE_AAAA, parse_aaaa)];
    for (qtype, parse) in lookups {
        if let Ok(response) = query(hostname, qtype, resolvers) {
            for (rtype, data) in response {
                if rtype == qtype {
                    if let Some(ip) = parse(&data) {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    Ok(ips)
}

fn ptr_query_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut nibbles = String::new();
            for byte in v6.octets().iter().rev() {
                nibbles.push_str(&format!("{:x}.{:x}.", byte & 0x0F, byte >> 4));
            }
            format!("{nibbles}ip6.arpa")
        }
    }
}

fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(id.to_be_bytes());
    buf.extend(0x0100u16.to_be_bytes()); // RD=1
    buf.extend(1u16.to_be_bytes()); // QDCOUNT
    buf.extend([0u8; 6]);
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        buf.push(label.len() as u8);
        buf.extend(label.as_bytes());
    }
    buf.push(0);
    buf.extend(qtype.to_be_bytes());
    buf.extend(CLASS_IN.to_be_bytes());
    buf
}

/// Read a (possibly compressed) domain name starting at `pos`. Returns
/// the decoded name and the position immediately after it in the
/// original stream (i.e. not following any pointer jump), per RFC 1035
/// §4.1.4.
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end_pos = None;
    let mut jumps = 0;

    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            let second = *buf.get(pos + 1)? as usize;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 32 {
                return None;
            }
            pos = ((len & 0x3F) << 8) | second;
            continue;
        }
        pos += 1;
        let label = buf.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += len;
    }

    Some((labels.join("."), end_pos.unwrap_or(pos)))
}

/// Send a query for `name`/`qtype` to each resolver in turn until one
/// answers, returning every `(TYPE, RDATA)` pair in the answer section.
fn query(name: &str, qtype: u16, resolvers: &[&str]) -> io::Result<Vec<(u16, Vec<u8>)>> {
    let id: u16 = rand::random();
    let request = encode_query(id, name, qtype);

    for resolver in resolvers {
        if let Ok(response) = send_and_receive(resolver, &request) {
            if let Some(answers) = parse_response(&response, id) {
                return Ok(answers);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no resolver answered",
    ))
}

fn send_and_receive(resolver: &str, request: &[u8]) -> io::Result<Vec<u8>> {
    let addr = resolver
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address for resolver"))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(QUERY_TIMEOUT))?;
    socket.set_write_timeout(Some(QUERY_TIMEOUT))?;
    socket.connect(addr)?;
    socket.send(request)?;
    let mut buf = vec![0u8; 4096];
    let len = socket.recv(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

fn parse_response(buf: &[u8], expected_id: u16) -> Option<Vec<(u16, Vec<u8>)>> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 1;
    let rcode = flags & 0x000F;
    if qr != 1 || rcode != 0 {
        return Some(Vec::new());
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_, next) = read_name(buf, pos)?;
        pos = next + 4; // QTYPE + QCLASS
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (_, next) = read_name(buf, pos)?;
        pos = next;
        let rtype = u16::from_be_bytes(*buf.get(pos..pos + 2)?.first_chunk()?);
        pos += 2;
        pos += 2; // CLASS
        pos += 4; // TTL
        let rdlength = u16::from_be_bytes(*buf.get(pos..pos + 2)?.first_chunk()?) as usize;
        pos += 2;
        let rdata_start = pos;
        pos += rdlength;

        let data = if rtype == TYPE_PTR {
            let (name, _) = read_name(buf, rdata_start)?;
            name.into_bytes()
        } else {
            buf.get(rdata_start..rdata_start + rdlength)?.to_vec()
        };
        answers.push((rtype, data));
    }

    Some(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ipv4_ptr_query_name() {
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        assert_eq!(ptr_query_name(ip), "34.216.184.93.in-addr.arpa");
    }

    #[test]
    fn builds_ipv6_ptr_query_name() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let name = ptr_query_name(ip);
        assert!(name.ends_with("ip6.arpa"));
        // 32 nibbles each followed by a dot, plus the one dot inside "ip6.arpa".
        assert_eq!(name.matches('.').count(), 33);
        assert_eq!(name.split('.').count(), 34);
    }

    #[test]
    fn round_trips_uncompressed_name() {
        let mut buf = vec![0u8; 12]; // fake header
        let start = buf.len();
        buf.push(7);
        buf.extend(b"example");
        buf.push(3);
        buf.extend(b"com");
        buf.push(0);
        let (name, end) = read_name(&buf, start).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, buf.len());
    }

    #[test]
    fn follows_compression_pointer() {
        let mut buf = vec![0u8; 12];
        let real_name_pos = buf.len();
        buf.push(7);
        buf.extend(b"example");
        buf.push(3);
        buf.extend(b"com");
        buf.push(0);

        let pointer_pos = buf.len();
        buf.push(0xC0 | ((real_name_pos >> 8) as u8));
        buf.push((real_name_pos & 0xFF) as u8);

        let (name, end) = read_name(&buf, pointer_pos).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, pointer_pos + 2);
    }

    #[test]
    fn encode_query_contains_labels() {
        let bytes = encode_query(1, "example.com", TYPE_A);
        assert!(bytes.windows(7).any(|w| w == b"example"));
    }

    /// A fake verifier for tests that don't want to hit the real network:
    /// approves exactly the (ip, hostname) pairs it's told to.
    struct FakeVerifier(Vec<(IpAddr, String)>);

    impl RdnsVerifier for FakeVerifier {
        fn verify(&self, source_ip: IpAddr, claimed_rdns: &str) -> bool {
            self.0
                .iter()
                .any(|(ip, host)| *ip == source_ip && host == claimed_rdns)
        }
    }

    #[test]
    fn fake_verifier_matches_known_pair() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let verifier = FakeVerifier(vec![(ip, "host.example.net".to_string())]);
        assert!(verifier.verify(ip, "host.example.net"));
        assert!(!verifier.verify(ip, "someone-else.example.net"));
    }

    #[test]
    fn allow_all_verifier_accepts_any_claim() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(AllowAllVerifier.verify(ip, "literally-anything.invalid"));
        assert!(AllowAllVerifier.verify(ip, ""));
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    /// A local, in-process fake DNS server: for every query it receives,
    /// it answers with `ptr_rdata` if the QTYPE was PTR and `a_rdata`
    /// otherwise, using a compression pointer back to the (echoed)
    /// question name, exactly like a real resolver's reply would. Runs
    /// until `queries_to_serve` requests have been answered.
    fn spawn_fake_resolver(
        ptr_rdata: Vec<u8>,
        a_rdata: Vec<u8>,
        queries_to_serve: usize,
    ) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..queries_to_serve {
                let Ok((len, from)) = socket.recv_from(&mut buf) else {
                    return;
                };
                let id = &buf[0..2];
                let question = &buf[12..len];
                let qtype = u16::from_be_bytes([buf[len - 4], buf[len - 3]]);
                let rdata = if qtype == TYPE_PTR {
                    &ptr_rdata
                } else {
                    &a_rdata
                };

                let mut response = Vec::new();
                response.extend_from_slice(id);
                response.extend_from_slice(&0x8180u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                response.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(question);
                response.extend_from_slice(&[0xC0, 0x0C]); // pointer to name at offset 12
                response.extend_from_slice(&qtype.to_be_bytes());
                response.extend_from_slice(&CLASS_IN.to_be_bytes());
                response.extend_from_slice(&300u32.to_be_bytes()); // TTL
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(rdata);
                let _ = socket.send_to(&response, from);
            }
        });
        addr
    }

    #[test]
    fn reverse_lookup_returns_ptr_name_from_a_real_query_response() {
        let ptr_rdata = encode_name("host.example.net");
        let resolver = spawn_fake_resolver(ptr_rdata, Vec::new(), 1);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let names = reverse_lookup(ip, &[&resolver]).unwrap();
        assert_eq!(names, vec!["host.example.net".to_string()]);
    }

    #[test]
    fn forward_lookup_returns_a_record_from_a_real_query_response() {
        let resolver = spawn_fake_resolver(Vec::new(), vec![203, 0, 113, 5], 1);
        let ips = forward_lookup("host.example.net", &[&resolver]).unwrap();
        assert!(ips.contains(&"203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn is_forward_confirmed_true_when_both_directions_agree() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let ptr_rdata = encode_name("host.example.net");
        let resolver = spawn_fake_resolver(ptr_rdata, vec![203, 0, 113, 5], 2);
        assert!(is_forward_confirmed(ip, "host.example.net", &[&resolver]));
    }

    #[test]
    fn is_forward_confirmed_false_when_ptr_does_not_match_claim() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let ptr_rdata = encode_name("someone-else.example.net");
        let resolver = spawn_fake_resolver(ptr_rdata, vec![203, 0, 113, 5], 1);
        assert!(!is_forward_confirmed(ip, "host.example.net", &[&resolver]));
    }

    #[test]
    fn is_forward_confirmed_false_when_forward_lookup_disagrees() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let ptr_rdata = encode_name("host.example.net");
        // Forward A record resolves to a different address than the
        // request's actual source IP.
        let resolver = spawn_fake_resolver(ptr_rdata, vec![198, 51, 100, 9], 2);
        assert!(!is_forward_confirmed(ip, "host.example.net", &[&resolver]));
    }

    #[test]
    fn normalize_ignores_case_and_trailing_dot() {
        assert_eq!(
            normalize("Host.Example.NET."),
            normalize("host.example.net")
        );
    }

    #[test]
    fn unreachable_resolver_yields_error_not_panic() {
        // Nothing is listening on this port; every call should fail
        // cleanly rather than hang forever or panic.
        let result = reverse_lookup("203.0.113.5".parse().unwrap(), &["127.0.0.1:1"]);
        assert!(result.is_err());
    }

    #[test]
    fn is_forward_confirmed_false_when_reverse_lookup_itself_fails() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        assert!(!is_forward_confirmed(
            ip,
            "host.example.net",
            &["127.0.0.1:1"]
        ));
    }

    #[test]
    fn is_forward_confirmed_false_when_forward_lookup_itself_fails() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let ptr_rdata = encode_name("host.example.net");
        // Server only answers the one (reverse) query, so the follow-up
        // forward lookup finds nothing listening and errors out.
        let resolver = spawn_fake_resolver(ptr_rdata, Vec::new(), 1);
        assert!(!is_forward_confirmed(ip, "host.example.net", &[&resolver]));
    }

    #[test]
    fn forward_lookup_returns_aaaa_record_from_a_real_query_response() {
        let ipv6 = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        // Serve the same 16-byte AAAA rdata for every query; the A query
        // fails to parse as 4 bytes (ignored), the AAAA query succeeds.
        let resolver = spawn_fake_resolver(Vec::new(), ipv6.octets().to_vec(), 2);
        let ips = forward_lookup("host.example.net", &[&resolver]).unwrap();
        assert!(ips.contains(&IpAddr::V6(ipv6)));
    }

    #[test]
    fn encode_query_skips_an_empty_label_from_a_trailing_dot() {
        let with_dot = encode_query(1, "example.com.", TYPE_A);
        let without_dot = encode_query(1, "example.com", TYPE_A);
        assert_eq!(with_dot, without_dot);
    }

    #[test]
    fn read_name_rejects_a_compression_pointer_loop() {
        let mut buf = vec![0u8; 12];
        let pointer_pos = buf.len();
        // A pointer that points at itself, so following it never
        // terminates without the jump-count guard.
        buf.push(0xC0 | ((pointer_pos >> 8) as u8));
        buf.push((pointer_pos & 0xFF) as u8);
        assert_eq!(read_name(&buf, pointer_pos), None);
    }

    #[test]
    fn parse_response_rejects_a_too_short_message() {
        assert_eq!(parse_response(&[0u8; 4], 1), None);
    }

    #[test]
    fn parse_response_rejects_a_mismatched_id() {
        let buf = vec![0u8; 48];
        // buf's id (first two bytes) is 0, which won't match.
        assert_eq!(parse_response(&buf, 1), None);
    }

    #[test]
    fn query_falls_back_to_a_later_resolver_after_an_earlier_one_fails() {
        let ptr_rdata = encode_name("host.example.net");
        let working = spawn_fake_resolver(ptr_rdata, Vec::new(), 1);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        // Nothing listens on the first resolver; the second is real.
        let names = reverse_lookup(ip, &["127.0.0.1:1", &working]).unwrap();
        assert_eq!(names, vec!["host.example.net".to_string()]);
    }

    /// A fake resolver that always answers with `fixed_rtype`, regardless
    /// of what type was actually queried — used to exercise the "server
    /// answered with a record type we didn't ask for" filtering path.
    fn spawn_mismatched_type_resolver(fixed_rtype: u16, rdata: Vec<u8>) -> String {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let addr = socket.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let Ok((len, from)) = socket.recv_from(&mut buf) else {
                return;
            };
            let id = &buf[0..2];
            let question = &buf[12..len];
            let mut response = Vec::new();
            response.extend_from_slice(id);
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(question);
            response.extend_from_slice(&[0xC0, 0x0C]);
            response.extend_from_slice(&fixed_rtype.to_be_bytes());
            response.extend_from_slice(&CLASS_IN.to_be_bytes());
            response.extend_from_slice(&300u32.to_be_bytes());
            response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            response.extend_from_slice(&rdata);
            let _ = socket.send_to(&response, from);
        });
        addr
    }

    #[test]
    fn forward_lookup_ignores_an_answer_of_the_wrong_record_type() {
        // The server always answers with a PTR record no matter what was
        // asked; forward_lookup wants A/AAAA, so every answer should be
        // filtered out rather than misinterpreted.
        let resolver = spawn_mismatched_type_resolver(TYPE_PTR, encode_name("irrelevant"));
        let ips = forward_lookup("host.example.net", &[&resolver]).unwrap();
        assert!(ips.is_empty());
    }
}
