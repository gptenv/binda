//! An example end-user client: probes liveness, registers a Unicode
//! domain, sets an A record, then resolves it both via BINDA's own
//! resolver protocol and via BINDA's native DNS-shaped wire protocol
//! (which carries the label as raw UTF-8 — no Punycode involved).
//!
//! Note: the `rdns` claimed below (`client-demo.example.net`) almost
//! certainly won't forward-confirm against wherever you actually run
//! this from (see `binda_core::fcrdns`), so `register` is expected to
//! come back as an `Error` unless you edit `rdns` to a hostname that
//! genuinely resolves back to your machine's real source IP.
//!
//! Run a node first, then this example against it:
//!
//! ```bash
//! cargo run -p binda --bin binda -- --gossip 127.0.0.1:9530 --resolver 127.0.0.1:9531 --api 127.0.0.1:9532 --dns 127.0.0.1:9533 &
//! cargo run -p binda --example client_demo
//! ```

use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use binda_core::client_api::{
    probe_message, register_message, set_records_message, ClientRequest, ClientResponse,
    ProbeBody, RegisterBody, SetRecordsBody, SignedEnvelope,
};
use binda_core::dns;
use binda_core::domain::DomainName;
use binda_core::resolver::{ResolveAnswer, ResolveQuery};
use binda_core::wire;
use binda_core::zone::{Record, RecordType};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn send_recv<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
    socket: &UdpSocket,
    addr: &str,
    request: &Req,
) -> Resp {
    let bytes = wire::encode(request).expect("encode request");
    socket.send_to(&bytes, addr).expect("send request");
    let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
    let (len, _) = socket.recv_from(&mut buf).expect("recv response");
    wire::decode(&buf[..len]).expect("decode response")
}

fn main() {
    let api_addr = "127.0.0.1:9532";
    let dns_addr = "127.0.0.1:9533";

    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind client socket");
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();

    let signing_key = SigningKey::generate(&mut OsRng);
    let rdns = "client-demo.example.net".to_string();

    // 1. Probe liveness.
    let t = now_millis();
    let msg = probe_message(t);
    let sig = signing_key.sign(&msg);
    let probe_req = ClientRequest::Probe(SignedEnvelope {
        verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
        rdns: rdns.clone(),
        timestamp_millis: t,
        signature: sig.to_bytes().to_vec(),
        body: ProbeBody,
    });
    let probe_resp: ClientResponse = send_recv(&socket, api_addr, &probe_req);
    println!("probe -> {probe_resp:?}");

    // 2. Register a domain.
    // A native Unicode label, to demonstrate that it travels the wire as
    // raw UTF-8 rather than being translated to Punycode/ASCII.
    let domain = DomainName::new("🔥demo.binda").expect("valid domain");
    let t = now_millis();
    let msg = register_message(&domain, t);
    let sig = signing_key.sign(&msg);
    let register_req = ClientRequest::Register(SignedEnvelope {
        verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
        rdns: rdns.clone(),
        timestamp_millis: t,
        signature: sig.to_bytes().to_vec(),
        body: RegisterBody { domain: domain.clone() },
    });
    let register_resp: ClientResponse = send_recv(&socket, api_addr, &register_req);
    println!("register -> {register_resp:?}");

    // 3. Publish an A record.
    let records = vec![Record {
        name: "@".into(),
        record_type: RecordType::A,
        ttl_secs: 300,
        value: "203.0.113.42".into(),
    }];
    let t = now_millis();
    let msg = set_records_message(&domain, &records, t);
    let sig = signing_key.sign(&msg);
    let set_records_req = ClientRequest::SetRecords(SignedEnvelope {
        verifying_key: signing_key.verifying_key().to_bytes().to_vec(),
        rdns: rdns.clone(),
        timestamp_millis: t,
        signature: sig.to_bytes().to_vec(),
        body: SetRecordsBody {
            domain: domain.clone(),
            records,
        },
    });
    let set_records_resp: ClientResponse = send_recv(&socket, api_addr, &set_records_req);
    println!("set_records -> {set_records_resp:?}");

    // 4. Resolve via BINDA's own resolver protocol.
    let query = ResolveQuery { domain: domain.clone() };
    let answer: ResolveAnswer = send_recv(&socket, api_addr.replace("9532", "9531").as_str(), &query);
    println!("resolve (binda protocol) -> {answer:?}");

    // 5. Resolve the same domain via BINDA's native, DNS-shaped wire
    // protocol. Every label goes on the wire as raw UTF-8 — never
    // Punycode/ASCII — which is the entire reason this is BINDA's own
    // protocol rather than RFC 1035.
    let mut native_query = Vec::new();
    native_query.extend(0x1234u16.to_be_bytes());
    native_query.extend(0x0100u16.to_be_bytes());
    native_query.extend(1u16.to_be_bytes());
    native_query.extend([0u8; 6]);
    for label in domain.labels() {
        let bytes = label.as_bytes();
        native_query.extend((bytes.len() as u32).to_be_bytes());
        native_query.extend(bytes);
    }
    native_query.extend(0u32.to_be_bytes());
    native_query.extend(1u16.to_be_bytes()); // QTYPE A
    native_query.extend(1u16.to_be_bytes()); // QCLASS IN

    socket.send_to(&native_query, dns_addr).expect("send native query");
    let mut buf = vec![0u8; wire::MAX_DATAGRAM_BYTES];
    let (len, _) = socket.recv_from(&mut buf).expect("recv native response");
    let response = &buf[..len];
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    println!("resolve (BINDA native protocol) -> ANCOUNT={ancount}, {} bytes", response.len());
    if let Ok(parsed) = dns::parse_query(&native_query) {
        println!("  echoed query domain (raw UTF-8 on the wire): {}", parsed.domain);
    }
}
