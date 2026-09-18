//! An example end-user client: probes liveness, registers a domain, sets
//! an A record, then resolves it both via BINDA's own resolver protocol
//! and via a real RFC1035 DNS query.
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
    let domain = DomainName::new("demo.binda").expect("valid domain");
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

    // 5. Resolve the same domain via a real RFC1035 DNS query.
    let mut dns_query = Vec::new();
    dns_query.extend(0x1234u16.to_be_bytes());
    dns_query.extend(0x0100u16.to_be_bytes());
    dns_query.extend(1u16.to_be_bytes());
    dns_query.extend([0u8; 6]);
    for label in domain.labels() {
        let ascii = binda_core::punycode::label_to_ascii(label).unwrap();
        dns_query.push(ascii.len() as u8);
        dns_query.extend(ascii.as_bytes());
    }
    dns_query.push(0);
    dns_query.extend(1u16.to_be_bytes()); // QTYPE A
    dns_query.extend(1u16.to_be_bytes()); // QCLASS IN

    socket.send_to(&dns_query, dns_addr).expect("send dns query");
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).expect("recv dns response");
    let response = &buf[..len];
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    println!("resolve (RFC1035 DNS) -> ANCOUNT={ancount}, {} bytes", response.len());
    if let Ok(parsed) = dns::parse_query(&dns_query) {
        println!("  echoed query domain: {}", parsed.domain);
    }
}
