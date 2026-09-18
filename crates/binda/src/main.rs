//! `binda`: the BINDA node daemon binary.
//!
//! Runs a node's gossip and resolver UDP listeners. Usage:
//!
//! ```text
//! binda --gossip 0.0.0.0:9530 --resolver 0.0.0.0:9531 [--peer 203.0.113.5:9530 ...]
//! ```
//!
//! Every `--peer` is a remote node's gossip address; the peer list grows
//! at runtime too, as this node learns of new peers from gossip it
//! receives.

mod node;
mod peers;

use std::net::SocketAddr;

use binda_core::client::ClientIdentity;
use binda_core::domain::DomainName;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use node::Node;

struct Args {
    gossip_addr: SocketAddr,
    resolver_addr: SocketAddr,
    peers: Vec<SocketAddr>,
}

fn parse_args() -> Args {
    let mut gossip_addr: SocketAddr = "0.0.0.0:9530".parse().unwrap();
    let mut resolver_addr: SocketAddr = "0.0.0.0:9531".parse().unwrap();
    let mut peers = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--gossip" => {
                gossip_addr = args
                    .next()
                    .expect("--gossip requires an address")
                    .parse()
                    .expect("invalid --gossip address");
            }
            "--resolver" => {
                resolver_addr = args
                    .next()
                    .expect("--resolver requires an address")
                    .parse()
                    .expect("invalid --resolver address");
            }
            "--peer" => {
                let addr = args
                    .next()
                    .expect("--peer requires an address")
                    .parse()
                    .expect("invalid --peer address");
                peers.push(addr);
            }
            other => {
                eprintln!("binda: ignoring unrecognized argument {other}");
            }
        }
    }

    Args {
        gossip_addr,
        resolver_addr,
        peers,
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = parse_args();
    println!("binda (bind10) — starting node");

    let node = Node::new(args.peers);
    println!("binda: known peers at startup: {:?}", node.peers.snapshot().await);

    // Demonstrate the registration flow locally so a freshly-started node
    // has something to gossip and resolve immediately.
    {
        let signing_key = SigningKey::generate(&mut OsRng);
        let client = ClientIdentity::new(signing_key.verifying_key(), "localhost.");
        let domain = DomainName::new("example.binda").expect("valid domain name");
        let mut store = node.store.lock().await;
        store.probe(&client, node.time.as_ref());
        match store.register(domain.clone(), &client, node.time.as_ref()) {
            Ok(token) => println!(
                "registered {domain} for client {} at t={}",
                client.rdns, token.issued_at_millis
            ),
            Err(err) => eprintln!("local registration failed: {err}"),
        }
    }

    let gossip_node = node.clone();
    let gossip_task = tokio::spawn(async move {
        if let Err(err) = gossip_node.run_gossip(args.gossip_addr).await {
            eprintln!("gossip loop exited: {err}");
        }
    });

    let resolver_node = node.clone();
    let resolver_task = tokio::spawn(async move {
        if let Err(err) = resolver_node.run_resolver(args.resolver_addr).await {
            eprintln!("resolver loop exited: {err}");
        }
    });

    let _ = tokio::join!(gossip_task, resolver_task);
    Ok(())
}
