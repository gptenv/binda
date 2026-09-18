//! `binda`: the BINDA node daemon binary.
//!
//! Runs a node's gossip, resolver, client-API, and (optional) legacy DNS
//! UDP listeners. Usage:
//!
//! ```text
//! binda --gossip 0.0.0.0:9530 --resolver 0.0.0.0:9531 --api 0.0.0.0:9532 \
//!       [--dns 0.0.0.0:9533] [--peer 203.0.113.5:9530 ...]
//! ```
//!
//! Every `--peer` is a remote node's gossip address; the peer list grows
//! at runtime too, as this node learns of new peers from gossip it
//! receives. `--dns` is optional: omit it to skip the legacy RFC1035
//! listener (real deployments would bind it to port 53, which needs
//! elevated privilege on most systems).

mod node;
mod peers;

use std::net::SocketAddr;

use node::Node;

struct Args {
    gossip_addr: SocketAddr,
    resolver_addr: SocketAddr,
    api_addr: SocketAddr,
    dns_addr: Option<SocketAddr>,
    peers: Vec<SocketAddr>,
}

fn parse_args() -> Args {
    let mut gossip_addr: SocketAddr = "0.0.0.0:9530".parse().unwrap();
    let mut resolver_addr: SocketAddr = "0.0.0.0:9531".parse().unwrap();
    let mut api_addr: SocketAddr = "0.0.0.0:9532".parse().unwrap();
    let mut dns_addr: Option<SocketAddr> = None;
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
            "--api" => {
                api_addr = args
                    .next()
                    .expect("--api requires an address")
                    .parse()
                    .expect("invalid --api address");
            }
            "--dns" => {
                dns_addr = Some(
                    args.next()
                        .expect("--dns requires an address")
                        .parse()
                        .expect("invalid --dns address"),
                );
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
        api_addr,
        dns_addr,
        peers,
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = parse_args();
    println!("binda (bind10) — starting node");

    let node = Node::new(args.peers);
    println!("binda: known peers at startup: {:?}", node.peers.snapshot().await);

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

    let api_node = node.clone();
    let api_task = tokio::spawn(async move {
        if let Err(err) = api_node.run_client_api(args.api_addr).await {
            eprintln!("client API loop exited: {err}");
        }
    });

    let dns_task = args.dns_addr.map(|dns_addr| {
        let dns_node = node.clone();
        tokio::spawn(async move {
            if let Err(err) = dns_node.run_dns(dns_addr).await {
                eprintln!("DNS loop exited: {err}");
            }
        })
    });

    if let Some(dns_task) = dns_task {
        let _ = tokio::join!(gossip_task, resolver_task, api_task, dns_task);
    } else {
        let _ = tokio::join!(gossip_task, resolver_task, api_task);
    }
    Ok(())
}
