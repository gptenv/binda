//! `binda`: the BINDA node daemon binary.
//!
//! Runs a node's gossip, resolver, client-API, and (optional) native
//! name-lookup UDP listeners. Usage:
//!
//! ```text
//! binda --gossip 0.0.0.0:9530 --resolver 0.0.0.0:9531 --api 0.0.0.0:9532 \
//!       [--dns 0.0.0.0:9533] [--peer 203.0.113.5:9530 ...]
//! ```
//!
//! Every `--peer` is a remote node's gossip address; the peer list grows
//! at runtime too, as this node learns of new peers from gossip it
//! receives. `--dns` is optional: omit it to skip the DNS-shaped listener
//! (see [`binda_core::dns`] — it is BINDA's own native, UTF-8-native
//! protocol, not RFC 1035; a production deployment might still bind it to
//! port 53 as a convenient, familiar-looking address, which needs
//! elevated privilege on most systems).

// `main` itself is excluded from coverage accounting (see the attribute
// on it below): it's pure top-level wiring — parse args, construct a
// Node, spawn the listener tasks, join them forever — with every piece
// it calls already covered on its own (parse_args_from,
// spawn_listener_tasks, Node::new). `main` never returns in a real run,
// so it can't be invoked from a test at all without spawning a whole
// subprocess, and doing that just to tick a coverage box would test the
// process harness, not this code.
#![feature(coverage_attribute)]

mod node;
mod peers;

use std::net::SocketAddr;

use node::Node;

#[derive(Debug, PartialEq, Eq)]
struct Args {
    gossip_addr: SocketAddr,
    resolver_addr: SocketAddr,
    api_addr: SocketAddr,
    dns_addr: Option<SocketAddr>,
    peers: Vec<SocketAddr>,
}

fn parse_args() -> Args {
    parse_args_from(std::env::args().skip(1))
}

/// The actual argument-parsing logic, taking an arbitrary iterator of
/// argument strings instead of reading `std::env::args()` directly, so it
/// can be exercised by tests without spawning a real process.
fn parse_args_from(args: impl Iterator<Item = String>) -> Args {
    let mut gossip_addr: SocketAddr = "0.0.0.0:9530".parse().unwrap();
    let mut resolver_addr: SocketAddr = "0.0.0.0:9531".parse().unwrap();
    let mut api_addr: SocketAddr = "0.0.0.0:9532".parse().unwrap();
    let mut dns_addr: Option<SocketAddr> = None;
    let mut peers = Vec::new();

    let mut args = args;
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

/// The four listener tasks a running node drives, as returned by
/// [`spawn_listener_tasks`]. Split out from `main` so the spawning logic
/// itself — which addresses go to which listener, and that a `--dns`
/// flag actually produces a fourth task — can be exercised by a test
/// without `main`'s own infinite `join!` ever needing to return.
struct ListenerTasks {
    gossip: tokio::task::JoinHandle<()>,
    resolver: tokio::task::JoinHandle<()>,
    api: tokio::task::JoinHandle<()>,
    dns: Option<tokio::task::JoinHandle<()>>,
}

fn spawn_listener_tasks(node: &Node, args: &Args) -> ListenerTasks {
    let gossip_node = node.clone();
    let gossip_addr = args.gossip_addr;
    let gossip = tokio::spawn(async move {
        if let Err(err) = gossip_node.run_gossip(gossip_addr).await {
            eprintln!("gossip loop exited: {err}");
        }
    });

    let resolver_node = node.clone();
    let resolver_addr = args.resolver_addr;
    let resolver = tokio::spawn(async move {
        if let Err(err) = resolver_node.run_resolver(resolver_addr).await {
            eprintln!("resolver loop exited: {err}");
        }
    });

    let api_node = node.clone();
    let api_addr = args.api_addr;
    let api = tokio::spawn(async move {
        if let Err(err) = api_node.run_client_api(api_addr).await {
            eprintln!("client API loop exited: {err}");
        }
    });

    let dns = args.dns_addr.map(|dns_addr| {
        let dns_node = node.clone();
        tokio::spawn(async move {
            if let Err(err) = dns_node.run_dns(dns_addr).await {
                eprintln!("DNS loop exited: {err}");
            }
        })
    });

    ListenerTasks {
        gossip,
        resolver,
        api,
        dns,
    }
}

#[coverage(off)]
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = parse_args();
    println!("binda (bind10) — starting node");

    let node = Node::new(args.peers.clone());
    node.spawn_rate_limiter_maintenance();
    println!(
        "binda: known peers at startup: {:?}",
        node.peers.snapshot().await
    );

    let tasks = spawn_listener_tasks(&node, &args);
    if let Some(dns_task) = tasks.dns {
        let _ = tokio::join!(tasks.gossip, tasks.resolver, tasks.api, dns_task);
    } else {
        let _ = tokio::join!(tasks.gossip, tasks.resolver, tasks.api);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(strs: &[&str]) -> Args {
        parse_args_from(strs.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_when_no_flags_given() {
        let parsed = args(&[]);
        assert_eq!(parsed.gossip_addr, "0.0.0.0:9530".parse().unwrap());
        assert_eq!(parsed.resolver_addr, "0.0.0.0:9531".parse().unwrap());
        assert_eq!(parsed.api_addr, "0.0.0.0:9532".parse().unwrap());
        assert_eq!(parsed.dns_addr, None);
        assert!(parsed.peers.is_empty());
    }

    #[test]
    fn parses_each_address_flag() {
        let parsed = args(&[
            "--gossip",
            "127.0.0.1:1",
            "--resolver",
            "127.0.0.1:2",
            "--api",
            "127.0.0.1:3",
            "--dns",
            "127.0.0.1:4",
        ]);
        assert_eq!(parsed.gossip_addr, "127.0.0.1:1".parse().unwrap());
        assert_eq!(parsed.resolver_addr, "127.0.0.1:2".parse().unwrap());
        assert_eq!(parsed.api_addr, "127.0.0.1:3".parse().unwrap());
        assert_eq!(parsed.dns_addr, Some("127.0.0.1:4".parse().unwrap()));
    }

    #[test]
    fn collects_repeated_peer_flags_in_order() {
        let parsed = args(&["--peer", "127.0.0.1:1", "--peer", "127.0.0.1:2"]);
        assert_eq!(
            parsed.peers,
            vec![
                "127.0.0.1:1".parse().unwrap(),
                "127.0.0.1:2".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn unrecognized_flag_is_ignored_not_fatal() {
        // Should not panic, and every recognized flag around it should
        // still be parsed normally.
        let parsed = args(&["--bogus", "--gossip", "127.0.0.1:1"]);
        assert_eq!(parsed.gossip_addr, "127.0.0.1:1".parse().unwrap());
    }

    #[test]
    #[should_panic(expected = "--gossip requires an address")]
    fn missing_value_for_flag_panics_with_clear_message() {
        args(&["--gossip"]);
    }

    #[test]
    #[should_panic(expected = "invalid --gossip address")]
    fn unparseable_address_panics_with_clear_message() {
        args(&["--gossip", "not-an-address"]);
    }

    #[test]
    fn parse_args_reads_from_the_process_environment() {
        // parse_args() itself just forwards std::env::args() into
        // parse_args_from; this exercises that thin wrapper. What it
        // returns depends on how the test binary itself was invoked, so
        // nothing beyond "it doesn't panic" is asserted here.
        let _ = parse_args();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_listener_tasks_creates_a_dns_task_when_configured() {
        let node = Node::new(Vec::new());
        let parsed_args = Args {
            gossip_addr: "127.0.0.1:29590".parse().unwrap(),
            resolver_addr: "127.0.0.1:29591".parse().unwrap(),
            api_addr: "127.0.0.1:29592".parse().unwrap(),
            dns_addr: Some("127.0.0.1:29593".parse().unwrap()),
            peers: Vec::new(),
        };
        let tasks = spawn_listener_tasks(&node, &parsed_args);
        assert!(tasks.dns.is_some());
        tasks.gossip.abort();
        tasks.resolver.abort();
        tasks.api.abort();
        tasks.dns.unwrap().abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawn_listener_tasks_omits_dns_when_not_configured() {
        let node = Node::new(Vec::new());
        let parsed_args = Args {
            gossip_addr: "127.0.0.1:29594".parse().unwrap(),
            resolver_addr: "127.0.0.1:29595".parse().unwrap(),
            api_addr: "127.0.0.1:29596".parse().unwrap(),
            dns_addr: None,
            peers: Vec::new(),
        };
        let tasks = spawn_listener_tasks(&node, &parsed_args);
        assert!(tasks.dns.is_none());
        tasks.gossip.abort();
        tasks.resolver.abort();
        tasks.api.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn spawned_tasks_log_and_exit_cleanly_when_their_bind_address_is_taken() {
        // Pre-bind every address so each listener's own UdpSocket::bind
        // fails, exercising the "loop exited: ..." eprintln branch in
        // each of the four spawned tasks instead of the happy path.
        let gossip_addr: SocketAddr = "127.0.0.1:29597".parse().unwrap();
        let resolver_addr: SocketAddr = "127.0.0.1:29598".parse().unwrap();
        let api_addr: SocketAddr = "127.0.0.1:29599".parse().unwrap();
        let dns_addr: SocketAddr = "127.0.0.1:29600".parse().unwrap();

        let _hold_gossip = tokio::net::UdpSocket::bind(gossip_addr).await.unwrap();
        let _hold_resolver = tokio::net::UdpSocket::bind(resolver_addr).await.unwrap();
        let _hold_api = tokio::net::UdpSocket::bind(api_addr).await.unwrap();
        let _hold_dns = tokio::net::UdpSocket::bind(dns_addr).await.unwrap();

        let node = Node::new(Vec::new());
        let parsed_args = Args {
            gossip_addr,
            resolver_addr,
            api_addr,
            dns_addr: Some(dns_addr),
            peers: Vec::new(),
        };
        let tasks = spawn_listener_tasks(&node, &parsed_args);

        // Each task should fail its bind and return promptly, rather
        // than hang waiting on a socket it never got.
        tokio::time::timeout(std::time::Duration::from_secs(5), tasks.gossip)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), tasks.resolver)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), tasks.api)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), tasks.dns.unwrap())
            .await
            .unwrap()
            .unwrap();
    }
}
