//! nova-edge: configured by its environment (see .env.example, "the tunnel's edge"):
//!
//! - `EDGE_API_BASE` (required): where the platform's API is, e.g. https://api.ROOT_DOMAIN
//! - `EDGE_TOKEN` (required): the API's EDGE_TOKEN
//! - `EDGE_QUIC`: where stations dial, UDP (default 0.0.0.0:443)
//! - `EDGE_PUBLIC`: where presenters connect, TCP, comma-separated (default
//!   0.0.0.0:443,0.0.0.0:25433: 25433 keeps addresses already given out working)
//! - `EDGE_CERT_FILE` + `EDGE_KEY_FILE`: a certificate of your own; without them the
//!   platform's (edge.ROOT_DOMAIN, issued by the worker) is fetched and kept current
//! - `EDGE_PER_ADDRESS` (96), `EDGE_TOTAL` (8192): open presenter connections allowed
//! - `EDGE_RECHECK_SECONDS` (300): how often a signed-in station is checked again

use std::net::SocketAddr;
use std::time::Duration;

use nova_edge::{api::Api, edge, log::say};

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn fail(message: &str) -> ! {
    eprintln!("nova-edge: {message}");
    std::process::exit(2);
}

fn number(name: &str, default: u64) -> u64 {
    var(name).map(|v| v.trim().parse().unwrap_or_else(|_| fail(&format!("{name} must be a number")))).unwrap_or(default)
}

fn main() {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!("nova-edge: configured by EDGE_API_BASE, EDGE_TOKEN, EDGE_QUIC, EDGE_PUBLIC, EDGE_CERT_FILE/EDGE_KEY_FILE (see src/main.rs).");
        return;
    }
    let base = var("EDGE_API_BASE").unwrap_or_else(|| fail("EDGE_API_BASE is not set"));
    let token = var("EDGE_TOKEN").unwrap_or_else(|| fail("EDGE_TOKEN is not set"));
    let addr = |v: &str| -> SocketAddr { v.trim().parse().unwrap_or_else(|_| fail(&format!("not an address: {v}"))) };
    let quic = addr(&var("EDGE_QUIC").unwrap_or_else(|| "0.0.0.0:443".into()));
    let public: Vec<SocketAddr> = var("EDGE_PUBLIC").unwrap_or_else(|| "0.0.0.0:443,0.0.0.0:25433".into()).split(',').filter(|s| !s.trim().is_empty()).map(addr).collect();
    let cert_files = match (var("EDGE_CERT_FILE"), var("EDGE_KEY_FILE")) {
        (Some(c), Some(k)) => Some((c, k)),
        (None, None) => None,
        _ => fail("set both EDGE_CERT_FILE and EDGE_KEY_FILE, or neither"),
    };
    let cfg = edge::Config {
        api: Api::new(&base, &token),
        quic,
        public,
        cert_files,
        per_address: number("EDGE_PER_ADDRESS", 96) as usize,
        total: number("EDGE_TOTAL", 8192) as usize,
        recheck: Duration::from_secs(number("EDGE_RECHECK_SECONDS", 300).max(5)),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a runtime");
    runtime.block_on(async move {
        match edge::start(cfg).await {
            Ok(_running) => loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            },
            Err(e) => {
                say(&format!("cannot start: {e}"));
                std::process::exit(1);
            }
        }
    });
}
