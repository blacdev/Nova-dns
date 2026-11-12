//! nova-edge: configured by its environment (see .env.example, "the tunnel's edge"):
//!
//! - `EDGE_API_BASE` (required): where the platform's API is, e.g. https://api.ROOT_DOMAIN
//! - `EDGE_TOKEN` (required): the API's EDGE_TOKEN
//! - Its ports come from the platform (EDGE_HOST's port for stations, EDGE_PORTS for
//!   presenters: GET /internal/edge/config), so the edge and what stations are told never
//!   differ. `EDGE_QUIC` / `EDGE_PUBLIC` may still name the address to bind
//!   (e.g. 10.0.0.5:4433), with the platform's ports; other ports are refused (ports.rs).
//!   When the platform's ports change, the edge ends and Docker starts it again on them.
//! - `EDGE_CERT_FILE` + `EDGE_KEY_FILE`: a certificate of your own; without them the
//!   platform's (edge.ROOT_DOMAIN, issued by the worker) is fetched and kept current
//! - `EDGE_PER_ADDRESS` (96), `EDGE_TOTAL` (8192): open presenter connections allowed
//! - `EDGE_RECHECK_SECONDS` (300): how often a signed-in station is checked again

use std::time::Duration;

use nova_edge::{api::Api, edge, log::say, ports};

/// How often the platform's ports are asked again while running.
const PORTS_EVERY: Duration = Duration::from_secs(300);

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

/// The platform's ports, asked until it answers (the API may still be starting).
async fn platform_ports(api: &Api) -> (u16, Vec<u16>) {
    loop {
        let a = api.clone();
        match tokio::task::spawn_blocking(move || a.config()).await {
            Ok(Ok(got)) => return got,
            Ok(Err(e)) => say(&format!("cannot learn this edge's ports from the platform ({e}); asking again in 30 s")),
            Err(e) => say(&format!("cannot learn this edge's ports ({e}); asking again in 30 s")),
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

fn main() {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        println!("nova-edge: configured by EDGE_API_BASE and EDGE_TOKEN; its ports come from the platform (see src/main.rs).");
        return;
    }
    let base = var("EDGE_API_BASE").unwrap_or_else(|| fail("EDGE_API_BASE is not set"));
    let token = var("EDGE_TOKEN").unwrap_or_else(|| fail("EDGE_TOKEN is not set"));
    let cert_files = match (var("EDGE_CERT_FILE"), var("EDGE_KEY_FILE")) {
        (Some(c), Some(k)) => Some((c, k)),
        (None, None) => None,
        _ => fail("set both EDGE_CERT_FILE and EDGE_KEY_FILE, or neither"),
    };
    let api = Api::new(&base, &token);
    let (per_address, total) = (number("EDGE_PER_ADDRESS", 96) as usize, number("EDGE_TOTAL", 8192) as usize);
    let recheck = Duration::from_secs(number("EDGE_RECHECK_SECONDS", 300).max(5));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a runtime");
    runtime.block_on(async move {
        let (quic_port, presenter_ports) = platform_ports(&api).await;
        let wanted = match ports::resolve(quic_port, &presenter_ports, var("EDGE_QUIC").as_deref(), var("EDGE_PUBLIC").as_deref()) {
            Ok(w) => w,
            Err(e) => {
                say(&format!("cannot start: {e}"));
                // Not at once: Docker would start it again many times a second.
                tokio::time::sleep(Duration::from_secs(30)).await;
                std::process::exit(2);
            }
        };
        let cfg = edge::Config { api: api.clone(), quic: wanted.quic, public: wanted.public, cert_files, per_address, total, recheck };
        if let Err(e) = edge::start(cfg).await {
            say(&format!("cannot start: {e}"));
            tokio::time::sleep(Duration::from_secs(30)).await;
            std::process::exit(1);
        }
        // The platform's ports changed (./setup.sh platform): end, and Docker starts the edge
        // again on the new ones (restart: unless-stopped).
        loop {
            tokio::time::sleep(PORTS_EVERY).await;
            let a = api.clone();
            if let Ok(Ok((q, p))) = tokio::task::spawn_blocking(move || a.config()).await {
                if q != quic_port || p != presenter_ports {
                    say(&format!(
                        "the platform's ports changed (UDP {quic_port} -> {q}, TCP {presenter_ports:?} -> {p:?}): starting again on them"
                    ));
                    std::process::exit(0);
                }
            }
        }
    });
}
