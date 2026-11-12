//! The edge (Nova's docs/TUNNEL.md, "What blacdev/Nova-dns needs to build").
//!
//! **Stations** dial in over QUIC (ALPN `nova-tunnel/1`), open one stream and send a JSON
//! line with their studio token. The API says whether it is good and what the station is
//! called; the edge answers that line and keeps the stream open. Every [`Config::recheck`]
//! it asks again: a renamed, suspended or deleted station is let go (it dials back and
//! gets its new name, or its refusal). A station that signs in again under its name takes
//! over from its older connection.
//!
//! **Presenters** connect over TCP (443 and 25433). The edge reads their first TLS record,
//! takes the name it asks for, opens a stream on that station's connection, writes a PROXY
//! v2 header (the presenter's address) and the record, and copies both ways. Nothing is
//! decrypted: TLS ends in Nova with the station's own certificate. Connections are limited
//! per presenter address and in total, as Nova limits its own (`nova/api/limits.py`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{Connection, Endpoint};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::api::{Api, Cert};
use crate::log::say;
use crate::{proxy, sni};

pub const ALPN: &[u8] = b"nova-tunnel/1";
/// As Nova's tunnel: keep-alive well inside NAT timeouts, idle after 30 s of nothing.
pub const KEEP_ALIVE: Duration = Duration::from_secs(10);
pub const IDLE: Duration = Duration::from_secs(30);
/// A station must sign in, and a presenter send their ClientHello, within this.
pub const WITHIN: Duration = Duration::from_secs(10);
/// How often the certificate is fetched again (the worker renews it 30 days ahead).
pub const CERT_EVERY: Duration = Duration::from_secs(3600);
/// Presenters' streams one station may have open at once (Nova takes 512).
pub const STREAMS_PER_STATION: u32 = 512;

pub struct Config {
    pub api: Api,
    /// Where stations dial (UDP).
    pub quic: SocketAddr,
    /// Where presenters connect (TCP): 443 and 25433 in production.
    pub public: Vec<SocketAddr>,
    /// Certificate and key files; None: fetched from the API (and kept current).
    pub cert_files: Option<(String, String)>,
    pub per_address: usize,
    pub total: usize,
    pub recheck: Duration,
}

/// Stations signed in now, by name.
type Stations = Arc<Mutex<HashMap<String, Connection>>>;

pub struct Running {
    pub quic: SocketAddr,
    pub public: Vec<SocketAddr>,
    stations: Stations,
    endpoint: Endpoint,
}

impl Running {
    pub fn signed_in(&self) -> Vec<String> {
        let mut v: Vec<String> = self.stations.lock().unwrap().keys().cloned().collect();
        v.sort();
        v
    }
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"edge closing");
    }
}

// ---------------------------------------------------------------- the certificate

fn server_config(cert: &Cert) -> Result<quinn::ServerConfig, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("the certificate could not be read: {e}"))?;
    if chain.is_empty() {
        return Err("no certificate in the PEM".into());
    }
    let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).map_err(|e| format!("the key could not be read: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("the certificate and key do not go together: {e}"))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.max_idle_timeout(Some(IDLE.try_into().unwrap()));
    transport.max_concurrent_bidi_streams(1u32.into()); // the station's sign-in stream
    transport.max_concurrent_uni_streams(0u32.into());
    server.transport_config(Arc::new(transport));
    Ok(server)
}

async fn load_cert(cfg_files: &Option<(String, String)>, api: &Api) -> Result<Option<Cert>, String> {
    match cfg_files {
        Some((c, k)) => {
            let cert_pem = std::fs::read_to_string(c).map_err(|e| format!("{c}: {e}"))?;
            let key_pem = std::fs::read_to_string(k).map_err(|e| format!("{k}: {e}"))?;
            Ok(Some(Cert { cert_pem, key_pem }))
        }
        None => {
            let api = api.clone();
            tokio::task::spawn_blocking(move || api.cert()).await.map_err(|e| e.to_string())?
        }
    }
}

// ---------------------------------------------------------------- starting

/// Start the edge: waits for its certificate (from the files, or until the worker has
/// issued it), then listens. Returns the addresses actually bound.
pub async fn start(cfg: Config) -> Result<Running, String> {
    let first = loop {
        match load_cert(&cfg.cert_files, &cfg.api).await {
            Ok(Some(c)) => break c,
            Ok(None) => say("edge.ROOT_DOMAIN's certificate is not issued yet; asking again in 60 s"),
            Err(e) if cfg.cert_files.is_some() => return Err(e),
            Err(e) => say(&format!("{e}; asking again in 60 s")),
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    };
    let endpoint = Endpoint::server(server_config(&first)?, cfg.quic).map_err(|e| format!("cannot listen on {} (UDP): {e}", cfg.quic))?;
    let quic = endpoint.local_addr().map_err(|e| e.to_string())?;
    let stations: Stations = Arc::default();
    let limits = Arc::new(Limits::new(cfg.per_address, cfg.total));
    let mut public = Vec::new();
    for addr in &cfg.public {
        let listener = TcpListener::bind(addr).await.map_err(|e| format!("cannot listen on {addr} (TCP): {e}"))?;
        let bound = listener.local_addr().map_err(|e| e.to_string())?;
        public.push(bound);
        let (stations, limits) = (stations.clone(), limits.clone());
        tokio::spawn(async move {
            loop {
                let Ok((tcp, from)) = listener.accept().await else { continue };
                let Some(guard) = limits.enter(from.ip()) else {
                    drop(tcp); // over a ceiling: closed, unanswered
                    continue;
                };
                let stations = stations.clone();
                tokio::spawn(async move {
                    let _guard = guard;
                    if let Err(e) = presenter(tcp, from, bound, stations).await {
                        // Routine (a scanner, a closed station); not worth more than a line.
                        let _ = e;
                    }
                });
            }
        });
    }
    // Stations.
    let (ep, st, api, recheck) = (endpoint.clone(), stations.clone(), cfg.api.clone(), cfg.recheck);
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let (st, api) = (st.clone(), api.clone());
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => station(conn, st, api, recheck).await,
                    Err(e) => say(&format!("a station's connection failed: {e}")),
                }
            });
        }
    });
    // The certificate, kept current (the worker renews it 30 days before it expires).
    let (ep, files, api) = (endpoint.clone(), cfg.cert_files.clone(), cfg.api.clone());
    tokio::spawn(async move {
        let mut current = first.cert_pem;
        loop {
            tokio::time::sleep(CERT_EVERY).await;
            match load_cert(&files, &api).await {
                Ok(Some(c)) if c.cert_pem != current => match server_config(&c) {
                    Ok(sc) => {
                        ep.set_server_config(Some(sc));
                        current = c.cert_pem;
                        say("took up a renewed certificate");
                    }
                    Err(e) => say(&format!("a renewed certificate could not be used: {e}")),
                },
                Ok(_) => {}
                Err(e) => say(&format!("could not check the certificate: {e}")),
            }
        }
    });
    say(&format!("listening: stations on {quic} (UDP), presenters on {}", public.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")));
    Ok(Running { quic, public, stations, endpoint })
}

// ---------------------------------------------------------------- a station

async fn ask(api: &Api, token: String) -> Result<Value, String> {
    let api = api.clone();
    tokio::task::spawn_blocking(move || api.auth(&token)).await.map_err(|e| e.to_string())?
}

async fn station(conn: Connection, stations: Stations, api: Api, recheck: Duration) {
    let from = conn.remote_address();
    let Ok(Ok((mut tx, rx))) = tokio::time::timeout(WITHIN, conn.accept_bi()).await else {
        return;
    };
    let mut rx = BufReader::new(rx.take(4096));
    let mut line = String::new();
    if !matches!(tokio::time::timeout(WITHIN, rx.read_line(&mut line)).await, Ok(Ok(n)) if n > 0) {
        return;
    }
    let hello: Value = serde_json::from_str(line.trim()).unwrap_or(Value::Null);
    let token = hello["token"].as_str().unwrap_or("").to_string();
    let answer = match ask(&api, token.clone()).await {
        Ok(a) => a,
        Err(e) => {
            say(&format!("a station at {from} could not be checked ({e}); told to try later"));
            json!({ "ok": false, "code": "try_later", "message": "The platform is busy; trying again shortly." })
        }
    };
    let fqdn = answer["fqdn"].as_str().map(str::to_ascii_lowercase);
    let reply = match (&answer["ok"], &fqdn) {
        (Value::Bool(true), Some(f)) => json!({ "ok": true, "fqdn": f }),
        _ => json!({ "ok": false, "code": answer["code"].as_str().unwrap_or("refused"),
                     "message": answer["message"].as_str().unwrap_or("The platform refused this station.") }),
    };
    let _ = tx.write_all(format!("{reply}\n").as_bytes()).await;
    let Some(fqdn) = fqdn.filter(|_| reply["ok"] == true) else {
        say(&format!("refused a station at {from}: {}", reply["code"]));
        let _ = tx.finish();
        tokio::time::sleep(Duration::from_millis(500)).await;
        conn.close(0u32.into(), b"refused");
        return;
    };
    // Now presenters' streams may be opened towards it (the edge opens them).
    if let Some(old) = stations.lock().unwrap().insert(fqdn.clone(), conn.clone()) {
        old.close(0u32.into(), b"replaced by a newer sign-in");
    }
    say(&format!("station {fqdn} signed in from {from}"));
    let mut tick = tokio::time::interval(recheck);
    tick.tick().await;
    let mut rest = [0u8; 64];
    let why = loop {
        tokio::select! {
            n = rx.read(&mut rest) => if !matches!(n, Ok(k) if k > 0) { break "it closed the tunnel".to_string() },
            e = conn.closed() => break format!("the connection ended ({e})"),
            _ = tick.tick() => match ask(&api, token.clone()).await {
                Ok(a) if a["ok"] == true && a["fqdn"].as_str().map(str::to_ascii_lowercase).as_deref() == Some(fqdn.as_str()) => {}
                // Renamed, suspended, deleted or signed out: it dials back and learns which.
                Ok(a) => break format!("the platform no longer has it as {fqdn} ({})", a["code"].as_str().unwrap_or("renamed")),
                // The API out of reach is no reason to cut a station off.
                Err(e) => say(&format!("could not re-check {fqdn} ({e}); keeping it")),
            },
        }
    };
    let _ = tx.finish();
    conn.close(0u32.into(), b"bye");
    let mut map = stations.lock().unwrap();
    if map.get(&fqdn).map(|c| c.stable_id()) == Some(conn.stable_id()) {
        map.remove(&fqdn);
    }
    say(&format!("station {fqdn} left: {why}"));
}

// ---------------------------------------------------------------- a presenter

async fn presenter(mut tcp: TcpStream, from: SocketAddr, to: SocketAddr, stations: Stations) -> Result<(), String> {
    let _ = tcp.set_nodelay(true);
    let record = tokio::time::timeout(WITHIN, first_record(&mut tcp)).await.map_err(|_| "no ClientHello in time")??;
    let name = sni::name(&record).ok_or("no name in the ClientHello")?;
    let conn = stations.lock().unwrap().get(&name).cloned().ok_or_else(|| format!("no station is signed in as {name}"))?;
    let (mut send, mut recv) = tokio::time::timeout(WITHIN, conn.open_bi())
        .await
        .map_err(|_| "the station took no new stream")?
        .map_err(|e| e.to_string())?;
    send.write_all(&proxy::encode(from, to)).await.map_err(|e| e.to_string())?;
    send.write_all(&record).await.map_err(|e| e.to_string())?;
    let (mut from_presenter, mut to_presenter) = tcp.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut from_presenter, &mut send).await;
        let _ = send.finish();
    };
    let down = async {
        let _ = tokio::io::copy(&mut recv, &mut to_presenter).await;
        let _ = to_presenter.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

async fn first_record(tcp: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut head = [0u8; 5];
    tcp.read_exact(&mut head).await.map_err(|e| e.to_string())?;
    if head[0] != 22 {
        return Err("not a TLS handshake".into());
    }
    let len = u16::from_be_bytes([head[3], head[4]]) as usize;
    if len > sni::MAX_RECORD {
        return Err("the record is too long".into());
    }
    let mut record = head.to_vec();
    record.resize(5 + len, 0);
    tcp.read_exact(&mut record[5..]).await.map_err(|e| e.to_string())?;
    Ok(record)
}

// ---------------------------------------------------------------- limits

/// Open presenter connections per address and in all (Nova's `nova/api/limits.py`).
pub struct Limits {
    per_address: usize,
    total: usize,
    open: Mutex<HashMap<IpAddr, usize>>,
    count: AtomicUsize,
}

pub struct Guard {
    limits: Arc<Limits>,
    ip: IpAddr,
}

impl Limits {
    pub fn new(per_address: usize, total: usize) -> Limits {
        Limits { per_address, total, open: Mutex::default(), count: AtomicUsize::new(0) }
    }

    pub fn enter(self: &Arc<Self>, ip: IpAddr) -> Option<Guard> {
        let mut open = self.open.lock().unwrap();
        let mine = open.get(&ip).copied().unwrap_or(0);
        if mine >= self.per_address || self.count.load(Ordering::Relaxed) >= self.total {
            return None;
        }
        open.insert(ip, mine + 1);
        self.count.fetch_add(1, Ordering::Relaxed);
        Some(Guard { limits: self.clone(), ip })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let mut open = self.limits.open.lock().unwrap();
        match open.get(&self.ip).copied().unwrap_or(0) {
            0 | 1 => {
                open.remove(&self.ip);
            }
            n => {
                open.insert(self.ip, n - 1);
            }
        }
        self.limits.count.fetch_sub(1, Ordering::Relaxed);
    }
}
