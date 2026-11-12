//! The edge end to end on one computer: a fake platform API (the two internal routes), a
//! test station speaking Nova's side of the protocol (blacdev/Nova apps/tunnel), and
//! presenters opening with a real rustls ClientHello.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nova_edge::api::Api;
use nova_edge::edge::{self, Running};
use quinn::Connection;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "edge.example.test";

// ---------------------------------------------------------------- a fake platform API

#[derive(Default)]
struct Platform {
    /// studio token -> station name; a missing token is unknown.
    tokens: HashMap<String, String>,
    suspended: Vec<String>,
    down: bool,
    cert: Option<(String, String)>,
    asked: usize,
}

async fn fake_api(platform: Arc<Mutex<Platform>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let platform = platform.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(tcp);
                let mut first = String::new();
                r.read_line(&mut first).await.unwrap();
                let (mut length, mut auth) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).await.unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    let lower = h.to_ascii_lowercase();
                    if let Some(v) = lower.strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap();
                    }
                    if lower.starts_with("authorization:") {
                        auth = h.trim().to_string();
                    }
                }
                let mut body = vec![0u8; length];
                r.read_exact(&mut body).await.unwrap();
                let (status, answer) = {
                    let mut p = platform.lock().unwrap();
                    p.asked += 1;
                    if p.down {
                        (503, json!({ "error": { "code": "internal", "message": "down" } }))
                    } else if !auth.ends_with("Bearer edge-token") {
                        (401, json!({ "error": { "code": "forbidden", "message": "Not allowed." } }))
                    } else if first.starts_with("POST /internal/edge/auth") {
                        let token = serde_json::from_slice::<Value>(&body).unwrap()["token"].as_str().unwrap_or("").to_string();
                        match p.tokens.get(&token) {
                            Some(f) if p.suspended.contains(f) => (200, json!({ "ok": false, "code": "suspended", "message": "This station is suspended." })),
                            Some(f) => (200, json!({ "ok": true, "fqdn": f, "studio_id": "s" })),
                            None => (200, json!({ "ok": false, "code": "invalid_token", "message": "Sign in again." })),
                        }
                    } else if first.starts_with("GET /internal/edge-cert") {
                        match &p.cert {
                            Some((c, k)) => (200, json!({ "cert_pem": c, "key_pem": k })),
                            None => (404, json!({ "error": { "code": "not_ready", "message": "Not issued yet." } })),
                        }
                    } else {
                        (404, json!({}))
                    }
                };
                let text = answer.to_string();
                let mut tcp = r.into_inner();
                let _ = tcp
                    .write_all(format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len()).as_bytes())
                    .await;
            });
        }
    });
    base
}

// ---------------------------------------------------------------- setting up

struct Rig {
    edge: Running,
    platform: Arc<Mutex<Platform>>,
    ca: Vec<u8>,
    dir: std::path::PathBuf,
}

fn certificate() -> (String, String, Vec<u8>) {
    let made = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
    (made.cert.pem(), made.key_pair.serialize_pem(), made.cert.der().to_vec())
}

async fn rig(name: &str, per_address: usize, recheck: Duration, cert_from_api: bool) -> Rig {
    let (cert_pem, key_pem, ca) = certificate();
    let dir = std::env::temp_dir().join(format!("nova-edge-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &key_pem).unwrap();
    let platform = Arc::new(Mutex::new(Platform::default()));
    {
        let mut p = platform.lock().unwrap();
        p.tokens.insert("good".into(), "kfm.example.test".into());
        if cert_from_api {
            p.cert = Some((cert_pem, key_pem));
        }
    }
    let base = fake_api(platform.clone()).await;
    let edge = edge::start(edge::Config {
        api: Api::new(&base, "edge-token"),
        quic: "127.0.0.1:0".parse().unwrap(),
        public: vec!["127.0.0.1:0".parse().unwrap(), "127.0.0.1:0".parse().unwrap()],
        cert_files: (!cert_from_api).then(|| (dir.join("cert.pem").display().to_string(), dir.join("key.pem").display().to_string())),
        per_address,
        total: 1000,
        recheck,
    })
    .await
    .unwrap();
    Rig { edge, platform, ca, dir }
}

// ---------------------------------------------------------------- a station (Nova's side)

struct Station {
    conn: Connection,
    answer: Value,
    seen: Arc<Mutex<Vec<SocketAddr>>>,
}

async fn station(rig: &Rig, token: &str) -> Station {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(rig.ca.clone())).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![edge::ALPN.to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(512u32.into());
    config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let conn = endpoint.connect(rig.edge.quic, NAME).unwrap().await.unwrap();
    let (mut tx, rx) = conn.open_bi().await.unwrap();
    tx.write_all(format!("{}\n", json!({ "v": 1, "token": token, "install_id": "t", "app_version": "0" })).as_bytes()).await.unwrap();
    let mut rx = BufReader::new(rx);
    let mut line = String::new();
    rx.read_line(&mut line).await.unwrap();
    let answer: Value = serde_json::from_str(line.trim()).unwrap();
    let seen: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
    let (c, s) = (conn.clone(), seen.clone());
    tokio::spawn(async move {
        let _keep = (tx, rx, endpoint); // the sign-in stream stays open while the tunnel is up
        while let Ok((mut send, mut recv)) = c.accept_bi().await {
            let s = s.clone();
            tokio::spawn(async move {
                let mut fixed = [0u8; 16];
                recv.read_exact(&mut fixed).await.unwrap();
                let mut header = vec![0u8; u16::from_be_bytes([fixed[14], fixed[15]]) as usize];
                recv.read_exact(&mut header).await.unwrap();
                assert_eq!(&fixed[..12], &nova_edge::proxy::SIGNATURE);
                let ip: [u8; 4] = header[0..4].try_into().unwrap();
                s.lock().unwrap().push(SocketAddr::from((ip, u16::from_be_bytes([header[8], header[9]]))));
                let _ = tokio::io::copy(&mut recv, &mut send).await; // an echo
                let _ = send.finish();
            });
        }
    });
    Station { conn, answer, seen }
}

/// The first bytes a browser sends to `name`: a real ClientHello.
fn client_hello(name: &str) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name.to_string().try_into().unwrap()).unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    out
}

/// A presenter: ClientHello and a body, everything echoed back by the station.
async fn present(at: SocketAddr, name: &str, body: &[u8]) -> Result<SocketAddr, String> {
    let mut tcp = TcpStream::connect(at).await.map_err(|e| e.to_string())?;
    let me = tcp.local_addr().unwrap();
    let mut sent = client_hello(name);
    sent.extend_from_slice(body);
    tcp.write_all(&sent).await.map_err(|e| e.to_string())?;
    let mut back = vec![0u8; sent.len()];
    match tokio::time::timeout(Duration::from_secs(5), tcp.read_exact(&mut back)).await {
        Ok(Ok(_)) if back == sent => Ok(me),
        Ok(Ok(_)) => Err("the bytes came back changed".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("nothing came back".into()),
    }
}

async fn until(what: &str, seconds: u64, mut check: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(seconds);
    while !check() {
        assert!(Instant::now() < end, "not within {seconds} s: {what}");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}

// ---------------------------------------------------------------- the tests

#[tokio::test(flavor = "multi_thread")]
async fn a_presenter_reaches_their_station_on_both_ports_with_their_own_address() {
    let rig = rig("reach", 96, Duration::from_secs(300), false).await;
    let st = station(&rig, "good").await;
    assert_eq!(st.answer, json!({ "ok": true, "fqdn": "kfm.example.test" }));
    assert_eq!(rig.edge.signed_in(), vec!["kfm.example.test".to_string()]);
    for port in &rig.edge.public {
        let me = present(*port, "KFM.example.test", b"GET /studio HTTP/1.1\r\n\r\n").await.unwrap();
        assert_eq!(st.seen.lock().unwrap().last(), Some(&me), "the station learns the presenter's address");
    }
    // Many at once, each their own bytes.
    let all: Vec<_> = (0..40u8)
        .map(|i| {
            let at = rig.edge.public[0];
            tokio::spawn(async move { present(at, "kfm.example.test", &vec![i; 32 * 1024]).await })
        })
        .collect();
    for a in all {
        a.await.unwrap().unwrap();
    }
    let _ = std::fs::remove_dir_all(&rig.dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_presenter_for_a_station_not_signed_in_is_closed_unanswered() {
    let rig = rig("nobody", 96, Duration::from_secs(300), false).await;
    let _st = station(&rig, "good").await;
    assert!(present(rig.edge.public[0], "other.example.test", b"x").await.is_err());
    let mut tcp = TcpStream::connect(rig.edge.public[0]).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: kfm.example.test\r\n\r\n").await.unwrap();
    let mut buf = [0u8; 8];
    let got = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await.unwrap();
    assert!(matches!(got, Ok(0) | Err(_)), "plain http gets nothing");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_platform_decides_who_signs_in() {
    let rig = rig("refuse", 96, Duration::from_secs(300), false).await;
    assert_eq!(station(&rig, "stale").await.answer["code"], "invalid_token");
    rig.platform.lock().unwrap().suspended.push("kfm.example.test".into());
    assert_eq!(station(&rig, "good").await.answer["code"], "suspended");
    rig.platform.lock().unwrap().suspended.clear();
    rig.platform.lock().unwrap().down = true;
    assert_eq!(station(&rig, "good").await.answer["code"], "try_later", "the API out of reach: try again shortly");
    assert!(rig.edge.signed_in().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_station_the_platform_no_longer_has_is_let_go_but_not_for_an_api_hiccup() {
    let rig = rig("recheck", 96, Duration::from_millis(300), false).await;
    let st = station(&rig, "good").await;
    rig.platform.lock().unwrap().down = true;
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(rig.edge.signed_in().len(), 1, "kept while the API is out of reach");
    rig.platform.lock().unwrap().down = false;
    rig.platform.lock().unwrap().tokens.insert("good".into(), "renamed.example.test".into());
    until("let go after the rename", 5, || rig.edge.signed_in().is_empty()).await;
    assert!(tokio::time::timeout(Duration::from_secs(5), st.conn.closed()).await.is_ok(), "its connection is closed, so it dials back");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_sign_in_takes_over_the_name() {
    let rig = rig("replace", 96, Duration::from_secs(300), false).await;
    let old = station(&rig, "good").await;
    let new = station(&rig, "good").await;
    assert!(tokio::time::timeout(Duration::from_secs(5), old.conn.closed()).await.is_ok());
    present(rig.edge.public[0], "kfm.example.test", b"x").await.unwrap();
    assert_eq!(new.seen.lock().unwrap().len(), 1);
    assert_eq!(old.seen.lock().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_from_one_address_are_limited() {
    let rig = rig("limits", 2, Duration::from_secs(300), false).await;
    let _st = station(&rig, "good").await;
    let held: Vec<TcpStream> = vec![
        TcpStream::connect(rig.edge.public[0]).await.unwrap(),
        TcpStream::connect(rig.edge.public[0]).await.unwrap(),
    ];
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(present(rig.edge.public[0], "kfm.example.test", b"x").await.is_err(), "a third is over the ceiling");
    drop(held);
    tokio::time::sleep(Duration::from_millis(200)).await;
    present(rig.edge.public[0], "kfm.example.test", b"x").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_certificate_comes_from_the_platform() {
    let rig = rig("cert", 96, Duration::from_secs(300), true).await;
    let st = station(&rig, "good").await;
    assert_eq!(st.answer["ok"], true, "the station trusted the certificate the API gave the edge");
}
