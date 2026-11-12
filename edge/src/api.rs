//! What the edge asks the platform's API (src/api/app.ts), with EDGE_TOKEN:
//!
//! - `POST /internal/edge/auth {token}`: is this station's token good, and what is its
//!   name? The answer is the very line the edge sends the station.
//! - `GET /internal/edge-cert`: edge.ROOT_DOMAIN's certificate and key (the worker issues
//!   and renews it); 404 until it is issued.
//!
//! Blocking calls (ureq), run off the async threads by the caller.

use std::time::Duration;

use serde_json::Value;

pub const TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct Api {
    base: String,
    token: String,
    agent: ureq::Agent,
}

/// The certificate and key, PEM.
pub struct Cert {
    pub cert_pem: String,
    pub key_pem: String,
}

impl Api {
    pub fn new(base: &str, token: &str) -> Api {
        Api {
            base: base.trim_end_matches('/').to_string(),
            token: token.to_string(),
            agent: ureq::AgentBuilder::new().timeout(TIMEOUT).build(),
        }
    }

    /// The API's answer for a station's token (`{ok, fqdn}` or `{ok:false, code, message}`);
    /// an error when the API could not be asked (the station is told to try later).
    pub fn auth(&self, station_token: &str) -> Result<Value, String> {
        let reply = self
            .agent
            .post(&format!("{}/internal/edge/auth", self.base))
            .set("Authorization", &format!("Bearer {}", self.token))
            .send_json(serde_json::json!({ "token": station_token }))
            .map_err(|e| format!("the API did not answer: {}", short(&e)))?;
        reply.into_json::<Value>().map_err(|e| format!("the API's answer was not understood: {e}"))
    }

    /// The edge's certificate; None while it is not issued yet.
    pub fn cert(&self) -> Result<Option<Cert>, String> {
        let got = self
            .agent
            .get(&format!("{}/internal/edge-cert", self.base))
            .set("Authorization", &format!("Bearer {}", self.token))
            .call();
        let reply = match got {
            Ok(r) => r,
            Err(ureq::Error::Status(404, _)) => return Ok(None),
            Err(e) => return Err(format!("the API did not give the certificate: {}", short(&e))),
        };
        let v: Value = reply.into_json().map_err(|e| e.to_string())?;
        match (v["cert_pem"].as_str(), v["key_pem"].as_str()) {
            (Some(c), Some(k)) => Ok(Some(Cert { cert_pem: c.to_string(), key_pem: k.to_string() })),
            _ => Err("the API's certificate answer had no certificate".into()),
        }
    }
}

/// An error without anything that could carry a secret (ureq prints the request line only).
fn short(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("status {code}"),
        ureq::Error::Transport(t) => t.kind().to_string(),
    }
}
