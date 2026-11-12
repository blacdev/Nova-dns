//! Which ports the edge listens on: the platform's, always (owner, 2026-11-12: the edge
//! listened on 25434 while the platform told stations 25433, and presenters were sent to a
//! port nothing of Nova's answered on). The platform is the one place they are set
//! (EDGE_HOST's port for stations, EDGE_PORTS for presenters; GET /internal/edge/config).
//! EDGE_QUIC / EDGE_PUBLIC on this machine may still choose the address to bind (an
//! interface), but their ports must be the platform's, or the edge refuses to start and says
//! which differ.

use std::collections::BTreeSet;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub quic: SocketAddr,
    pub public: Vec<SocketAddr>,
}

fn parse(text: &str, name: &str) -> Result<SocketAddr, String> {
    text.trim().parse().map_err(|_| format!("{name} has \"{}\", which is not an address like 0.0.0.0:443", text.trim()))
}

/// The addresses to listen on, from the platform's ports and this machine's optional settings.
pub fn resolve(quic_port: u16, ports: &[u16], env_quic: Option<&str>, env_public: Option<&str>) -> Result<Wanted, String> {
    if ports.is_empty() {
        return Err("the platform names no presenter ports (EDGE_PORTS)".into());
    }
    let quic = match env_quic {
        Some(v) => {
            let a = parse(v, "EDGE_QUIC")?;
            if a.port() != quic_port {
                return Err(format!(
                    "this machine's EDGE_QUIC says UDP port {}, but the platform tells stations {} (its EDGE_HOST). \
                     Remove EDGE_QUIC from deploy/edge/.env (./setup.sh edge does), or change the port on the platform (./setup.sh platform).",
                    a.port(), quic_port
                ));
            }
            a
        }
        None => SocketAddr::from(([0, 0, 0, 0], quic_port)),
    };
    let public = match env_public {
        Some(v) => {
            let given = v.split(',').filter(|s| !s.trim().is_empty()).map(|s| parse(s, "EDGE_PUBLIC")).collect::<Result<Vec<_>, _>>()?;
            let mine: BTreeSet<u16> = given.iter().map(|a| a.port()).collect();
            let theirs: BTreeSet<u16> = ports.iter().copied().collect();
            if mine != theirs {
                let list = |s: &BTreeSet<u16>| s.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                return Err(format!(
                    "this machine's EDGE_PUBLIC says TCP {}, but the platform tells stations {} (its EDGE_PORTS). \
                     Remove EDGE_PUBLIC from deploy/edge/.env (./setup.sh edge does), or change the ports on the platform (./setup.sh platform).",
                    list(&mine), list(&theirs)
                ));
            }
            given
        }
        None => ports.iter().map(|p| SocketAddr::from(([0, 0, 0, 0], *p))).collect(),
    };
    Ok(Wanted { quic, public })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_settings_here_the_platforms_ports_are_used() {
        let w = resolve(4433, &[25434], None, None).unwrap();
        assert_eq!(w.quic, "0.0.0.0:4433".parse().unwrap());
        assert_eq!(w.public, vec!["0.0.0.0:25434".parse().unwrap()]);
    }

    #[test]
    fn settings_here_may_choose_the_address_but_not_the_port() {
        let w = resolve(4433, &[25434], Some("10.10.0.182:4433"), Some("10.10.0.182:25434")).unwrap();
        assert_eq!(w.quic, "10.10.0.182:4433".parse().unwrap());
        // The owner's case: the edge on 25434, the platform telling stations 25433.
        let e = resolve(4433, &[25433], None, Some("0.0.0.0:25434")).unwrap_err();
        assert!(e.contains("TCP 25434") && e.contains("25433") && e.contains("EDGE_PORTS"), "{e}");
        let e = resolve(4433, &[25434], Some("0.0.0.0:443"), None).unwrap_err();
        assert!(e.contains("UDP port 443") && e.contains("4433"), "{e}");
        assert!(resolve(443, &[], None, None).is_err());
    }
}
