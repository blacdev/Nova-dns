//! The PROXY protocol, version 2 (HAProxy's): the bytes the edge writes at the start of
//! each presenter's stream, so the station knows who the presenter is. Nova reads them at
//! its tunnel entrance (blacdev/Nova `nova/api/proxyproto.py`); the same bytes as Nova's
//! `apps/tunnel/src/proxy.rs`.

use std::net::{IpAddr, SocketAddr};

pub const SIGNATURE: [u8; 12] = [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A];

/// The header for a presenter at `from` who reached the edge at `to`.
pub fn encode(from: SocketAddr, to: SocketAddr) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.push(0x21); // version 2, PROXY
    match (from.ip(), to.ip()) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            out.push(0x11); // TCP over IPv4
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&a.octets());
            out.extend_from_slice(&b.octets());
        }
        (a, b) => {
            let six = |ip: IpAddr| match ip {
                IpAddr::V4(v) => v.to_ipv6_mapped(),
                IpAddr::V6(v) => v,
            };
            out.push(0x21); // TCP over IPv6
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&six(a).octets());
            out.extend_from_slice(&six(b).octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
    out.extend_from_slice(&to.port().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_what_nova_reads() {
        let h = encode("203.0.113.7:51234".parse().unwrap(), "198.51.100.1:443".parse().unwrap());
        assert_eq!(&h[..12], &SIGNATURE);
        assert_eq!((h[12], h[13], u16::from_be_bytes([h[14], h[15]])), (0x21, 0x11, 12));
        assert_eq!(&h[16..20], &[203, 0, 113, 7]);
        assert_eq!(u16::from_be_bytes([h[24], h[25]]), 51234);
        let v6 = encode("[2001:db8::5]:4000".parse().unwrap(), "198.51.100.1:443".parse().unwrap());
        assert_eq!((v6[13], v6.len()), (0x21, 16 + 36));
    }
}
