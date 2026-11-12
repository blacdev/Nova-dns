//! The tunnel's edge for Nova's Remote Studio (blacdev/Nova docs/TUNNEL.md): a station
//! that opens no port on its router dials in here over QUIC; presenters' browsers connect
//! here, and each connection is passed down to its station, still encrypted.

pub mod api;
pub mod edge;
pub mod log;
pub mod ports;
pub mod proxy;
pub mod sni;
