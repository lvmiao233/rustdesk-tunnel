use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// AddrMangle decode, ported from hbb_common/src/lib.rs. v4 addresses are
/// packed as `((ip + tm) << 49) | (tm << 17) | (port + (tm & 0xFFFF))` with
/// trailing zero bytes trimmed; v6 is 16 bytes of address + LE port.
pub fn decode(bytes: &[u8]) -> SocketAddr {
    if bytes.len() > 16 {
        if bytes.len() != 18 {
            return SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
        }
        let port = u16::from_le_bytes([bytes[16], bytes[17]]);
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&bytes[..16]);
        return SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port);
    }
    let mut padded = [0u8; 16];
    padded[..bytes.len()].copy_from_slice(bytes);
    let number = u128::from_le_bytes(padded);
    let tm = (number >> 17) & (u32::MAX as u128);
    let ip = (((number >> 49) - tm) as u32).to_le_bytes();
    let port = (number & 0xFFFFFF) - (tm & 0xFFFF);
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        port as u16,
    )
}
