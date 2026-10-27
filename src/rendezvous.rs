use crate::mangle;
use crate::proto::punch_hole_response;
use crate::proto::rendezvous_message::Union as RzUnion;
use crate::proto::*;
use anyhow::{anyhow, bail, Result};
use prost::Message as _;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const CONN_TYPE_PORT_FORWARD: i32 = 2;
pub const NAT_TYPE_SYMMETRIC: i32 = 2;
pub const CLIENT_VERSION: &str = "1.4.5";
/// TCP fallback prefix the stock client prepends before the first protobuf
/// message on a fresh rendezvous connection; without it hbbs drops the frame.
pub const TCP_PUNCH_PREFIX: [u8; 2] = [0x11, 0x01];

/// What came back from a punch request.
pub struct PunchInfo {
    /// the peer's address as our intranet-first hbbs reports it (its LAN addr)
    pub peer_addr: SocketAddr,
    /// server-signed IdPk blob (peer id + peer static sign pk inside)
    pub pk: Vec<u8>,
    pub relay_server: String,
    pub is_local: bool,
}

/// Send a PunchHoleRequest to hbbs over TCP and wait for the PunchHoleResponse.
///
/// The wire format mirrors what the stock client sends on TCP fallback: a
/// two-byte prefix, then the protobuf PunchHoleRequest carrying the server's
/// public key in `licence_key` and `nat_type = SYMMETRIC` (both required by
/// hbbs, or the frame is silently dropped).
pub async fn punch(
    server: &str,
    device_id: &str,
    licence_key: &str,
    timeout: Duration,
) -> Result<PunchInfo> {
    let addr = resolve_server(server)?;
    let mut s = TcpStream::connect(addr).await?;

    // conn_type must be left at 0 here: hbbs silently closes the connection
    // on a TCP punch carrying conn_type=PORT_FORWARD; it only matters later
    // in the LoginRequest on the peer session
    let req = RendezvousMessage {
        union: Some(RzUnion::PunchHoleRequest(PunchHoleRequest {
            id: device_id.to_owned(),
            nat_type: NAT_TYPE_SYMMETRIC,
            licence_key: licence_key.to_owned(),
            version: CLIENT_VERSION.to_owned(),
            ..Default::default()
        })),
    };
    // Two writes so the server sees the prefix and the protobuf as separate
    // frames — a single combined frame fails to parse server-side.
    let wire = req.encode_to_vec();
    if std::env::var("RDT_DEBUG").is_ok() {
        eprintln!("TX prefix={} protobuf={}B hex={}", hex::encode(TCP_PUNCH_PREFIX), wire.len(), hex::encode(&wire));
    }
    s.write_all(&TCP_PUNCH_PREFIX).await?;
    // Brief pause so the two writes land as separate TCP reads server-side;
    // coalesced into one frame, hbbs cannot parse the combination
    tokio::time::sleep(Duration::from_millis(5)).await;
    s.write_all(&wire).await?;

    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            bail!("timeout waiting for punch response");
        }
        let n = tokio::time::timeout(remain, s.read(&mut chunk)).await??;
        if n == 0 {
            bail!("hbbs closed the connection before answering");
        }
        buf.extend_from_slice(&chunk[..n]);
        if std::env::var("RDT_DEBUG").is_ok() {
            eprintln!("RX {}B: {}", n, hex::encode(&chunk[..n]));
        }
        if let Some(info) = try_parse_response(&buf)? {
            return Ok(info);
        }
    }
}

fn try_parse_response(buf: &[u8]) -> Result<Option<PunchInfo>> {
    // hbbs responses carry a 2-byte framing prefix (observed as 41 02); try
    // the raw bytes first, then with the prefix stripped
    for data in [buf, buf.get(2..).unwrap_or(&[])] {
        if data.is_empty() {
            continue;
        }
        if let Ok(msg) = RendezvousMessage::decode(data) {
            if let Some(RzUnion::PunchHoleResponse(ph)) = msg.union {
                if ph.failure != 0 {
                    bail!("punch failed, failure code {}", ph.failure);
                }
                if ph.socket_addr.is_empty() {
                    continue;
                }
                let is_local =
                    matches!(ph.union, Some(punch_hole_response::Union::IsLocal(true)));
                return Ok(Some(PunchInfo {
                    peer_addr: mangle::decode(&ph.socket_addr),
                    pk: ph.pk,
                    relay_server: ph.relay_server,
                    is_local,
                }));
            }
        }
    }
    Ok(None)
}

pub fn resolve_server(server: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let with_port = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:21116")
    };
    if let Ok(a) = with_port.parse::<SocketAddr>() {
        return Ok(a);
    }
    let mut addrs = with_port
        .to_socket_addrs()
        .map_err(|e| anyhow!("resolve {with_port}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address for {with_port}"))
}
