use crate::mangle;
use crate::proto::rendezvous_message::Union as RzUnion;
use crate::proto::*;
use anyhow::{bail, Result};
use prost::Message as _;
use rand::Rng;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

/// Ask hbbs to have the peer meet us at the relay server, then dial the relay.
/// Returns the raw TCP stream to hbbr with the UUID handshake done on both
/// sides (the peer connects independently; hbbr pairs by UUID).
pub async fn request_relay(
    server: &str,
    device_id: &str,
    relay_server: &str,
    timeout: Duration,
) -> Result<TcpStream> {
    let uuid = Uuid::new_v4().to_string();

    // Phase 1: tell hbbs to relay — peer will dial hbbr with this uuid
    let addr = crate::rendezvous::resolve_server(server)?;
    let mut s = TcpStream::connect(addr).await?;
    let req = RendezvousMessage {
        union: Some(RzUnion::RequestRelay(RequestRelay {
            id: device_id.to_owned(),
            uuid: uuid.clone(),
            relay_server: relay_server.to_owned(),
            ..Default::default()
        })),
    };
    // Relay requests go as a single protobuf frame (no prefix needed —
    // only PunchHoleRequest uses the TCP fallback prefix)
    s.write_all(&req.encode_to_vec()).await?;

    // Wait for RelayResponse confirming the peer has been notified
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            bail!("timeout waiting for relay response");
        }
        let n = tokio::time::timeout(remain, s.read(&mut chunk)).await??;
        if n == 0 {
            bail!("hbbs closed the connection");
        }
        buf.extend_from_slice(&chunk[..n]);
        for data in [buf.as_slice(), buf.get(2..).unwrap_or(&[])] {
            if data.is_empty() {
                continue;
            }
            if let Ok(msg) = RendezvousMessage::decode(data) {
                if let Some(RzUnion::RelayResponse(rr)) = msg.union {
                    if !rr.refuse_reason.is_empty() {
                        bail!("relay refused: {}", rr.refuse_reason);
                    }
                    // Phase 2: dial hbbr with the uuid
                    let relay_addr = if rr.relay_server.is_empty() {
                        crate::rendezvous::resolve_server(relay_server)?
                    } else {
                        crate::rendezvous::resolve_server(&rr.relay_server)?
                    };
                    drop(s); // release the hbbs connection
                    return dial_relay(relay_addr, &uuid, timeout).await;
                }
            }
        }
    }
}

/// Connect to hbbr and announce our UUID so it can pair us with the peer.
async fn dial_relay(
    relay_addr: std::net::SocketAddr,
    uuid: &str,
    timeout: Duration,
) -> Result<TcpStream> {
    let mut s = TcpStream::connect(relay_addr).await?;
    let req = RendezvousMessage {
        union: Some(RzUnion::RequestRelay(RequestRelay {
            uuid: uuid.to_owned(),
            ..Default::default()
        })),
    };
    s.write_all(&req.encode_to_vec()).await?;
    // hbbr doesn't respond — it just starts relaying once both sides arrive.
    // The stream from here on is a raw byte pipe to the peer.
    let _ = timeout;
    Ok(s)
}
