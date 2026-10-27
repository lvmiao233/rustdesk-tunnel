use crate::frame::{send_frame, Deframer};
use crate::mangle;
use crate::proto::punch_hole_response;
use crate::proto::rendezvous_message::Union as RzUnion;
use crate::proto::*;
use anyhow::{anyhow, bail, Result};
use prost::Message as _;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;

pub const NAT_TYPE_SYMMETRIC: i32 = 2;
pub const CLIENT_VERSION: &str = "1.4.5";

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
/// Everything on this connection uses hbb_common's length-prefix framing
/// (crate::frame). conn_type stays 0: hbbs closes TCP punches that carry
/// conn_type=PORT_FORWARD; the forward intent only matters in the session
/// LoginRequest. nat_type=SYMMETRIC forces the server down the TCP path.
pub async fn punch(
    server: &str,
    device_id: &str,
    licence_key: &str,
    timeout: Duration,
) -> Result<PunchInfo> {
    let addr = resolve_server(server)?;
    let mut s = TcpStream::connect(addr).await?;
    s.set_nodelay(true).ok();

    let req = RendezvousMessage {
        union: Some(RzUnion::PunchHoleRequest(PunchHoleRequest {
            id: device_id.to_owned(),
            nat_type: NAT_TYPE_SYMMETRIC,
            licence_key: licence_key.to_owned(),
            version: CLIENT_VERSION.to_owned(),
            ..Default::default()
        })),
    };
    send_frame(&mut s, &req.encode_to_vec()).await?;

    let mut df = Deframer::new();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remain = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remain.is_zero() {
            bail!("timeout waiting for punch response");
        }
        let payload = tokio::time::timeout(remain, df.recv(&mut s))
            .await
            .map_err(|_| anyhow!("timeout waiting for punch response"))??;
        let msg = RendezvousMessage::decode(payload.as_slice())?;
        match msg.union {
            Some(RzUnion::PunchHoleResponse(ph)) => {
                if ph.failure != 0 {
                    bail!("punch failed, failure code {}", ph.failure);
                }
                if ph.socket_addr.is_empty() {
                    continue;
                }
                let is_local =
                    matches!(ph.union, Some(punch_hole_response::Union::IsLocal(true)));
                return Ok(PunchInfo {
                    peer_addr: mangle::decode(&ph.socket_addr),
                    pk: ph.pk,
                    relay_server: ph.relay_server,
                    is_local,
                });
            }
            // intranet-first hbbs may send FetchLocalAddr first; also ignore
            // anything else that is not the response we are after
            _ => continue,
        }
    }
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
