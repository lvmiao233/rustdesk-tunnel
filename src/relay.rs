//! Relay path: ask hbbs to have the peer meet us on hbbr, then dial hbbr.
//!
//! Flow (all rendezvous messages length-prefixed, see crate::frame):
//! 1. TCP to hbbs, framed RequestRelay{id, uuid, relay_server, licence_key}
//!    — hbbs forwards it to the peer over UDP; nothing comes back to us, so
//!    we can drop the hbbs connection right away.
//! 2. TCP to hbbr, framed RequestRelay{uuid, licence_key}. hbbr parks the
//!    first side and pairs when the second arrives (both must arrive within
//!    ~30s), then flips both sides to raw mode — a plain byte pipe.
//! 3. The RustDesk session handshake (Hash / LoginRequest / TestDelay) runs
//!    inside that pipe between us and the peer, also framed.

use crate::frame::{send_frame};
use crate::proto::rendezvous_message::Union as RzUnion;
use crate::proto::*;
use anyhow::{Context, Result};
use prost::Message as _;
use std::time::Duration;
use tokio::net::TcpStream;
use uuid::Uuid;

/// Resolve `host[:port]` against the hbbr default port 21117.
fn resolve_relay(server: &str) -> anyhow::Result<std::net::SocketAddr> {
    let with_port = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:21117")
    };
    if let Ok(a) = with_port.parse() {
        return Ok(a);
    }
    use std::net::ToSocketAddrs;
    let mut addrs = with_port.to_socket_addrs().context("resolve relay")?;
    addrs.next().context("no address for relay")
}

pub async fn open(
    server: &str,
    device_id: &str,
    licence_key: &str,
    relay_server: &str,
    _timeout: Duration,
) -> Result<TcpStream> {
    let uuid = Uuid::new_v4().to_string();

    // 1. tell hbbs; the peer dials hbbr on its own once notified
    let hbbs_addr = crate::rendezvous::resolve_server(server)?;
    let mut s = TcpStream::connect(hbbs_addr).await?;
    s.set_nodelay(true).ok();
    let req = RendezvousMessage {
        union: Some(RzUnion::RequestRelay(RequestRelay {
            id: device_id.to_owned(),
            uuid: uuid.clone(),
            relay_server: relay_server.to_owned(),
            licence_key: licence_key.to_owned(),
            ..Default::default()
        })),
    };
    send_frame(&mut s, &req.encode_to_vec())
        .await
        .context("send RequestRelay to hbbs")?;
    drop(s);

    // 2. dial hbbr and announce the same uuid — hbbr pairs the two sides and
    //    turns the connection into a raw pipe
    let hbbr_addr = resolve_relay(relay_server)?;
    let mut r = TcpStream::connect(hbbr_addr).await?;
    r.set_nodelay(true).ok();
    let announce = RendezvousMessage {
        union: Some(RzUnion::RequestRelay(RequestRelay {
            uuid: uuid.clone(),
            licence_key: licence_key.to_owned(),
            ..Default::default()
        })),
    };
    send_frame(&mut r, &announce.encode_to_vec())
        .await
        .context("send RequestRelay to hbbr")?;
    if std::env::var("RDT_DEBUG").is_ok() {
        eprintln!("relay {uuid}: announced on {hbbr_addr}");
    }
    Ok(r)
}
