//! RustDesk session protocol (plaintext mode): the verified flow is
//!
//! 1. peer sends framed `Hash{salt, challenge}` on connect
//! 2. we send framed `LoginRequest{password, .., port_forward{host, port}}`
//!    where password = sha256(sha256(pw || salt) || challenge)
//! 3. peer replies framed `LoginResponse{peer_info}` (or `{error}`)
//! 4. answering the peer's TestDelay probe flips the peer into raw mode —
//!    from then on the connection is a plain byte pipe to host:port
//!
//! Framing is hbb_common's BytesCodec (see crate::frame). One tunnel carries
//! exactly one forwarded TCP connection — the stock client does the same.

use crate::config::Config;
use crate::frame::{send_frame, Deframer};
use crate::proto::message::Union as MsgUnion;
use crate::proto::{Hash, LoginRequest, Message, PortForward, TestDelay};
use anyhow::{bail, Context, Result};
use prost::Message as _;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

pub const CLIENT_VERSION: &str = "1.4.5";

/// A stream that has completed the session handshake and switched to the
/// raw port-forward pipe. `leftover` holds bytes already read past the last
/// session frame — they belong to the pipe, not to the handshake.
pub struct Tunnel {
    pub stream: TcpStream,
    pub leftover: Vec<u8>,
    pub host: String,
    pub port: i32,
    pub peer_hostname: String,
}

/// Run the full handshake over an established connection (direct or relayed).
pub async fn handshake(mut stream: TcpStream, cfg: &Config, peer: &str) -> Result<Tunnel> {
    stream.set_nodelay(true).ok();
    let mut df = Deframer::new();

    // 1. Hash challenge (tolerate permission Miscs and an early TestDelay).
    //    Probes are answered exactly when they arrive — mirroring the stock
    //    client — and never afterwards: once authorized with no probe pending
    //    the peer flips the stream to raw, and a late echo would leak framing
    //    bytes into the forwarded data.
    let hash = loop {
        let payload = df.recv(&mut stream).await.context("waiting for Hash")?;
        let msg = Message::decode(payload.as_slice()).context("decode session message")?;
        match msg.union {
            Some(MsgUnion::Hash(h)) => break h,
            Some(MsgUnion::TestDelay(_)) => {
                send_frame(&mut stream, &echo_test_delay()).await?;
                continue;
            }
            Some(MsgUnion::SignedId(_)) => {
                bail!("{peer}: peer insists on the secure (SignedId) handshake")
            }
            _ => continue,
        }
    };

    // 2. login with port forward
    let password = hash_password(&cfg.rustdesk.password, &hash.salt, &hash.challenge);
    let (host, port) = cfg.remote()?;
    let lr = LoginRequest {
        username: peer.to_string(),
        password,
        my_id: cfg.rustdesk.device_id.clone(),
        my_name: "rdt".to_string(),
        session_id: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        version: CLIENT_VERSION.to_string(),
        my_platform: "Linux".to_string(),
        union: Some(crate::proto::login_request::Union::PortForward(PortForward {
            host: host.clone(),
            port,
        })),
        ..Default::default()
    };
    let msg = Message {
        union: Some(MsgUnion::LoginRequest(lr)),
    };
    send_frame(&mut stream, &msg.encode_to_vec())
        .await
        .context("send LoginRequest")?;

    // 3. wait for LoginResponse; keep answering probes on the way
    let peer_hostname;
    loop {
        let payload = df.recv(&mut stream).await.context("waiting for LoginResponse")?;
        let msg = Message::decode(payload.as_slice()).context("decode session message")?;
        match msg.union {
            Some(MsgUnion::LoginResponse(resp)) => match resp.union {
                Some(crate::proto::login_response::Union::PeerInfo(pi)) => {
                    peer_hostname = format!("{} ({})", pi.hostname, pi.platform);
                    break;
                }
                Some(crate::proto::login_response::Union::Error(e)) => {
                    bail!("{peer}: login rejected: {e}")
                }
                _ => bail!("{peer}: empty LoginResponse"),
            },
            Some(MsgUnion::TestDelay(_)) => {
                send_frame(&mut stream, &echo_test_delay()).await?;
                continue;
            }
            _ => continue,
        }
    }

    // The peer breaks its main loop as soon as it is authorized AND has no
    // pending probe, then switches the stream to raw. Anything buffered past
    // the last session frame is pipe data.
    let leftover = df.take_remaining();
    if !leftover.is_empty() && std::env::var("RDT_DEBUG").is_ok() {
        eprintln!("pipe leftover: {}B", leftover.len());
    }
    Ok(Tunnel {
        stream,
        leftover,
        host,
        port,
        peer_hostname,
    })
}

/// The probe echo: an empty TestDelay. The peer sent TestDelay{} (all default
/// fields), and its handler treats a from_client=false message as the answer.
fn echo_test_delay() -> Vec<u8> {
    Message {
        union: Some(MsgUnion::TestDelay(TestDelay::default())),
    }
    .encode_to_vec()
}

pub fn hash_password(password: &str, salt: &str, challenge: &str) -> Vec<u8> {
    let h1 = Sha256::new()
        .chain_update(password.as_bytes())
        .chain_update(salt.as_bytes())
        .finalize();
    Sha256::new()
        .chain_update(h1)
        .chain_update(challenge.as_bytes())
        .finalize()
        .to_vec()
}

/// Bidirectional pipe between an accepted local connection and a tunnel.
pub async fn forward(mut local: TcpStream, mut tunnel: Tunnel) -> Result<()> {
    tunnel.stream.set_nodelay(true).ok();
    if !tunnel.leftover.is_empty() {
        local.write_all(&tunnel.leftover).await?;
    }
    let mut remote = tunnel.stream;
    tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

/// Accept loop: each local connection gets its own fresh tunnel.
/// `dial` establishes a new tunnel session (direct or relayed).
pub async fn serve<L, Fut>(listener: TcpListener, label: &str, dial: L) -> Result<()>
where
    L: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<Tunnel>> + Send + 'static,
{
    eprintln!("tunnel active: {} -> {label}", listener.local_addr()?);
    loop {
        let (mut sock, addr) = listener.accept().await?;
        let dial_fut = (dial)();
        tokio::spawn(async move {
            match dial_fut.await {
                Ok(tunnel) => {
                    if let Err(e) = forward(sock, tunnel).await {
                        eprintln!("conn {addr}: {e:#}");
                    }
                }
                Err(e) => {
                    eprintln!("dial for {addr}: {e:#}");
                    // best effort: reset so the local client sees the failure
                    let _ = sock.shutdown().await;
                }
            }
        });
    }
}

// keep Hash referenced so the import stays meaningful for future readers
#[allow(dead_code)]
fn _hash_type_check(_: Hash) {}
