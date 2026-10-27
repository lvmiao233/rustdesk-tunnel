//! RustDesk session protocol. Verified flow (plaintext and secure):
//!
//! secure (relay, `RequestRelay{secure:true}`):
//!   1. peer sends framed `SignedId{id: sign(IdPk{id, eph_pk}, peer_static_sk)}`
//!   2. we verify the two-level signature chain — rendezvous-server-signed
//!      pk from the punch (trust anchor = configured server key), then the
//!      SignedId — and reply `PublicKey{asym: our_eph_pk, sym: box_(key)}`
//!   3. every further frame is secretbox-sealed (crate::crypto)
//!   4. `Hash` -> `LoginRequest{password, port_forward}` -> `LoginResponse`
//!   5. answering the peer's TestDelay probe flips the stream to raw mode
//!
//! plaintext (direct-IP listener): the peer sends `Hash` straight away.
//!
//! After the flip the connection is a plain byte pipe to host:port — the
//! RustDesk code drops the session key at that point (`set_raw`), so the
//! pipe itself is not session-encrypted on any peer version.

use crate::config::Config;
use crate::crypto::Encrypt;
use crate::frame::{send_frame, Deframer};
use crate::proto::message::Union as MsgUnion;
use crate::proto::{IdPk, LoginRequest, Message, PortForward, PublicKey, TestDelay};
use anyhow::{anyhow, bail, Context, Result};
use prost::Message as _;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::{box_, secretbox, sign};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

pub const CLIENT_VERSION: &str = "1.4.5";

/// Framed message I/O with optional per-frame secretbox sealing.
struct SessionIo {
    stream: TcpStream,
    df: Deframer,
    enc: Option<Encrypt>,
}

impl SessionIo {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            df: Deframer::new(),
            enc: None,
        }
    }

    async fn send_msg(&mut self, msg: &Message) -> Result<()> {
        let mut plain = msg.encode_to_vec();
        if let Some(e) = self.enc.as_mut() {
            plain = e.enc(&plain);
        }
        send_frame(&mut self.stream, &plain).await
    }

    async fn recv_msg(&mut self) -> Result<Message> {
        let payload = self.df.recv(&mut self.stream).await?;
        let plain = match self.enc.as_mut() {
            Some(e) => e.dec(&payload)?,
            None => payload,
        };
        Message::decode(plain.as_slice()).context("decode session message")
    }
}

/// A stream that has completed the session handshake and switched to the
/// raw port-forward pipe. `leftover` holds bytes already read past the last
/// session frame — they belong to the pipe, not to the handshake.
pub struct Tunnel {
    pub stream: TcpStream,
    pub leftover: Vec<u8>,
    pub host: String,
    pub port: i32,
    pub peer_hostname: String,
    pub encrypted_login: bool,
}

/// Run the full handshake over an established connection (direct or relayed).
/// `peer_signed_pk` is the punch response's server-signed IdPk blob — required
/// to verify the peer when it demands the secure handshake.
pub async fn handshake(
    stream: TcpStream,
    cfg: &Config,
    peer: &str,
    peer_signed_pk: Option<&[u8]>,
) -> Result<Tunnel> {
    let mut stream = stream;
    stream.set_nodelay(true).ok();
    let mut io = SessionIo::new(stream);
    let mut encrypted_login = false;

    // First frame decides the mode: SignedId => secure, Hash => plaintext.
    // An early TestDelay is answered either way.
    let first = io.recv_msg().await.context("waiting for first session message")?;
    let hash = match first.union {
        Some(MsgUnion::SignedId(sid)) => {
            let punch_pk = peer_signed_pk.ok_or_else(|| {
                anyhow!("{peer}: peer demands secure handshake but no signed pk from punch")
            })?;
            io.enc = Some(secure_handshake(&mut io, cfg, peer, &sid.id, punch_pk).await?);
            encrypted_login = true;
            eprintln!("{peer}: secure handshake ok (session encrypted)");
            expect_hash(&mut io, peer).await?
        }
        Some(MsgUnion::Hash(h)) => {
            eprintln!("{peer}: peer is in plaintext mode");
            h
        }
        Some(MsgUnion::TestDelay(_)) => {
            send_test_delay_echo(&mut io).await?;
            expect_hash(&mut io, peer).await?
        }
        _ => bail!("{peer}: unexpected first message, expected SignedId or Hash"),
    };

    // Login with port forward
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
    io.send_msg(&Message {
        union: Some(MsgUnion::LoginRequest(lr)),
    })
    .await
    .context("send LoginRequest")?;

    // Wait for LoginResponse; keep answering probes on the way. Probes are
    // answered exactly when they arrive — mirroring the stock client — and
    // never afterwards: once authorized with no probe pending the peer
    // flips the stream to raw, and a late echo would leak framing bytes
    // into the forwarded data.
    let peer_hostname;
    loop {
        let msg = io.recv_msg().await.context("waiting for LoginResponse")?;
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
                send_test_delay_echo(&mut io).await?;
                continue;
            }
            _ => continue,
        }
    }

    // Raw mode from here (the peer drops the session key; so do we).
    let leftover = io.df.take_remaining();
    if !leftover.is_empty() && std::env::var("RDT_DEBUG").is_ok() {
        eprintln!("pipe leftover: {}B", leftover.len());
    }
    Ok(Tunnel {
        stream: io.stream,
        leftover,
        host,
        port,
        peer_hostname,
        encrypted_login,
    })
}

async fn expect_hash(io: &mut SessionIo, _peer: &str) -> Result<crate::proto::Hash> {
    loop {
        let msg = io.recv_msg().await.context("waiting for Hash")?;
        match msg.union {
            Some(MsgUnion::Hash(h)) => return Ok(h),
            Some(MsgUnion::TestDelay(_)) => {
                send_test_delay_echo(io).await?;
                continue;
            }
            _ => continue,
        }
    }
}

/// Verify the peer and negotiate the symmetric key (KX v0, matching 1.4.x
/// peers; there is no kx_version negotiation on the wire for them).
async fn secure_handshake(
    io: &mut SessionIo,
    cfg: &Config,
    peer: &str,
    signed_id_blob: &[u8],
    punch_pk: &[u8],
) -> Result<Encrypt> {
    // level 1: punch pk signed by the rendezvous server (trust anchor:
    // base64 id_ed25519.pub from our config)
    let rs_pk = server_sign_pk(&cfg.rustdesk.key)?;
    let (level1_id, peer_static) = decode_signed_id_pk(punch_pk, &rs_pk, peer)?;
    if level1_id != cfg.rustdesk.device_id {
        bail!("{peer}: punch pk is for id {level1_id}, expected {}", cfg.rustdesk.device_id);
    }
    // level 2: SignedId signed by the peer's static key
    let (level2_id, peer_ephemeral) =
        decode_signed_id_pk(signed_id_blob, &sign::PublicKey(peer_static), peer)?;
    if level2_id != cfg.rustdesk.device_id {
        bail!("{peer}: SignedId is for id {level2_id}");
    }

    // key exchange: fresh ephemeral box pair, random symmetric key sealed
    // to the peer's ephemeral pk under a zero nonce, as the stock client does
    let (our_pk, our_sk) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let zero_nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed =
        box_::seal(&key.0, &zero_nonce, &box_::PublicKey(peer_ephemeral), &our_sk);
    io.send_msg(&Message {
        union: Some(MsgUnion::PublicKey(PublicKey {
            asymmetric_value: our_pk.0.to_vec(),
            symmetric_value: sealed,
            ..Default::default()
        })),
    })
    .await
    .context("send PublicKey")?;
    Ok(Encrypt::new(key))
}

fn server_sign_key(base64_key: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(base64_key.trim())
        .context("decode server key base64")?;
    if raw.len() != sign::PUBLICKEYBYTES {
        bail!("server key must be {} bytes, got {}", sign::PUBLICKEYBYTES, raw.len());
    }
    let mut pk = [0u8; sign::PUBLICKEYBYTES];
    pk.copy_from_slice(&raw);
    Ok(pk)
}

fn server_sign_pk(base64_key: &str) -> Result<sign::PublicKey> {
    Ok(sign::PublicKey(server_sign_key(base64_key)?))
}

/// libsodium `sign` prepends the 64-byte signature to the message, so
/// `verify` returns exactly the IdPk protobuf.
fn decode_signed_id_pk(
    signed_blob: &[u8],
    pk: &sign::PublicKey,
    peer: &str,
) -> Result<(String, [u8; 32])> {
    let idpk_bytes = sign::verify(signed_blob, pk)
        .map_err(|_| anyhow!("{peer}: signature verification failed"))?;
    let idpk = IdPk::decode(idpk_bytes.as_slice()).context("decode IdPk")?;
    if idpk.pk.len() != box_::PUBLICKEYBYTES {
        bail!("{peer}: IdPk pk wrong length: {}", idpk.pk.len());
    }
    let mut pk = [0u8; box_::PUBLICKEYBYTES];
    pk.copy_from_slice(&idpk.pk);
    Ok((idpk.id, pk))
}

/// The probe echo: an empty TestDelay. The peer sent TestDelay{} (all default
/// fields), and its handler treats a from_client=false message as the answer.
async fn send_test_delay_echo(io: &mut SessionIo) -> Result<()> {
    io.send_msg(&Message {
        union: Some(MsgUnion::TestDelay(TestDelay::default())),
    })
    .await
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
                    let _ = sock.shutdown().await;
                }
            }
        });
    }
}
