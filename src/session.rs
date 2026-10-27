use crate::config::Config;
use crate::proto::message::Union as MsgUnion;
use crate::proto::port_forward_channel::Union as PfcUnion;
use crate::proto::*;
use anyhow::{anyhow, bail, Context, Result};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use prost::Message as _;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static CHANNEL_ID: AtomicI32 = AtomicI32::new(1);
const INITIAL_WINDOW: u32 = 64 * 1024;

/// A established, encrypted port-forward session to the peer.
pub struct Session {
    stream: TcpStream,
    send_key: secretbox::Key,
    recv_key: secretbox::Key,
    send_seq: u64,
    current_recv_seq: u64,
    recv_buf: Vec<u8>,
    remote_host: String,
    remote_port: i32,
}

impl Session {
    /// Connect to the peer (direct address from punch), do the key exchange,
    /// login, and return the encrypted session.
    pub async fn connect_direct(
        peer_addr: std::net::SocketAddr,
        server_pk_blob: &[u8],
        cfg: &Config,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect(peer_addr)
            .await
            .context("connect to peer")?;

        // 1. Receive SignedId from peer
        let signed_id_msg = recv_plain(&mut stream).await?;
        let signed_id = match signed_id_msg.union {
            Some(MsgUnion::SignedId(sid)) => sid,
            _ => bail!("expected SignedId from peer"),
        };

        // Extract peer's ephemeral box pk from the signed blob
        let (peer_id, peer_ephemeral_pk, peer_kx_version) =
            extract_peer_pk(&signed_id.id, server_pk_blob)
                .context("extract peer pk from SignedId")?;
        eprintln!("peer identified: {peer_id}");

        let (our_pk, our_sk) = box_::gen_keypair();
        let sym_key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let their_pk = box_::PublicKey(peer_ephemeral_pk);
        let sealed_key = box_::seal(sym_key.0.as_ref(), &nonce, &their_pk, &our_sk);
        // Use the peer's advertised kx_version: 0 = single key, 1 = direction split
        let picked = peer_kx_version.min(1);
        let (send_key, recv_key) = if picked == 1 {
            let initiator_pk = our_pk.0;
            let responder_pk = peer_ephemeral_pk;
            (
                derive_subkey(&sym_key, 1, peer_kx_version, 1, &initiator_pk, &responder_pk),
                derive_subkey(&sym_key, 2, peer_kx_version, 1, &initiator_pk, &responder_pk),
            )
        } else {
            // v0: same key both directions
            let mut k2 = [0u8; secretbox::KEYBYTES];
            k2.copy_from_slice(sym_key.as_ref());
            (sym_key, secretbox::Key(k2))
        };

        // 3. Send PublicKey
        let pk_msg = Message {
            union: Some(MsgUnion::PublicKey(PublicKey {
                asymmetric_value: our_pk.0.to_vec(),
                symmetric_value: sealed_key,
                kx_version: picked,
                ..Default::default()
            })),
        };
        send_plain(&mut stream, &pk_msg).await?;

        let (remote_host, remote_port) = cfg.remote()?;
        let mut session = Session {
            stream,
            send_key,
            recv_key,
            send_seq: 0,
            current_recv_seq: 0,
            recv_buf: Vec::new(),
            remote_host,
            remote_port,
        };

        // 4. Receive Hash challenge (now encrypted)
        let hash_msg = session.recv().await?;
        let hash = match hash_msg.union {
            Some(MsgUnion::Hash(h)) => h,
            _ => bail!("expected Hash challenge, got {:?}", hash_msg.union.as_ref().map(|u| discriminant_name(u))),
        };

        // 5. Login with password
        let password = compute_password(&cfg.rustdesk.password, &hash.salt, &hash.challenge);
        let login = Message {
            union: Some(MsgUnion::LoginRequest(LoginRequest {
                password,
                my_id: "0".to_string(),
                my_name: "rdt".to_string(),
                session_id: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                version: "1.4.5".to_string(),
                my_platform: "Linux".to_string(),
                union: Some(login_request::Union::PortForward(PortForward {
                    host: session.remote_host.clone(),
                    port: session.remote_port,
                    multiplex: true,
                })),
                ..Default::default()
            })),
        };
        session.send(&login).await?;

        // 6. Verify LoginResponse
        let resp = session.recv().await?;
        match resp.union {
            Some(MsgUnion::LoginResponse(lr)) => match lr.union {
                Some(login_response::Union::PeerInfo(pi)) => {
                    eprintln!("logged in: {} ({}) — {}", pi.hostname, pi.platform, pi.version);
                }
                Some(login_response::Union::Error(e)) => bail!("login rejected: {e}"),
                _ => bail!("unexpected login response"),
            },
            _ => bail!("expected LoginResponse"),
        }

        Ok(session)
    }

    fn nonce(seq: u64) -> [u8; 24] {
        let mut n = [0u8; 24];
        n[..8].copy_from_slice(&seq.to_le_bytes());
        n
    }

    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        let plain = msg.encode_to_vec();
        self.send_seq += 1;
        let nonce = secretbox::Nonce(Self::nonce(self.send_seq));
        let cipher = secretbox::seal(&plain, &nonce, &self.send_key);
        self.stream.write_all(&cipher).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            // Try to decrypt what we already have
            if !self.recv_buf.is_empty() {
                let seq = self.recv_buf.len(); // not right; we need proper seq tracking
                let _ = seq;
                // For now, try decrypting the entire buffer as one message.
                // The peer encrypts one message per write, and our reads
                // should align with writes on the other side.
                let recv_seq = self.current_recv_seq + 1;
                let rn = secretbox::Nonce(Self::nonce(recv_seq));
                if let Ok(plain) = secretbox::open(&self.recv_buf[..], &rn, &self.recv_key) {
                    self.current_recv_seq = recv_seq;
                    self.recv_buf.clear();
                    return Message::decode(&plain[..])
                        .map_err(|e| anyhow!("decode decrypted: {e}"));
                }
            }
            // Read more data
            let mut chunk = [0u8; 65536];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                bail!("peer closed the connection");
            }
            self.recv_buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Serve the local port: accept connections, open mux channels, pipe data.
    pub async fn serve(mut self, listen_addr: std::net::SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(listen_addr).await?;
        eprintln!("tunnel active: {listen_addr} -> {}:{}",
            self.remote_host, self.remote_port);

        let mut channels: HashMap<i32, TcpStream> = HashMap::new();

        loop {
            tokio::select! {
                Ok((sock, addr)) = listener.accept() => {
                    let ch = CHANNEL_ID.fetch_add(1, Ordering::SeqCst);
                    eprintln!("ch{ch}: connect from {addr}");
                    channels.insert(ch, sock);
                    let open = Message {
                        union: Some(MsgUnion::PortForwardChannel(PortForwardChannel {
                            union: Some(PfcUnion::Open(PortForwardOpen {
                                channel_id: ch,
                                host: self.remote_host.clone(),
                                port: self.remote_port,
                                window: INITIAL_WINDOW,
                            })),
                        })),
                    };
                    self.send(&open).await?;
                }

                msg = self.recv() => {
                    match msg {
                        Ok(m) => {
                            if let Some(MsgUnion::PortForwardChannel(pfc)) = &m.union {
                                match &pfc.union {
                                    Some(PfcUnion::Data(d)) => {
                                        if let Some(sock) = channels.get_mut(&d.channel_id) {
                                            if sock.write_all(&d.data).await.is_err() {
                                                channels.remove(&d.channel_id);
                                            }
                                        }
                                    }
                                    Some(PfcUnion::Close(c)) => {
                                        channels.remove(&c.channel_id);
                                    }
                                    Some(PfcUnion::Opened(o)) => {
                                        if !o.success {
                                            eprintln!("ch{}: open failed: {}", o.channel_id, o.message);
                                            channels.remove(&o.channel_id);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("session error: {e}");
                            break;
                        }
                    }
                }

                // Read from local sockets and forward to peer
                Some((ch_id, data)) = read_from_channels(&mut channels) => {
                    let fwd = Message {
                        union: Some(MsgUnion::PortForwardChannel(PortForwardChannel {
                            union: Some(PfcUnion::Data(PortForwardData {
                                channel_id: ch_id,
                                data,
                            })),
                        })),
                    };
                    if self.send(&fwd).await.is_err() {
                        break;
                    }
                }
            }
        }
        eprintln!("tunnel closed");
        Ok(())
    }
}

/// Poll all channel sockets for readable data; return the first one with data.
async fn read_from_channels(
    channels: &mut HashMap<i32, TcpStream>,
) -> Option<(i32, Vec<u8>)> {
    // Simple approach: round-robin check each socket with a non-blocking read
    // In production this should use a proper select/poll mechanism
    let ch_ids: Vec<i32> = channels.keys().cloned().collect();
    for ch_id in ch_ids {
        if let Some(sock) = channels.get_mut(&ch_id) {
            let mut buf = vec![0u8; 16384];
            // Use a very short timeout to avoid blocking
            match sock.try_read(&mut buf) {
                Ok(0) => {
                    // Socket closed
                    channels.remove(&ch_id);
                }
                Ok(n) => {
                    buf.truncate(n);
                    return Some((ch_id, buf));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(_) => {
                    channels.remove(&ch_id);
                }
            }
        }
    }
    // Yield to let other tasks run
    tokio::task::yield_now().await;
    None
}

fn compute_password(password: &str, salt: &str, challenge: &str) -> Vec<u8> {
    let h1 = Sha256::digest(password.as_bytes());
    let mut h1s = Sha256::new();
    h1s.update(h1);
    h1s.update(salt.as_bytes());
    let h1 = h1s.finalize();
    let mut h2 = Sha256::new();
    h2.update(h1);
    h2.update(challenge.as_bytes());
    h2.finalize().to_vec()
}

/// Extract the peer's ephemeral box pk from the SignedId payload.
/// The payload structure: IdPk{id, pk} where pk is 32 bytes, with a 64-byte
/// ed25519 signature appended. We strip the signature and decode the IdPk.
fn extract_peer_pk(signed_payload: &[u8], _server_blob: &[u8]) -> Result<(String, [u8; 32], u32)> {
    // The peer's RustDesk code signs IdPk bytes with its static key and
    // sends sign(IdPk_bytes). We strip the 64-byte signature suffix.
    if signed_payload.len() < 64 + 2 {
        bail!("signed payload too short: {}", signed_payload.len());
    }
    let idpk_bytes = &signed_payload[64..];  // libsodium sign(): [64B sig][message]
    let idpk = IdPk::decode(idpk_bytes).context("decode IdPk")?;
    let mut pk = [0u8; 32];
    if idpk.pk.len() == 32 {
        pk.copy_from_slice(&idpk.pk);
        Ok((idpk.id, pk, idpk.kx_version))
    } else {
        bail!("peer pk wrong length: {} (want 32)", idpk.pk.len())
    }
}

async fn send_plain(stream: &mut TcpStream, msg: &Message) -> Result<()> {
    let bytes = msg.encode_to_vec();
    if std::env::var("RDT_DEBUG").is_ok() {
        eprintln!("TX plain {}B: {}", bytes.len(), hex::encode(&bytes));
    }
    stream.write_all(&bytes).await?;
    Ok(())
}

async fn recv_plain(stream: &mut TcpStream) -> Result<Message> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 { bail!("peer closed during handshake"); }
        buf.extend_from_slice(&chunk[..n]);
        if std::env::var("RDT_DEBUG").is_ok() && buf.len() == n {
            eprintln!("RX plain {}B: {}", n, hex::encode(&chunk[..n]));
        }
        // Session messages carry a 2-byte framing prefix before the protobuf;
        // try both the raw bytes and with the prefix stripped
        if let Ok(msg) = Message::decode(&buf[..]) { return Ok(msg); }
        if buf.len() > 2 {
            if let Ok(msg) = Message::decode(&buf[2..]) { return Ok(msg); }
        }
    }
}

fn discriminant_name(u: &MsgUnion) -> &'static str {
    match u {
        MsgUnion::SignedId(_) => "SignedId",
        MsgUnion::PublicKey(_) => "PublicKey",
        MsgUnion::LoginRequest(_) => "LoginRequest",
        MsgUnion::LoginResponse(_) => "LoginResponse",
        MsgUnion::Hash(_) => "Hash",
        MsgUnion::Misc(_) => "Misc",
        MsgUnion::PortForwardChannel(_) => "PortForwardChannel",
    }
}

fn derive_subkey(
    key: &secretbox::Key,
    direction: u8,
    advertised: u32,
    picked: u32,
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
) -> secretbox::Key {
    use sodiumoxide::crypto::generichash;
    let mut h = generichash::State::new(Some(secretbox::KEYBYTES), Some(key.as_ref())).unwrap();
    h.update(b"rdkx-spl").unwrap();
    h.update(&[direction]).unwrap();
    h.update(&advertised.to_le_bytes()).unwrap();
    h.update(&picked.to_le_bytes()).unwrap();
    h.update(initiator_pk).unwrap();
    h.update(responder_pk).unwrap();
    let digest = h.finalize().unwrap();
    let mut k = [0u8; secretbox::KEYBYTES];
    k.copy_from_slice(&digest[..secretbox::KEYBYTES]);
    secretbox::Key(k)
}
