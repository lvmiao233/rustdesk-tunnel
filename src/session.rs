use crate::config::Config;
use crate::proto::message::Union as MsgUnion;
use crate::proto::port_forward_channel::Union as PfcUnion;
use crate::proto::*;
use anyhow::{anyhow, bail, Context, Result};
use prost::Message as _;
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::secretbox;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static CHANNEL_ID: AtomicI32 = AtomicI32::new(1);
const INITIAL_WINDOW: u32 = 64 * 1024;

pub struct Session {
    stream: TcpStream,
    send_key: secretbox::Key,
    recv_key: secretbox::Key,
    send_seq: u64,
    recv_buf: Vec<u8>,
    remote_host: String,
    remote_port: i32,
}

impl Session {
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
        let (peer_id, peer_ephemeral_pk, _kx_ver) =
            extract_peer_pk(&signed_id.id, server_pk_blob)?;
        eprintln!("peer identified: {peer_id}");
        let _ = peer_ephemeral_pk;

        // 2. PLAINTEXT: PublicKey with empty asymmetric_value → peer skips
        //    encryption ("Force to update pk") and continues to Connection::start
        let plaintext_pk = Message {
            union: Some(MsgUnion::PublicKey(PublicKey {
                asymmetric_value: Vec::new(),
                symmetric_value: Vec::new(),
                ..Default::default()
            })),
        };
        send_plain(&mut stream, &plaintext_pk).await?;
        eprintln!("sent PublicKey{{empty}} (plaintext mode)");

        // 3. Set up dummy keys (not used in plaintext mode)
        let dummy = secretbox::Key([0u8; secretbox::KEYBYTES]);
        let dummy2 = secretbox::Key([0u8; secretbox::KEYBYTES]);
        let (remote_host, remote_port) = cfg.remote()?;
        let mut session = Session {
            stream,
            send_key: dummy,
            recv_key: dummy2,
            send_seq: 0,
            recv_buf: Vec::new(),
            remote_host,
            remote_port,
        };

        // 4. Receive Hash challenge (plaintext)
        let hash_msg = session.recv().await?;
        let hash = match hash_msg.union {
            Some(MsgUnion::Hash(h)) => h,
            _ => bail!("expected Hash challenge, got unexpected message"),
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
        // PLAINTEXT MODE: no encryption
        self.stream.write_all(&plain).await?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            if !self.recv_buf.is_empty() {
                let buf = std::mem::take(&mut self.recv_buf);
                for data in [buf.as_slice(), buf.get(2..).unwrap_or(&[])] {
                    if data.is_empty() { continue; }
                    if let Ok(msg) = Message::decode(data) {
                        return Ok(msg);
                    }
                }
                self.recv_buf = buf;
            }
            let mut chunk = [0u8; 65536];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 { bail!("peer closed the connection"); }
            self.recv_buf.extend_from_slice(&chunk[..n]);
        }
    }

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
                                    Some(PfcUnion::Close(c)) => { channels.remove(&c.channel_id); }
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
                        Err(e) => { eprintln!("session error: {e}"); break; }
                    }
                }
                Some((ch_id, data)) = read_from_channels(&mut channels) => {
                    let fwd = Message {
                        union: Some(MsgUnion::PortForwardChannel(PortForwardChannel {
                            union: Some(PfcUnion::Data(PortForwardData {
                                channel_id: ch_id, data,
                            })),
                        })),
                    };
                    if self.send(&fwd).await.is_err() { break; }
                }
            }
        }
        eprintln!("tunnel closed");
        Ok(())
    }
}

async fn read_from_channels(
    channels: &mut HashMap<i32, TcpStream>,
) -> Option<(i32, Vec<u8>)> {
    let ch_ids: Vec<i32> = channels.keys().cloned().collect();
    for ch_id in ch_ids {
        if let Some(sock) = channels.get_mut(&ch_id) {
            let mut buf = vec![0u8; 16384];
            match sock.try_read(&mut buf) {
                Ok(0) => { channels.remove(&ch_id); }
                Ok(n) => { buf.truncate(n); return Some((ch_id, buf)); }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => { continue; }
                Err(_) => { channels.remove(&ch_id); }
            }
        }
    }
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

fn extract_peer_pk(signed_payload: &[u8], _server_blob: &[u8]) -> Result<(String, [u8; 32], u32)> {
    if signed_payload.len() < 66 { bail!("signed payload too short"); }
    let idpk_bytes = &signed_payload[64..];
    let idpk = IdPk::decode(idpk_bytes).context("decode IdPk")?;
    let mut pk = [0u8; 32];
    if idpk.pk.len() == 32 {
        pk.copy_from_slice(&idpk.pk);
        Ok((idpk.id, pk, idpk.kx_version))
    } else {
        bail!("peer pk wrong length: {}", idpk.pk.len())
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
        if let Ok(msg) = Message::decode(&buf[..]) { return Ok(msg); }
        if buf.len() > 2 {
            if let Ok(msg) = Message::decode(&buf[2..]) { return Ok(msg); }
        }
    }
}
