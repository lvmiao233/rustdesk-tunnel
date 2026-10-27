//! SSH transport inside the tunnel: the RustDesk port-forward pipe carries
//! exactly one SSH connection to the device's sshd, and every local forward
//! becomes a `direct-tcpip` channel inside it. Since RustDesk drops its
//! session key when the pipe goes raw, this SSH layer is the actual
//! end-to-end encryption for forwarded data — the relay only ever sees SSH
//! ciphertext.

use crate::config::Ssh as SshConfig;
use crate::session::Tunnel;
use anyhow::{bail, Context, Result};
use russh::client::{Handle, Handler};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};

/// Wraps the tunnel's raw stream so bytes the session handshake already read
/// (e.g. the device sshd's banner) are seen by russh first.
struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: TcpStream,
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = std::cmp::min(buf.remaining(), self.prefix.len() - self.pos);
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Trust-on-first-use host key pin: stores the device sshd's fingerprint on
/// the first connection and refuses any later mismatch. The RustDesk leg
/// already verifies the device identity; this closes the loop for SSH.
#[derive(Clone)]
struct KeyPin {
    path: PathBuf,
    pinned: Arc<Mutex<Option<String>>>,
}

impl KeyPin {
    fn fingerprint(key: &russh::keys::PublicKey) -> String {
        format!("{}", key.fingerprint(russh::keys::HashAlg::Sha256))
    }

    /// true when acceptable (first use pins, later uses must match).
    fn check_or_pin(&self, fingerprint: &str) -> bool {
        let mut pinned = self.pinned.lock().unwrap();
        match pinned.as_deref() {
            None => {
                *pinned = Some(fingerprint.to_string());
                if let Some(dir) = self.path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(&self.path, format!("{fingerprint}\n"));
                true
            }
            Some(p) => p == fingerprint,
        }
    }
}

struct ClientHandler {
    pin: KeyPin,
    dead: Arc<tokio::sync::Notify>,
}

impl Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = KeyPin::fingerprint(key);
        if self.pin.check_or_pin(&fp) {
            Ok(true)
        } else {
            eprintln!("ssh host key mismatch: pinned key != {fp}, refusing");
            Ok(false)
        }
    }

    async fn disconnected(
        &mut self,
        _reason: russh::client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        self.dead.notify_waiters();
        Ok(())
    }
}

pub struct SshTunnel {
    handle: std::sync::Arc<Handle<ClientHandler>>,
}

impl SshTunnel {
    /// Run SSH directly over the tunnel's raw pipe and authenticate.
    /// Returns the tunnel and a notify that fires when the session dies.
    pub async fn connect(
        tunnel: Tunnel,
        cfg: &SshConfig,
        state_dir: &std::path::Path,
    ) -> Result<(Self, Arc<tokio::sync::Notify>)> {
        let stream = PrefixedStream {
            prefix: tunnel.leftover,
            pos: 0,
            inner: tunnel.stream,
        };
        let pin_path = state_dir.join("known_host");
        let pinned = std::fs::read_to_string(&pin_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let pin = KeyPin {
            path: pin_path,
            pinned: Arc::new(Mutex::new(pinned)),
        };
        let dead = Arc::new(tokio::sync::Notify::new());

        let mut config = russh::client::Config::default();
        // keeps NAT/hbbr/peer inactivity timers fed through the raw pipe
        config.keepalive_interval = Some(std::time::Duration::from_secs(30));
        config.keepalive_max = 3;
        let config = Arc::new(config);

        let mut handle = russh::client::connect_stream(
            config,
            stream,
            ClientHandler { pin: pin.clone(), dead: dead.clone() },
        )
        .await
        .context("ssh handshake over tunnel")?;

        let authed = if let Some(key_path) = cfg.key_file.as_deref() {
            let key = russh::keys::load_secret_key(key_path, cfg.password.as_deref())
                .with_context(|| format!("load key {key_path}"))?;
            handle
                .authenticate_publickey(
                    &cfg.user,
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None),
                )
                .await
                .context("ssh publickey auth")?
        } else {
            let password = cfg
                .password
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("ssh: set password or key_file"))?;
            handle
                .authenticate_password(&cfg.user, password)
                .await
                .context("ssh password auth")?
        };
        if !matches!(authed, russh::client::AuthResult::Success) {
            bail!("ssh auth failed for {}: {:?}", cfg.user, authed);
        }
        Ok((Self { handle: std::sync::Arc::new(handle) }, dead))
    }

    /// Bind `rule.local` and forward every accepted connection as an SSH
    /// direct-tcpip channel to `rule.remote_host:port` (as reachable from
    /// the device). Returns the bound listener address.
    pub async fn spawn_forward(
        &self,
        rule: &crate::config::ForwardRule,
    ) -> Result<std::net::SocketAddr> {
        let listener = TcpListener::bind(rule.local)
            .await
            .with_context(|| format!("bind {}", rule.local))?;
        let addr = listener.local_addr()?;
        let handle = self.handle.clone();
        let rule = rule.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((sock, peer)) => {
                        let handle = handle.clone();
                        let rule = rule.clone();
                        tokio::spawn(async move {
                            if let Err(e) = forward_conn(sock, handle, &rule).await {
                                eprintln!(
                                    "forward {peer} -> {}:{}: {e:#}",
                                    rule.remote_host, rule.remote_port
                                );
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("forward listener {addr}: {e}");
                        break;
                    }
                }
            }
        });
        Ok(addr)
    }
}

async fn forward_conn(
    sock: TcpStream,
    handle: std::sync::Arc<Handle<ClientHandler>>,
    rule: &crate::config::ForwardRule,
) -> Result<()> {
    let channel = handle
        .channel_open_direct_tcpip(
            &rule.remote_host,
            rule.remote_port as u32,
            "127.0.0.1",
            0,
        )
        .await
        .with_context(|| format!("open channel to {}:{}", rule.remote_host, rule.remote_port))?;
    let mut stream = channel.into_stream();
    let mut sock = sock;
    tokio::io::copy_bidirectional(&mut sock, &mut stream).await?;
    Ok(())
}
