//! App orchestrator: campus-aware lifecycle for the full stack
//!
//!   probe → (on campus) idle            — no tunnel at all, as required
//!         → (off campus) one RustDesk tunnel (secure login, raw pipe)
//!            carrying one SSH session whose direct-tcpip channels are the
//!            local forwards
//!
//! Reconnects with backoff; publishes state transitions on a watch channel
//! for the CLI/GUI to render.

use crate::config::Config;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Notify};

#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    Probing,
    /// on campus: no tunnel, direct access
    CampusIdle,
    /// off campus: bringing up tunnel + ssh + forwards
    Connecting(String),
    /// stack is up; one entry per forward rule (label, local addr)
    Active {
        peer: String,
        encrypted_login: bool,
        forwards: Vec<(String, std::net::SocketAddr)>,
    },
    Failed(String),
    Stopped,
}

impl Phase {
    pub fn label(&self) -> String {
        match self {
            Phase::Probing => "探测校园网".into(),
            Phase::CampusIdle => "校内直连（隧道闲置）".into(),
            Phase::Connecting(w) => format!("连接中：{w}"),
            Phase::Active { peer, forwards, .. } => {
                format!("已连接 {peer}，{} 条转发", forwards.len())
            }
            Phase::Failed(e) => format!("失败：{e}"),
            Phase::Stopped => "已停止".into(),
        }
    }
}

/// External control handle (CLI Ctrl-C / GUI buttons).
#[derive(Clone)]
pub struct AppHandle {
    stop: Arc<Notify>,
    state: watch::Receiver<Phase>,
}

impl AppHandle {
    pub fn stop(&self) {
        self.stop.notify_waiters();
    }
    pub fn subscribe(&self) -> watch::Receiver<Phase> {
        self.state.clone()
    }
    pub fn phase(&self) -> Phase {
        self.state.borrow().clone()
    }
}

pub fn spawn(cfg: Config, force: bool) -> AppHandle {
    let (state_tx, state_rx) = watch::channel(Phase::Probing);
    let stop = Arc::new(Notify::new());
    let app = App {
        cfg: Arc::new(cfg),
        state_tx,
        stop: stop.clone(),
        force,
    };
    tokio::spawn(app.run());
    AppHandle {
        stop,
        state: state_rx,
    }
}

struct App {
    cfg: Arc<Config>,
    state_tx: watch::Sender<Phase>,
    stop: Arc<Notify>,
    force: bool,
}

impl App {
    fn set(&self, p: Phase) {
        eprintln!("state: {}", p.label());
        let _ = self.state_tx.send(p);
    }

    async fn run(self) {
        let mut backoff = 1u64;
        loop {
            let on_campus = crate::probe::http_body_contains(
                &self.cfg.campus.probe_url,
                &self.cfg.campus.probe_expect,
                self.cfg.campus.probe_timeout_ms,
            )
            .await;
            if on_campus && !self.force {
                self.set(Phase::CampusIdle);
                // idle on campus; re-probe periodically or stop
                if self.wait_or_stop(Duration::from_secs(30)).await.is_err() {
                    self.set(Phase::Stopped);
                    return;
                }
                continue;
            }
            match self.run_stack().await {
                Ok(()) => {
                    self.set(Phase::Stopped);
                    return;
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    self.set(Phase::Failed(msg.clone()));
                    eprintln!("stack error: {msg}");
                    let secs = backoff.min(30);
                    if self.wait_or_stop(Duration::from_secs(secs)).await.is_err() {
                        self.set(Phase::Stopped);
                        return;
                    }
                    backoff = (backoff * 2).min(30);
                }
            }
        }
    }

    /// Bring the whole stack up and monitor it until it dies or we're stopped.
    async fn run_stack(&self) -> Result<()> {
        self.set(Phase::Connecting("打洞请求".into()));
        let punch = crate::rendezvous::punch(
            &self.cfg.rustdesk.server,
            &self.cfg.rustdesk.device_id,
            &self.cfg.rustdesk.key,
            Duration::from_secs(10),
        )
        .await
        .context("hbbs punch")?;

        // The SSH layer requires the pipe to end at the device sshd; if the
        // config still points somewhere else we refuse — that data would
        // cross the relay unencrypted.
        let (_, rp) = self.cfg.remote()?;
        if self.cfg.ssh.is_some() && rp != 22 {
            anyhow::bail!(
                "with [ssh] configured, service.remote_addr must be the device sshd (port 22), got port {rp}"
            );
        }

        // Always relay. Our intranet-first hbbs reports is_local=true to every
        // punch (so stock clients try the LAN instantly), which says nothing
        // about where WE are; and on campus the probe keeps the tunnel idle
        // entirely, so there is no direct case worth dialing here.
        self.set(Phase::Connecting("中继连接".into()));
        let relay_server = if punch.relay_server.is_empty() {
            self.cfg.rustdesk.server.clone()
        } else {
            punch.relay_server.clone()
        };
        let stream = crate::relay::open(
            &self.cfg.rustdesk.server,
            &self.cfg.rustdesk.device_id,
            &self.cfg.rustdesk.key,
            &relay_server,
            Duration::from_secs(15),
        )
        .await
        .context("relay")?;

        self.set(Phase::Connecting("会话登录".into()));
        let tunnel = crate::session::handshake(
            stream,
            &self.cfg,
            &self.cfg.rustdesk.device_id,
            Some(&punch.pk),
        )
        .await
        .context("session")?;

        let Some(ssh_cfg) = self.cfg.ssh.as_ref() else {
            anyhow::bail!("no [ssh] section: refusing to serve unencrypted forwards; configure [ssh] and [[forward]]");
        };

        self.set(Phase::Connecting("SSH 通道".into()));
        let peer_hostname = tunnel.peer_hostname.clone();
        let encrypted_login = tunnel.encrypted_login;
        let (ssh, dead) = crate::ssh::SshTunnel::connect(tunnel, ssh_cfg, &Config::state_dir()).await?;
        let mut bound = Vec::new();
        for rule in &self.cfg.forwards {
            let addr = ssh.spawn_forward(rule).await?;
            bound.push((
                format!("{} → {}:{}", rule.local, rule.remote_host, rule.remote_port),
                addr,
            ));
        }
        if bound.is_empty() {
            anyhow::bail!("no [[forward]] rules configured");
        }
        self.set(Phase::Active {
            peer: peer_hostname,
            encrypted_login,
            forwards: bound,
        });
        // monitor: ssh session death or stop signal
        tokio::select! {
            _ = dead.notified() => anyhow::bail!("ssh session closed"),
            _ = self.stop.notified() => return Ok(()),
        }
    }

    /// Ok(()) = elapsed, Err(()) = stop requested
    async fn wait_or_stop(&self, d: Duration) -> Result<(), ()> {
        tokio::select! {
            _ = tokio::time::sleep(d) => Ok(()),
            _ = self.stop.notified() => Err(()),
        }
    }
}
