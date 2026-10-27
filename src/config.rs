use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rustdesk: Rustdesk,
    pub campus: Campus,
    /// device-side target of the RustDesk port forward — normally the
    /// device's own sshd, since the SSH layer inside is the data encryption
    #[serde(default = "default_service")]
    pub service: Service,
    /// legacy single-listener mode (plain tunnel, no SSH layer)
    #[serde(default)]
    pub local: Option<Local>,
    #[serde(default)]
    pub ssh: Option<Ssh>,
    /// local forwards served over the in-tunnel SSH session
    #[serde(default, rename = "forward")]
    pub forwards: Vec<ForwardRule>,
}

fn default_service() -> Service {
    Service {
        remote_addr: "127.0.0.1:22".to_string(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rustdesk {
    /// hbbs address, host:port (default port 21116)
    pub server: String,
    /// id_ed25519.pub contents (base64), the trust anchor
    pub key: String,
    /// device id of the machine running the service
    pub device_id: String,
    /// its permanent RustDesk password
    pub password: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    /// address as seen from the device; the SSH layer requires the sshd
    pub remote_addr: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Local {
    /// local listen address, what your programs connect to off campus
    pub listen: SocketAddr,
}

/// SSH login for the in-tunnel SSH session (the end-to-end data encryption).
#[derive(Debug, Clone, Deserialize)]
pub struct Ssh {
    pub user: String,
    /// either password or key_file must be set
    pub password: Option<String>,
    pub key_file: Option<String>,
}

/// One forwarded port: `local` listens here, traffic exits from the device
/// to `remote_host:remote_port`.
#[derive(Debug, Clone, Deserialize)]
pub struct ForwardRule {
    pub local: SocketAddr,
    pub remote_host: String,
    pub remote_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Campus {
    /// plain-HTTP URL that only answers on campus
    pub probe_url: String,
    /// response body must contain this to count as on campus
    pub probe_expect: String,
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,
}

fn default_probe_timeout_ms() -> u64 {
    2000
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        toml::from_str(&raw).with_context(|| format!("parse {path}"))
    }

    pub fn remote(&self) -> Result<(String, i32)> {
        let (h, p) = self
            .service
            .remote_addr
            .rsplit_once(':')
            .context("remote_addr must be host:port")?;
        Ok((h.to_string(), p.parse().context("remote port")?))
    }

    /// State dir for runtime files (pinned host key, logs). XDG-ish.
    pub fn state_dir() -> std::path::PathBuf {
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| {
                    let mut p = std::path::PathBuf::from(h);
                    p.push(".local/state");
                    p
                })
            })
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join("rdt")
    }
}
