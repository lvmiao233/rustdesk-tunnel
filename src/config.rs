use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub rustdesk: Rustdesk,
    pub service: Service,
    pub local: Local,
    pub campus: Campus,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct Service {
    /// remote service address as seen from the device (usually 127.0.0.1:port)
    pub remote_addr: String,
}

#[derive(Debug, Deserialize)]
pub struct Local {
    /// local listen address, what your programs connect to off campus
    pub listen: SocketAddr,
}

#[derive(Debug, Deserialize)]
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
}
