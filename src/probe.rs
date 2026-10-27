use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// GET a plain-HTTP URL and report whether the body contains `expect`.
/// Hand-rolled HTTP/1.0 — the probe host is on our own network; TLS would
/// only add a dependency, the check is "did an answer come back at all".
pub async fn http_body_contains(url: &str, expect: &str, timeout_ms: u64) -> bool {
    match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        fetch_and_match(url, expect),
    )
    .await
    {
        Ok(Ok(v)) => v,
        _ => false,
    }
}

async fn fetch_and_match(url: &str, expect: &str) -> Result<bool> {
    let (host, port, path) = parse_http_url(url)?;
    let mut s = TcpStream::connect((host.as_str(), port)).await?;
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: rdt-probe\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 64 * 1024 {
                    break;
                }
                if buf.windows(expect.len()).any(|w| w == expect.as_bytes()) {
                    return Ok(true);
                }
            }
            Err(_) => break,
        }
    }
    Ok(buf.windows(expect.len()).any(|w| w == expect.as_bytes()))
}

fn parse_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("probe_url must be http:// for now: {url}"))?;
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse::<u16>()?)
        }
        _ => (auth.to_string(), 80),
    };
    Ok((host, port, path.to_string()))
}
