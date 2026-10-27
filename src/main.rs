mod config;
mod crypto;
mod frame;
mod mangle;
mod probe;
mod proto;
mod rendezvous;
mod relay;
mod session;


use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "rdt — rustdesk-tunnel core (P0)

USAGE:
  rdt --config <path> probe              report campus state from the HTTP probe
  rdt --config <path> punch              hbbs rendezvous, print peer address
  rdt --config <path> relay              open a relay pipe + session handshake
  rdt --config <path> direct <host:port> tunnel via direct connection (e.g. 127.0.0.1:21118)
  rdt --config <path> connect            campus-aware: idle on campus, tunnel off campus
";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path = String::from("rdt.toml");
    let mut cmd = String::new();
    let mut cmd_arg = String::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                cfg_path = args.get(i).cloned().unwrap_or_default();
            }
            "--force" | "-f" => {
                std::env::set_var("RDT_FORCE", "1");
            }
            other => {
                if cmd.is_empty() {
                    cmd = other.to_string();
                } else if cmd_arg.is_empty() {
                    cmd_arg = other.to_string();
                }
            }
        }
        i += 1;
    }
    if cmd.is_empty() {
        eprint!("{USAGE}");
        std::process::exit(2);
    }
    let cfg = match config::Config::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e:#}");
            std::process::exit(1);
        }
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run(&cmd, &cmd_arg, &cfg));
    std::process::exit(code);
}

async fn run(cmd: &str, arg: &str, cfg: &config::Config) -> i32 {
    match cmd {
        "probe" => probe_cmd(cfg).await,
        "punch" => punch_cmd(cfg).await,
        "relay" => relay_cmd(cfg).await,
        "direct" => direct_cmd(cfg, arg).await,
        "connect" => connect_cmd(cfg).await,
        other => {
            eprintln!("unknown command: {other}\n{USAGE}");
            2
        }
    }
}

async fn probe_cmd(cfg: &config::Config) -> i32 {
    let on_campus = probe::http_body_contains(
        &cfg.campus.probe_url,
        &cfg.campus.probe_expect,
        cfg.campus.probe_timeout_ms,
    )
    .await;
    println!("campus={on_campus}");
    0
}

async fn punch_cmd(cfg: &config::Config) -> i32 {
    match rendezvous::punch(
        &cfg.rustdesk.server,
        &cfg.rustdesk.device_id,
        &cfg.rustdesk.key,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(info) => {
            println!("peer_addr={}", info.peer_addr);
            println!("is_local={}", info.is_local);
            println!("relay_server={}", info.relay_server);
            println!("pk_len={}", info.pk.len());
            0
        }
        Err(e) => {
            eprintln!("punch failed: {e:#}");
            1
        }
    }
}

/// Tunnel through a direct connection to a RustDesk peer (host:port of its
/// direct-access listener, e.g. 127.0.0.1:21118 for a local test).
async fn direct_cmd(cfg: &config::Config, addr: &str) -> i32 {
    let addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("usage: rdt direct <host:port>  (got {addr:?})");
            return 2;
        }
    };
    let listener = match tokio::net::TcpListener::bind(cfg.local.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {}: {e}", cfg.local.listen);
            return 1;
        }
    };
    let (rh, rp) = cfg.remote().unwrap();
    let label = format!("{rh}:{rp}");
    let cfg = Arc::new(cfg.clone());
    let dial = move || {
        let cfg = cfg.clone();
        async move {
            let s = tokio::net::TcpStream::connect(addr).await?;
            session::handshake(s, &cfg, &addr.to_string(), None).await
        }
    };
    match session::serve(listener, &label, dial).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("serve: {e:#}");
            1
        }
    }
}

async fn relay_cmd(cfg: &config::Config) -> i32 {
    let punch = match rendezvous::punch(
        &cfg.rustdesk.server,
        &cfg.rustdesk.device_id,
        &cfg.rustdesk.key,
        Duration::from_secs(10),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("punch for relay info failed: {e:#}");
            return 1;
        }
    };
    let relay_server = if punch.relay_server.is_empty() {
        cfg.rustdesk.server.clone()
    } else {
        punch.relay_server.clone()
    };
    eprintln!("opening relay via {relay_server}...");
    let stream = match relay::open(
        &cfg.rustdesk.server,
        &cfg.rustdesk.device_id,
        &cfg.rustdesk.key,
        &relay_server,
        Duration::from_secs(15),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("relay failed: {e:#}");
            return 1;
        }
    };
    eprintln!("relay pipe established, starting session handshake...");
    match session::handshake(stream, cfg, &cfg.rustdesk.device_id, Some(&punch.pk)).await {
        Ok(t) => {
            eprintln!(
                "logged in via relay: {} -> {}:{}",
                t.peer_hostname, t.host, t.port
            );
            0
        }
        Err(e) => {
            eprintln!("session failed: {e:#}");
            1
        }
    }
}

async fn connect_cmd(cfg: &config::Config) -> i32 {
    let on_campus = probe::http_body_contains(
        &cfg.campus.probe_url,
        &cfg.campus.probe_expect,
        cfg.campus.probe_timeout_ms,
    )
    .await;
    if on_campus && std::env::var("RDT_FORCE").is_err() {
        println!("campus=true, tunnel idle (direct access available)");
        return 0;
    }
    println!("campus=false (or forced), establishing tunnel...");

    let listener = match tokio::net::TcpListener::bind(cfg.local.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind {}: {e}", cfg.local.listen);
            return 1;
        }
    };

    // dialer: try direct punch first, fall back to relay
    let (rh, rp) = cfg.remote().unwrap();
    let label = format!("{rh}:{rp}");
    let cfg = Arc::new(cfg.clone());
    let server = cfg.rustdesk.server.clone();
    let device_id = cfg.rustdesk.device_id.clone();
    let key = cfg.rustdesk.key.clone();
    let dial = move || {
        let cfg = cfg.clone();
        let server = server.clone();
        let device_id = device_id.clone();
        let key = key.clone();
        async move {
            let punch = rendezvous::punch(&server, &device_id, &key, Duration::from_secs(10))
                .await?;
            if punch.is_local && std::env::var("RDT_RELAY").is_err() {
                match tokio::net::TcpStream::connect(punch.peer_addr).await {
                    Ok(s) => {
                        return session::handshake(s, &cfg, &punch.peer_addr.to_string(), None).await
                    }
                    Err(e) => eprintln!("direct {e}, falling back to relay"),
                }
            }
            let relay_server = if punch.relay_server.is_empty() {
                server.clone()
            } else {
                punch.relay_server.clone()
            };
            let stream =
                relay::open(&server, &device_id, &key, &relay_server, Duration::from_secs(15))
                    .await?;
            session::handshake(stream, &cfg, &cfg.rustdesk.device_id, Some(&punch.pk)).await
        }
    };

    match session::serve(listener, &label, dial).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("serve: {e:#}");
            1
        }
    }
}
