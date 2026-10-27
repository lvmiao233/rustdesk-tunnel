use rustdesk_tunnel::{app, config, probe, rendezvous, relay, session};
use std::time::Duration;

const USAGE: &str = "rdt — rustdesk-tunnel

USAGE:
  rdt --config <path> up                full stack: campus probe -> tunnel -> SSH -> forwards
  rdt --config <path> probe             report campus state
  rdt --config <path> punch             hbbs rendezvous, print peer address
  rdt --config <path> relay             open relay pipe + session handshake (encrypted)
  rdt --config <path> connect           plain single-forward tunnel (no SSH layer)
  rdt --config <path> direct <host:port> tunnel via direct peer listener (e.g. 127.0.0.1:21118)

FLAGS:
  -f, --force     ignore campus probe and bring the tunnel up anyway
  RDT_RELAY=1     force the relay path even when a direct one exists
";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path = String::from("rdt.toml");
    let mut cmd = String::new();
    let mut cmd_arg = String::new();
    let mut force = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                cfg_path = args.get(i).cloned().unwrap_or_default();
            }
            "--force" | "-f" => force = true,
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
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let code = rt.block_on(run(&cmd, &cmd_arg, cfg, force));
    std::process::exit(code);
}

async fn run(cmd: &str, arg: &str, cfg: config::Config, force: bool) -> i32 {
    match cmd {
        "probe" => probe_cmd(&cfg).await,
        "punch" => punch_cmd(&cfg).await,
        "relay" => relay_cmd(&cfg).await,
        "up" => up_cmd(cfg, force).await,
        "connect" => connect_cmd(&cfg, force).await,
        "direct" => direct_cmd(&cfg, arg).await,
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
                "logged in via relay: {} -> {}:{} (encrypted_login={})",
                t.peer_hostname, t.host, t.port, t.encrypted_login
            );
            0
        }
        Err(e) => {
            eprintln!("session failed: {e:#}");
            1
        }
    }
}

/// Full stack with the SSH layer inside the tunnel.
async fn up_cmd(cfg: config::Config, force: bool) -> i32 {
    let handle = app::spawn(cfg, force);
    let mut state = handle.subscribe();
    loop {
        if state.changed().await.is_err() {
            break;
        }
        let p = state.borrow().clone();
        if let app::Phase::Active { forwards, .. } = &p {
            eprintln!("forwards:");
            for (label, addr) in forwards {
                eprintln!("  {addr}  {label}");
            }
        }
        if p == app::Phase::Stopped {
            return 0;
        }
    }
    0
}

/// Plain single-forward tunnel, no SSH layer (legacy/testing).
async fn connect_cmd(cfg: &config::Config, force: bool) -> i32 {
    let on_campus = probe::http_body_contains(
        &cfg.campus.probe_url,
        &cfg.campus.probe_expect,
        cfg.campus.probe_timeout_ms,
    )
    .await;
    if on_campus && !force {
        println!("campus=true, tunnel idle (direct access available)");
        return 0;
    }
    println!("campus=false (or forced), establishing tunnel...");

    let listener = match tokio::net::TcpListener::bind(
        cfg.local
            .as_ref()
            .map(|l| l.listen)
            .unwrap_or_else(|| "127.0.0.1:49825".parse().unwrap()),
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind: {e}");
            return 1;
        }
    };

    let dial_cfg = std::sync::Arc::new(cfg.clone());
    let dial = move || {
        let cfg = dial_cfg.clone();
        async move {
            let punch = rendezvous::punch(
                &cfg.rustdesk.server,
                &cfg.rustdesk.device_id,
                &cfg.rustdesk.key,
                Duration::from_secs(10),
            )
            .await?;
            let relay_server = if punch.relay_server.is_empty() {
                cfg.rustdesk.server.clone()
            } else {
                punch.relay_server.clone()
            };
            let stream = relay::open(
                &cfg.rustdesk.server,
                &cfg.rustdesk.device_id,
                &cfg.rustdesk.key,
                &relay_server,
                Duration::from_secs(15),
            )
            .await?;
            session::handshake(stream, &cfg, &cfg.rustdesk.device_id, Some(&punch.pk)).await
        }
    };

    let (rh, rp) = cfg.remote().unwrap();
    match session::serve(listener, &format!("{rh}:{rp}"), dial).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("serve: {e:#}");
            1
        }
    }
}

/// Tunnel through a direct connection to a RustDesk peer listener.
async fn direct_cmd(cfg: &config::Config, addr: &str) -> i32 {
    let addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("usage: rdt direct <host:port>  (got {addr:?})");
            return 2;
        }
    };
    let listener = match tokio::net::TcpListener::bind(
        cfg.local
            .as_ref()
            .map(|l| l.listen)
            .unwrap_or_else(|| "127.0.0.1:49825".parse().unwrap()),
    )
    .await
    {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind: {e}");
            return 1;
        }
    };
    let dial_cfg = std::sync::Arc::new(cfg.clone());
    let dial = move || {
        let cfg = dial_cfg.clone();
        async move {
            let s = tokio::net::TcpStream::connect(addr).await?;
            session::handshake(s, &cfg, &addr.to_string(), None).await
        }
    };
    let (rh, rp) = cfg.remote().unwrap();
    match session::serve(listener, &format!("{rh}:{rp}"), dial).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("serve: {e:#}");
            1
        }
    }
}
