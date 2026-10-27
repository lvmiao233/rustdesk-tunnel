mod config;
mod mangle;
mod probe;
mod proto;
mod rendezvous;
mod session;
mod relay;

use anyhow::Result;
use std::time::Duration;

const USAGE: &str = "rdt — rustdesk-tunnel core (P0)

USAGE:
  rdt --config <path> probe     report campus state from the HTTP probe
  rdt --config <path> punch     do the hbbs rendezvous and print the result
";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg_path = String::from("rdt.toml");
    let mut cmd = String::new();
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
            other => cmd = other.to_string(),
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
    let code = rt.block_on(run(&cmd, &cfg));
    std::process::exit(code);
}

async fn run(cmd: &str, cfg: &config::Config) -> i32 {
    match cmd {
        "probe" => probe_cmd(cfg).await,
        "punch" => punch_cmd(cfg).await,
        "relay" => relay_cmd(cfg).await,
        "connect" => connect_cmd(cfg).await,
            "relay" => relay_cmd(cfg).await,
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

async fn connect_cmd(cfg: &config::Config) -> i32 {
    // Check campus first
    let on_campus = probe::http_body_contains(
        &cfg.campus.probe_url,
        &cfg.campus.probe_expect,
        cfg.campus.probe_timeout_ms,
    ).await;
    if on_campus && std::env::var("RDT_FORCE").is_err() {
        println!("campus=true, tunnel idle (direct access available)");
        return 0;
    }
    println!("campus=false, establishing tunnel...");

    let punch = match rendezvous::punch(
        &cfg.rustdesk.server,
        &cfg.rustdesk.device_id,
        &cfg.rustdesk.key,
        Duration::from_secs(10),
    ).await {
        Ok(p) => p,
        Err(e) => { eprintln!("punch failed: {e:#}"); return 1; }
    };
    eprintln!("peer: {} (is_local={}) — connecting...", punch.peer_addr, punch.is_local);

    let session = match session::Session::connect_direct(
        punch.peer_addr, &punch.pk, cfg,
    ).await {
        Ok(s) => s,
        Err(e) => { eprintln!("session failed: {e:#}"); return 1; }
    };
    if let Err(e) = session.serve(cfg.local.listen).await {
        eprintln!("serve: {e:#}");
        return 1;
    }
    0
}

async fn relay_cmd(cfg: &config::Config) -> i32 {
    // First punch to get relay server info
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
    println!("requesting relay via {relay_server}...");
    match relay::request_relay(
        &cfg.rustdesk.server,
        &cfg.rustdesk.device_id,
        &relay_server,
        Duration::from_secs(15),
    )
    .await
    {
        Ok(stream) => {
            let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
            println!("relay established: connected to {peer}");
            0
        }
        Err(e) => {
            eprintln!("relay failed: {e:#}");
            1
        }
    }
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
