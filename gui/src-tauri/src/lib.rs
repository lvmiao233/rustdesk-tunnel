//! rdt GUI backend: bridges the core app state to the webview and owns the
//! tray lifecycle.

use rustdesk_tunnel::app::{self, AppHandle as CoreHandle, Phase};
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Emitter, Manager,
};

struct Core {
    handle: Mutex<Option<CoreHandle>>,
}

fn cfg_file(app: &tauri::AppHandle) -> std::path::PathBuf {
    let dir = app
        .path()
        .app_config_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    std::fs::create_dir_all(&dir).ok();
    dir.join("rdt.toml")
}

fn phase_json(p: &Phase) -> serde_json::Value {
    use serde_json::json;
    match p {
        Phase::Probing => json!({"kind": "probing", "label": p.label()}),
        Phase::CampusIdle => json!({"kind": "idle", "label": p.label()}),
        Phase::Connecting(w) => json!({"kind": "connecting", "label": p.label(), "what": w}),
        Phase::Active { peer, encrypted_login, forwards } => json!({
            "kind": "active",
            "label": p.label(),
            "peer": peer,
            "encrypted_login": encrypted_login,
            "forwards": forwards.iter().map(|(l, a)| json!({"label": l, "addr": a.to_string()})).collect::<Vec<_>>(),
        }),
        Phase::Failed(e) => json!({"kind": "failed", "label": p.label(), "error": e}),
        Phase::Stopped => json!({"kind": "stopped", "label": p.label()}),
    }
}

const ICON_IDLE: &[u8] = include_bytes!("../icons/icon.png");
const ICON_ACTIVE: &[u8] = include_bytes!("../icons/icon-green.png");
const ICON_CONNECTING: &[u8] = include_bytes!("../icons/icon-orange.png");
const ICON_FAILED: &[u8] = include_bytes!("../icons/icon-red.png");

fn tray_icon_for(kind: &str) -> &'static [u8] {
    match kind {
        "active" => ICON_ACTIVE,
        "connecting" => ICON_CONNECTING,
        "failed" => ICON_FAILED,
        _ => ICON_IDLE,
    }
}

fn refresh_tray(app: &tauri::AppHandle, phase: &Phase) {
    let j = phase_json(phase);
    let kind = j["kind"].as_str().unwrap_or("stopped").to_string();
    if let Some(tray) = app.tray_by_id("main") {
        if let Ok(img) = tauri::image::Image::from_bytes(tray_icon_for(&kind)) {
            tray.set_icon(Some(img)).ok();
        }
        let title = j["label"].as_str().unwrap_or("").to_string();
        tray.set_tooltip(Some(&title)).ok();
    }
    let _ = app.emit("state", j);
}

#[tauri::command]
fn get_state(app: tauri::AppHandle, state: tauri::State<'_, Core>) -> serde_json::Value {
    let guard = state.handle.lock().unwrap();
    match guard.as_ref() {
        Some(h) => phase_json(&h.phase()),
        None => serde_json::json!({"kind": "stopped", "label": "已停止"}),
    }
}

fn start_inner(app: &tauri::AppHandle, state: &Core, force: bool) -> Result<(), String> {
    let mut guard = state.handle.lock().unwrap();
    if let Some(h) = guard.take() {
        h.stop();
    }
    let cfg = load_config(app)?;
    let h = app::spawn(cfg, force);
    let watcher = h.subscribe();
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut rx = watcher;
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let p = rx.borrow().clone();
            refresh_tray(&app2, &p);
            if p == Phase::Stopped {
                break;
            }
        }
    });
    *guard = Some(h);
    Ok(())
}

#[tauri::command]
fn start(app: tauri::AppHandle, state: tauri::State<'_, Core>, force: bool) -> Result<(), String> {
    start_inner(&app, &state, force)
}

#[tauri::command]
fn stop(state: tauri::State<'_, Core>) {
    if let Some(h) = state.handle.lock().unwrap().take() {
        h.stop();
    }
}

fn load_config(app: &tauri::AppHandle) -> Result<rustdesk_tunnel::config::Config, String> {
    let path = cfg_file(app);
    if !path.exists() {
        // seed from a config next to the binary (dev) if present
        for seed in ["rdt.toml", "../rdt.toml", "../../rdt.toml"] {
            if let Ok(src) = std::fs::read_to_string(seed) {
                std::fs::write(&path, &src).ok();
                break;
            }
        }
    }
    rustdesk_tunnel::config::Config::load(path.to_str().unwrap_or("rdt.toml"))
        .map_err(|e| format!("{e:#}"))
}

#[tauri::command]
fn get_config(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let path = cfg_file(&app);
    let raw = std::fs::read_to_string(&path).unwrap_or_default();
    let val: toml::Value = raw.parse().unwrap_or(toml::Value::Table(Default::default()));
    Ok(serde_json::to_value(val).unwrap_or_default())
}

#[tauri::command]
fn save_config(app: tauri::AppHandle, cfg: serde_json::Value) -> Result<(), String> {
    let toml_val: toml::Value =
        serde_json::from_value(cfg).map_err(|e| format!("invalid config: {e}"))?;
    let text = toml::to_string_pretty(&toml_val).map_err(|e| e.to_string())?;
    std::fs::write(cfg_file(&app), text).map_err(|e| e.to_string())
}

#[tauri::command]
fn probe_now(app: tauri::AppHandle) -> serde_json::Value {
    let cfg = load_config(&app).ok();
    match cfg {
        Some(c) => {
            let on = tauri::async_runtime::block_on(rustdesk_tunnel::probe::http_body_contains(
                &c.campus.probe_url,
                &c.campus.probe_expect,
                c.campus.probe_timeout_ms,
            ));
            serde_json::json!({"campus": on})
        }
        None => serde_json::json!({"campus": null, "error": "config invalid"}),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Core {
            handle: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            get_state, start, stop, get_config, save_config, probe_now
        ])
        .setup(|app| {
            let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let toggle = MenuItem::with_id(app, "toggle", "启动/停止隧道", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &toggle, &quit])?;
            TrayIconBuilder::with_id("main")
                .icon(
                    tauri::image::Image::from_bytes(ICON_IDLE)
                        .map_err(|e| e.to_string())?,
                )
                .tooltip("RustDesk Tunnel")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            w.show().ok();
                            w.set_focus().ok();
                        }
                    }
                    "toggle" => {
                        let state = app.state::<Core>();
                        let running = state.handle.lock().unwrap().is_some();
                        if running {
                            if let Some(h) = state.handle.lock().unwrap().take() {
                                h.stop();
                            }
                        } else {
                            let app2 = app.clone();
                            // run the blocking config load + spawn off the menu thread
                            std::thread::spawn(move || {
                                let state = app2.state::<Core>();
                                if let Err(e) = start_inner(&app2, &state, false) {
                                    eprintln!("start: {e}");
                                }
                            });
                        }
                    }
                    "quit" => {
                        let state = app.state::<Core>();
                        if let Some(h) = state.handle.lock().unwrap().take() {
                            h.stop();
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let tauri::tray::TrayIconEvent::Click { button: tauri::tray::MouseButton::Left, button_state: tauri::tray::MouseButtonState::Up, .. } = event {
                        if let Some(w) = tray.app_handle().get_webview_window("main") {
                            w.show().ok();
                            w.set_focus().ok();
                        }
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().ok();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
