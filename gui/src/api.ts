// typed bridge to the tauri backend; falls back to a demo state in a plain
// browser so the UI can be developed and screenshotted without tauri
export type PhaseKind = "probing" | "idle" | "connecting" | "active" | "failed" | "stopped";
export interface Forward { label: string; addr: string }
export interface StateSnapshot {
  kind: PhaseKind;
  label: string;
  peer?: string;
  encrypted_login?: boolean;
  forwards?: Forward[];
  error?: string;
  what?: string;
}

const hasTauri = typeof (window as any).__TAURI_INTERNALS__ !== "undefined";

async function invoke<T>(cmd: string, args?: any): Promise<T> {
  if (!hasTauri) return demoInvoke<T>(cmd, args);
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

const demoState: StateSnapshot = {
  kind: "active",
  label: "已连接 jsa (Linux)，2 条转发",
  peer: "jsa (Linux)",
  encrypted_login: true,
  forwards: [
    { label: "127.0.0.1:49825 → 127.0.0.1:23834", addr: "127.0.0.1:49825" },
    { label: "127.0.0.1:49826 → 10.214.117.5:8080", addr: "127.0.0.1:49826" },
  ],
};

const demoConfig: any = {
  rustdesk: {
    server: "118.178.88.35:21116",
    key: "kdeD4DHik3lsXtP1vA689yovVOgYjHqmys+ZlwM4qHM=",
    device_id: "382976955",
    password: "Vipa@404",
  },
  campus: { probe_url: "http://ping.vipa.dev/", probe_expect: "<html", probe_timeout_ms: 2000 },
  service: { remote_addr: "127.0.0.1:22" },
  ssh: { user: "jsa", password: "vipa_404" },
  forward: [
    { local: "127.0.0.1:49825", remote_host: "127.0.0.1", remote_port: 23834 },
  ],
};

function demoInvoke<T>(cmd: string, _args?: any): Promise<T> {
  return new Promise((resolve) =>
    setTimeout(() => {
      switch (cmd) {
        case "get_state": resolve(demoState as T); break;
        case "get_config": resolve(demoConfig as T); break;
        case "save_config": resolve(undefined as T); break;
        case "start": resolve(undefined as T); break;
        case "stop": resolve(undefined as T); break;
        case "probe_now": resolve({ campus: true } as T); break;
        default: resolve(undefined as T);
      }
    }, 150)
  );
}

export const api = {
  getState: () => invoke<StateSnapshot>("get_state"),
  getConfig: () => invoke<any>("get_config"),
  saveConfig: (cfg: any) => invoke<void>("save_config", { cfg }),
  exportConfig: () => invoke<string>("export_config"),
  importConfig: () => invoke<string>("import_config"),
  start: (force: boolean) => invoke<void>("start", { force }),
  stop: () => invoke<void>("stop"),
  probe: () => invoke<{ campus: boolean | null }>("probe_now"),
  listen: (cb: (s: StateSnapshot) => void) => {
    if (!hasTauri) return () => {};
    import("@tauri-apps/api/event").then(({ listen }) =>
      listen<StateSnapshot>("state", (e) => cb(e.payload))
    );
    return () => {};
  },
};
