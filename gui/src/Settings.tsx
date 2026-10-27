import { useEffect, useState } from "react";
import { api } from "./api";

interface ForwardRule {
  local: string;
  remote_host: string;
  remote_port: number;
}

export default function Settings({ onSaved }: { onSaved: () => void }) {
  const [cfg, setCfg] = useState<any>(null);
  const [forwards, setForwards] = useState<ForwardRule[]>([]);
  const [status, setStatus] = useState<string>("");

  useEffect(() => {
    api.getConfig().then((c) => {
      setCfg(c);
      setForwards((c.forward ?? []) as ForwardRule[]);
    });
  }, []);

  if (!cfg) return <div className="text-sm text-neutral-500">加载配置…</div>;

  const set = (path: string[], value: any) => {
    setCfg((prev: any) => {
      const next = structuredClone(prev);
      let node = next;
      for (const k of path.slice(0, -1)) node = node[k] ??= {};
      node[path[path.length - 1]] = value;
      return next;
    });
  };

  const save = async () => {
    const next = structuredClone(cfg);
    next.forward = forwards;
    next.service = { remote_addr: "127.0.0.1:22" };
    try {
      await api.saveConfig(next);
      setStatus("已保存");
      onSaved();
    } catch (e) {
      setStatus(`保存失败: ${e}`);
    }
  };

  const field = "w-full bg-neutral-900 border border-neutral-800 rounded-lg px-3 py-2 text-sm font-mono focus:border-emerald-500/50 focus:outline-none";
  const label = "block text-xs text-neutral-400 mb-1";

  return (
    <div className="space-y-5">
      <section>
        <h2 className="text-sm font-medium text-neutral-300 mb-3">RustDesk 服务器与设备</h2>
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className={label}>hbbs 地址</label>
            <input className={field} value={cfg.rustdesk?.server ?? ""}
              onChange={(e) => set(["rustdesk", "server"], e.target.value)} />
          </div>
          <div className="col-span-2">
            <label className={label}>服务器公钥 (id_ed25519.pub, base64)</label>
            <input className={field} value={cfg.rustdesk?.key ?? ""}
              onChange={(e) => set(["rustdesk", "key"], e.target.value)} />
          </div>
          <div>
            <label className={label}>设备 ID</label>
            <input className={field} value={cfg.rustdesk?.device_id ?? ""}
              onChange={(e) => set(["rustdesk", "device_id"], e.target.value)} />
          </div>
          <div>
            <label className={label}>RustDesk 密码</label>
            <input className={field} type="password" value={cfg.rustdesk?.password ?? ""}
              onChange={(e) => set(["rustdesk", "password"], e.target.value)} />
          </div>
        </div>
      </section>

      <section>
        <h2 className="text-sm font-medium text-neutral-300 mb-3">设备 SSH（隧道内加密层）</h2>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={label}>SSH 用户</label>
            <input className={field} value={cfg.ssh?.user ?? ""}
              onChange={(e) => set(["ssh", "user"], e.target.value)} />
          </div>
          <div>
            <label className={label}>SSH 密码（或留空并用密钥文件）</label>
            <input className={field} type="password" value={cfg.ssh?.password ?? ""}
              onChange={(e) => set(["ssh", "password"], e.target.value)} />
          </div>
        </div>
        <p className="mt-2 text-[11px] text-neutral-500">
          隧道固定转发设备的 22 端口；以下端口经由设备上的 SSH 通道转发，端到端加密。
        </p>
      </section>

      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-medium text-neutral-300">转发规则</h2>
          <button
            className="text-xs px-2.5 py-1 rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700"
            onClick={() => setForwards([...forwards, { local: "127.0.0.1:49825", remote_host: "127.0.0.1", remote_port: 23834 }])}
          >
            + 添加
          </button>
        </div>
        <div className="space-y-2">
          {forwards.map((f, i) => (
            <div key={i} className="flex gap-2 items-center">
              <input className={field} value={f.local} placeholder="本地监听"
                onChange={(e) => setForwards(forwards.map((x, j) => j === i ? { ...x, local: e.target.value } : x))} />
              <span className="text-neutral-600 text-sm">→</span>
              <input className={field} value={f.remote_host} placeholder="设备侧主机"
                onChange={(e) => setForwards(forwards.map((x, j) => j === i ? { ...x, remote_host: e.target.value } : x))} />
              <input className={`${field} w-24`} value={f.remote_port} placeholder="端口"
                onChange={(e) => setForwards(forwards.map((x, j) => j === i ? { ...x, remote_port: Number(e.target.value) || 0 } : x))} />
              <button className="text-red-400/70 hover:text-red-400 px-2"
                onClick={() => setForwards(forwards.filter((_, j) => j !== i))}>✕</button>
            </div>
          ))}
          {forwards.length === 0 && (
            <div className="rounded-lg bg-neutral-900 border border-dashed border-neutral-800 px-3 py-5 text-center text-xs text-neutral-500">
              没有转发规则
            </div>
          )}
        </div>
      </section>

      <div className="flex items-center gap-3 sticky bottom-0 py-3 bg-neutral-950/90 backdrop-blur border-t border-neutral-800">
        <button onClick={save}
          className="px-4 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 text-sm">
          保存配置
        </button>
        {status && <span className="text-xs text-neutral-400">{status}</span>}
      </div>
    </div>
  );
}
