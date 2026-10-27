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

  const base = "bg-neutral-900 border border-neutral-800 rounded-lg px-3 py-2 text-sm font-mono focus:border-emerald-500/50 focus:outline-none";
  const field = `${base} w-full`;

  const label = "block text-xs text-neutral-400 mb-1";

  return (
    <div className="space-y-5">
      <section>
        <h2 className="text-sm font-medium text-neutral-300 mb-3">公网中继节点</h2>
        <div className="space-y-3">
          <div>
            <label className={label}>中继节点地址</label>
            <input className={field} value={cfg.rustdesk?.server ?? ""}
              onChange={(e) => set(["rustdesk", "server"], e.target.value)} />
          </div>
          <div>
            <label className={label}>中继服务公钥</label>
            <input className={field} value={cfg.rustdesk?.key ?? ""}
              onChange={(e) => set(["rustdesk", "key"], e.target.value)} />
          </div>
        </div>
      </section>

      <section>
        <h2 className="text-sm font-medium text-neutral-300 mb-3">校内中继节点</h2>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={label}>中继设备 ID</label>
            <input className={field} value={cfg.rustdesk?.device_id ?? ""}
              onChange={(e) => set(["rustdesk", "device_id"], e.target.value)} />
          </div>
          <div>
            <label className={label}>中继设备密码</label>
            <input className={field} type="password" value={cfg.rustdesk?.password ?? ""}
              onChange={(e) => set(["rustdesk", "password"], e.target.value)} />
          </div>
          <div>
            <label className={label}>中继设备用户</label>
            <input className={field} value={cfg.ssh?.user ?? ""}
              onChange={(e) => set(["ssh", "user"], e.target.value)} />
          </div>
          <div>
            <label className={label}>中继设备 SSH 密码</label>
            <input className={field} type="password" value={cfg.ssh?.password ?? ""}
              onChange={(e) => set(["ssh", "password"], e.target.value)} />
          </div>
        </div>
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
              <input className={`${base} w-[38%] min-w-0`} value={f.local} placeholder="本地监听"
                onChange={(e) => setForwards(forwards.map((x, j) => j === i ? { ...x, local: e.target.value } : x))} />
              <span className="text-neutral-600 text-sm shrink-0">→</span>
              <input className={`${base} flex-1 min-w-0`} value={f.remote_host} placeholder="校内主机"
                onChange={(e) => setForwards(forwards.map((x, j) => j === i ? { ...x, remote_host: e.target.value } : x))} />
              <input className={`${base} w-16 shrink-0`} value={f.remote_port} placeholder="端口"
                onChange={(e) => setForwards(forwards.map((x, j) => j === i ? { ...x, remote_port: Number(e.target.value) || 0 } : x))} />
              <button className="text-red-400/70 hover:text-red-400 px-1 shrink-0"
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

      <div className="flex items-center gap-2 sticky bottom-0 py-3 bg-neutral-950/90 backdrop-blur border-t border-neutral-800">
        <button onClick={save}
          className="px-4 py-2 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 text-sm">
          保存配置
        </button>
        <button
          onClick={async () => {
            const p = await api.importConfig();
            if (p) {
              setStatus("已导入并应用: " + p);
              const c = await api.getConfig();
              setCfg(c);
              setForwards((c.forward ?? []) as ForwardRule[]);
              onSaved();
            }
          }}
          className="px-4 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-200 text-sm">
          导入配置…
        </button>
        <button
          onClick={async () => {
            const p = await api.exportConfig();
            if (p) setStatus("已导出到: " + p);
          }}
          className="px-4 py-2 rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-200 text-sm">
          导出配置…
        </button>
        {status && <span className="text-xs text-neutral-400 truncate max-w-52" title={status}>{status}</span>}
      </div>
    </div>
  );
}
