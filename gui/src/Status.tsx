import { useState } from "react";
import { api, StateSnapshot } from "./api";

const KIND_META: Record<string, { dot: string; ring: string; text: string }> = {
  active: { dot: "bg-emerald-400", ring: "border-emerald-500/40 bg-emerald-500/10", text: "text-emerald-300" },
  connecting: { dot: "bg-orange-400 animate-pulse", ring: "border-orange-500/40 bg-orange-500/10", text: "text-orange-300" },
  failed: { dot: "bg-red-400", ring: "border-red-500/40 bg-red-500/10", text: "text-red-300" },
  idle: { dot: "bg-sky-400", ring: "border-sky-500/40 bg-sky-500/10", text: "text-sky-300" },
  probing: { dot: "bg-neutral-400 animate-pulse", ring: "border-neutral-600/40 bg-neutral-800/50", text: "text-neutral-300" },
  stopped: { dot: "bg-neutral-500", ring: "border-neutral-700 bg-neutral-900/50", text: "text-neutral-400" },
};

export default function Status({ state, onChanged }: { state: StateSnapshot | null; onChanged: () => void }) {
  const [campus, setCampus] = useState<boolean | null>(null);
  const kind = state?.kind ?? "stopped";
  const meta = KIND_META[kind] ?? KIND_META.stopped;
  const running = kind !== "stopped";

  return (
    <div className="space-y-4">
      <section className={`rounded-xl border p-4 ${meta.ring} ${kind === "active" ? "glow-sweep" : ""}`}>
        <div className="flex items-center gap-3">
          <span className={`w-3 h-3 rounded-full ${meta.dot}`} />
          <div className="flex-1">
            <div className={`font-medium ${meta.text}`}>{state?.label ?? "已停止"}</div>
            {state?.kind === "active" && (
              <div className="text-xs text-neutral-400 mt-0.5">{state.peer}</div>
            )}
            {state?.kind === "failed" && state.error && (
              <div className="text-xs text-red-400/80 mt-1 break-all">{state.error}</div>
            )}
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => api.probe().then((r) => setCampus(r.campus))}
              className="px-3 py-1.5 text-xs rounded-lg bg-neutral-800 hover:bg-neutral-700 border border-neutral-700"
            >
              检测校园网
            </button>
            {running ? (
              <button
                onClick={() => api.stop().then(onChanged)}
                className="px-3 py-1.5 text-xs rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300"
              >
                停止
              </button>
            ) : (
              <button
                onClick={() => api.start(false).then(onChanged)}
                className="px-3 py-1.5 text-xs rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300"
              >
                启动
              </button>
            )}
          </div>
        </div>
        {campus !== null && (
          <div className="mt-3 text-xs text-neutral-400">
            校园网探测：<span className={campus ? "text-emerald-400" : "text-orange-400"}>
              {campus ? "校内（直连可用，隧道将闲置）" : "校外（需要隧道）"}
            </span>
          </div>
        )}
      </section>

      <section>
        <h2 className="text-sm font-medium text-neutral-300 mb-2">端口转发</h2>
        {state?.forwards?.length ? (
          <ul className="space-y-2">
            {state.forwards.map((f) => (
              <li key={f.addr} className="flex items-center gap-3 rounded-lg bg-neutral-900 border border-neutral-800 px-3 py-2.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400" />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-mono truncate">{f.addr}</div>
                  <div className="text-xs text-neutral-500 truncate">{f.label}</div>
                </div>
                <button
                  className="text-xs px-2 py-1 rounded bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 text-neutral-300"
                  onClick={() => navigator.clipboard?.writeText(f.addr)}
                >
                  复制
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <div className="rounded-lg bg-neutral-900 border border-dashed border-neutral-800 px-3 py-6 text-center text-xs text-neutral-500">
            {running ? "暂无转发规则，请在设置中添加" : "隧道未运行"}
          </div>
        )}
      </section>
    </div>
  );
}
