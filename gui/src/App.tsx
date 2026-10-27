import { useEffect, useState } from "react";
import { api, StateSnapshot } from "./api";
import Status from "./Status";
import Settings from "./Settings";

type Tab = "status" | "settings";

export default function App() {
  const initial = (typeof location !== "undefined" && new URLSearchParams(location.search).get("tab")) as Tab | null;
  const [tab, setTab] = useState<Tab>(initial === "settings" ? "settings" : "status");
  const [state, setState] = useState<StateSnapshot | null>(null);
  const [configVersion, setConfigVersion] = useState(0);

  useEffect(() => {
    api.getState().then(setState);
    const off = api.listen(setState);
    const timer = setInterval(() => api.getState().then(setState), 3000);
    return () => { off(); clearInterval(timer); };
  }, [configVersion]);

  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 font-sans select-none">
      <div className="max-w-[500px] mx-auto p-4 pt-5">
        <nav className="flex gap-1 mb-4 p-1 bg-neutral-900 rounded-lg border border-neutral-800 mt-1">
          {(["status", "settings"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 py-1.5 text-sm rounded-md transition-colors ${
                tab === t
                  ? "bg-neutral-800 text-neutral-100 font-medium"
                  : "text-neutral-400 hover:text-neutral-200"
              }`}
            >
              {t === "status" ? "状态" : "设置"}
            </button>
          ))}
        </nav>

        {tab === "status" ? (
          <Status state={state} onChanged={() => setConfigVersion((v) => v + 1)} />
        ) : (
          <Settings onSaved={() => setConfigVersion((v) => v + 1)} />
        )}
      </div>
    </div>
  );
}
