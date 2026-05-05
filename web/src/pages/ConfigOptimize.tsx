import { Save } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Settings, SystemStatus } from "../types";

type Props = {
  settings?: Settings;
  onSettings: (settings: Settings) => void;
};

export function ConfigOptimize({ settings, onSettings }: Props) {
  const [local, setLocal] = useState<Settings | undefined>(settings);
  const [interfaces, setInterfaces] = useState<SystemStatus["interfaces"]>([]);
  const [error, setError] = useState("");

  useEffect(() => setLocal(settings), [settings]);

  const dirty = useMemo(() => JSON.stringify(local) !== JSON.stringify(settings), [local, settings]);

  async function save() {
    if (!local || !dirty) return;
    try {
      const response = await api.saveSettings(local);
      setLocal(response.settings);
      onSettings(response.settings);
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    api.system().then((data) => setInterfaces(data.interfaces)).catch((err) => setError((err as Error).message));
  }, []);

  if (!local) return null;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>配置优化</h1>
          <div className="muted">生产运行配置 / Lua overrides / manual rules</div>
        </div>
        <button className={dirty ? "primary" : ""} disabled={!dirty} onClick={save}>
          <Save size={16} /> 保存
        </button>
      </header>
      {error ? <div className="banner bad">{error}</div> : null}

      <section className="panel">
        <div className="panel-title">运行配置</div>
        <div className="form-grid settings-form">
          <label>
            <span>Snort config</span>
            <input
              value={local.snort_config_path}
              onChange={(event) => setLocal({ ...local, snort_config_path: event.target.value })}
            />
          </label>
          <label>
            <span>Raw rules</span>
            <input value={local.raw_rule_path} onChange={(event) => setLocal({ ...local, raw_rule_path: event.target.value })} />
          </label>
          <label>
            <span>SWD</span>
            <input value={local.swd} onChange={(event) => setLocal({ ...local, swd: event.target.value })} />
          </label>
          <label>
            <span>Interface</span>
            <select value={local.interface} onChange={(event) => setLocal({ ...local, interface: event.target.value })}>
              <option value="">选择网卡</option>
              {interfaces.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.name}
                  {item.up ? " up" : ""}
                </option>
              ))}
            </select>
          </label>
        </div>
      </section>

      <section className="panel">
        <div className="panel-title">Lua 覆写</div>
        <div className="toggle-grid">
          {local.lua_overrides.map((override, index) => (
            <label key={override.id || index} className="toggle-card">
              <input
                type="checkbox"
                checked={override.enabled}
                onChange={(event) => {
                  const next = [...local.lua_overrides];
                  next[index] = { ...override, enabled: event.target.checked };
                  setLocal({ ...local, lua_overrides: next });
                }}
              />
              <span>
                <strong>{override.label}</strong>
                <small>{override.description}</small>
                <code>{override.value}</code>
              </span>
            </label>
          ))}
        </div>
      </section>
    </div>
  );
}
