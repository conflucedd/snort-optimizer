import { Save, Search } from "lucide-react";
import { useEffect, useState } from "react";
import { api, fmtNumber, pct } from "../api";
import type { Recommendation, RuleList, Settings } from "../types";

type Props = {
  settings?: Settings;
  onSettings: (settings: Settings) => void;
};

export function ConfigOptimize({ settings, onSettings }: Props) {
  const [local, setLocal] = useState<Settings | undefined>(settings);
  const [rules, setRules] = useState<RuleList>();
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [query, setQuery] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => setLocal(settings), [settings]);

  async function save() {
    if (!local) return;
    try {
      const response = await api.saveSettings(local);
      setLocal(response.settings);
      onSettings(response.settings);
      setMessage("已保存");
    } catch (err) {
      setMessage((err as Error).message);
    }
  }

  async function loadRules() {
    const params = new URLSearchParams({ limit: "100", offset: "0", run_id: String(local?.active_run_id ?? 0) });
    if (query) params.set("q", query);
    const [ruleData, recData] = await Promise.all([api.rules(params), api.recommendations(120)]);
    setRules(ruleData);
    setRecommendations(recData.items);
  }

  useEffect(() => {
    loadRules().catch((err) => setMessage((err as Error).message));
  }, [local?.active_run_id]);

  async function toggle(gid: number, sid: number, enabled: boolean) {
    await api.toggleRule({ gid, sid, enabled, run_id: local?.active_run_id ?? 0, reason: "manual" });
    await loadRules();
  }

  if (!local) return null;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>配置优化</h1>
          <div className="muted">Lua overrides / manual rules</div>
        </div>
        <button className="primary" onClick={save}>
          <Save size={16} /> 保存
        </button>
      </header>
      {message ? <div className="banner">{message}</div> : null}

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
            <span>AWD</span>
            <input value={local.awd} onChange={(event) => setLocal({ ...local, awd: event.target.value })} />
          </label>
          <label>
            <span>Interface</span>
            <input value={local.interface} onChange={(event) => setLocal({ ...local, interface: event.target.value })} />
          </label>
          <label>
            <span>Run ID</span>
            <input
              type="number"
              value={local.active_run_id}
              onChange={(event) => setLocal({ ...local, active_run_id: Number(event.target.value) })}
            />
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

      <section className="panel-grid two">
        <div className="panel">
          <div className="panel-title">智能建议</div>
          <div className="compact-list">
            {recommendations.map((item) => (
              <div key={`${item.run_id}-${item.gid}-${item.sid}-${item.reason}`}>
                <strong>{item.gid}:{item.sid}</strong>
                <span>{item.msg || item.reason}</span>
                <em>
                  {item.fp_rate !== undefined ? `${pct(item.fp_rate)} FP` : item.recommendation}
                </em>
                <button onClick={() => toggle(item.gid, item.sid, false)}>禁用</button>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <div className="panel-title">规则开关</div>
          <div className="searchbar compact">
            <Search size={16} />
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="SID、msg、source" />
            <button onClick={loadRules}>查询</button>
          </div>
          <div className="compact-list">
            {(rules?.items ?? []).map((rule) => (
              <div key={`${rule.gid}-${rule.sid}`}>
                <strong>{rule.gid}:{rule.sid}</strong>
                <span>{rule.msg}</span>
                <em>{rule.enabled ? "enabled" : "disabled"}</em>
                <button onClick={() => toggle(rule.gid, rule.sid, !rule.enabled)}>{rule.enabled ? "禁用" : "启用"}</button>
              </div>
            ))}
          </div>
          <div className="muted">显示 {fmtNumber(rules?.items.length ?? 0)} / {fmtNumber(rules?.total ?? 0)}</div>
        </div>
      </section>
    </div>
  );
}
