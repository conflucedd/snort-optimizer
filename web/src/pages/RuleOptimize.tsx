import { CheckCircle2, Play, RotateCcw, Save, Search, Square, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, compactBytes, fmtNumber, pct } from "../api";
import { LineChart } from "../components/LineChart";
import { StatusPill } from "../components/StatusPill";
import type { AnalysisStrategy, AnalysisStatus, FileItem, RuleList, Settings } from "../types";

type Props = {
  settings?: Settings;
  onSettings: (settings: Settings) => void;
};

export function RuleOptimize({ settings, onSettings }: Props) {
  const [status, setStatus] = useState<AnalysisStatus>();
  const [error, setError] = useState("");
  const [strategies, setStrategies] = useState<AnalysisStrategy[]>([]);
  const [selectedStrategies, setSelectedStrategies] = useState<string[]>([]);
  const [strategySaving, setStrategySaving] = useState("");
  const [pcapFiles, setPcapFiles] = useState<FileItem[]>([]);
  const [dbFiles, setDbFiles] = useState<FileItem[]>([]);
  const [applying, setApplying] = useState(false);
  const [decisionOffset, setDecisionOffset] = useState(0);
  const [awd, setAwd] = useState(settings?.awd ?? "AWD");
  const [form, setForm] = useState({
    pcap1: "data/Tuesday.pcap",
    db1: "data/Tuesday.db",
    pcap2: "data/Monday.pcap",
    max_round: 4,
    factor: 0.8
  });
  const awdDirty = Boolean(settings && awd !== settings.awd);

  const decisionLimit = 80;

  async function load(nextDecisionOffset = decisionOffset) {
    try {
      const params = new URLSearchParams({
        decision_limit: String(decisionLimit),
        decision_offset: String(nextDecisionOffset)
      });
      setStatus(await api.analysisStatus(params));
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load(decisionOffset);
    const timer = window.setInterval(load, 4000);
    return () => window.clearInterval(timer);
  }, [decisionOffset]);

  useEffect(() => {
    setAwd(settings?.awd ?? "AWD");
  }, [settings?.awd]);

  useEffect(() => {
    Promise.all([api.analysisStrategies(), api.pcapFiles(), api.dbFiles()])
      .then(([strategyData, pcapData, dbData]) => {
        setStrategies(strategyData.items);
        setPcapFiles(pcapData.files);
        setDbFiles(dbData.files);
      })
      .catch((err) => setError((err as Error).message));
  }, []);

  useEffect(() => {
    if (strategies.length === 0) return;
    const disabled = new Set(settings?.analysis_disabled_strategies ?? []);
    setSelectedStrategies(strategies.map((item) => item.name).filter((name) => !disabled.has(name)));
  }, [settings?.analysis_disabled_strategies, strategies]);

  async function start() {
    setError("");
    try {
      setDecisionOffset(0);
      const disabledStrategies = strategies
        .map((item) => item.name)
        .filter((name) => !selectedStrategies.includes(name));
      setStatus(
        await api.startAnalysis({
          ...form,
          snort_config: settings?.snort_config_path,
          raw_snort_sqlite: settings?.raw_snort_sqlite,
          raw_rule_path: settings?.raw_rule_path,
          work_dir: awd,
          strategies: ["all"],
          disabled_strategies: disabledStrategies,
          force_new: true
        })
      );
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function cancel() {
    try {
      await api.cancelAnalysis();
      await load(decisionOffset);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function saveAwd() {
    if (!settings || !awdDirty) return;
    try {
      const response = await api.saveSettings({ ...settings, awd });
      onSettings(response.settings);
      setAwd(response.settings.awd);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function toggleStrategy(name: string, enabled: boolean) {
    const nextSelected = enabled
      ? Array.from(new Set([...selectedStrategies, name]))
      : selectedStrategies.filter((item) => item !== name);
    setSelectedStrategies(nextSelected);
    if (!settings) return;
    setStrategySaving(name);
    try {
      const selected = new Set(nextSelected);
      const disabled = strategies.map((item) => item.name).filter((item) => !selected.has(item));
      const response = await api.saveSettings({ ...settings, analysis_disabled_strategies: disabled });
      onSettings(response.settings);
      setError("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setStrategySaving("");
    }
  }

  async function apply(runId: number) {
    setApplying(true);
    try {
      await api.applyAnalysis(runId);
      const response = await api.settings();
      onSettings(response.settings);
      await load(decisionOffset);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setApplying(false);
    }
  }

  function updateExperimentPcap(path: string) {
    const dbPath = path.replace(/\.(pcapng|pcap)$/i, ".db");
    setForm({ ...form, pcap1: path, db1: dbPath });
  }

  function pageDecisions(delta: number) {
    const next = Math.max(0, decisionOffset + delta * decisionLimit);
    setDecisionOffset(next);
    load(next);
  }

  const runs = status?.result?.runs ?? [];
  const fpPoints = useMemo(
    () => runs.map((run) => ({ label: `run ${run.run_id}`, value: run.evaluation.false_positive_rate, alt: run.evaluation.miss_rate })),
    [runs]
  );
  const throughputPoints = useMemo(
    () =>
      runs.map((run) => {
        const totalMS = Math.max(1, run.evaluation.real_runtime_ms);
        return {
          label: `run ${run.run_id}`,
          value: run.evaluation.total_flows / (totalMS / 1000),
          alt: run.evaluation.real_rule_time_us / 1_000_000
        };
      }),
    [runs]
  );
  const finalRun = status?.result?.final_run_id ?? 0;
  const decisionTotal = status?.result?.top_decision_total ?? 0;
  const dbSelectedExists = !form.db1 || dbFiles.some((file) => file.path === form.db1);
  const jobStatus = status?.job?.status;
  const statusText = status?.running ? "分析中" : jobStatus === "completed" ? "已完成" : status?.result ? "已有结果" : "空闲";
  const hasResult = Boolean(status?.result?.runs?.length);
  const applied = finalRun > 0 && settings?.last_applied_final_run === finalRun;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>规则优化</h1>
          <div className="muted">Workdir {status?.work_dir ?? awd}</div>
        </div>
        <div className="head-actions">
          <StatusPill tone={status?.running ? "warn" : hasResult ? "good" : "neutral"}>{statusText}</StatusPill>
        </div>
      </header>

      {error ? <div className="banner bad">{error}</div> : null}

      <section className="panel">
        <div className="panel-title">分析任务</div>
        <div className="form-grid analysis-form">
          <label>
            <span>AWD</span>
            <input value={awd} onChange={(event) => setAwd(event.target.value)} />
          </label>
          <label>
            <span>实验 PCAP</span>
            <select value={form.pcap1} onChange={(event) => updateExperimentPcap(event.target.value)}>
              <option value="">选择 PCAP</option>
              {pcapFiles.map((file) => (
                <option key={file.path} value={file.path}>
                  {file.path} ({compactBytes(file.size)})
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>标签 DB</span>
            <select value={form.db1} onChange={(event) => setForm({ ...form, db1: event.target.value })}>
              <option value="">选择 DB</option>
              {!dbSelectedExists ? <option value={form.db1}>{form.db1}</option> : null}
              {dbFiles.map((file) => (
                <option key={file.path} value={file.path}>
                  {file.path} ({compactBytes(file.size)})
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>真实 PCAP</span>
            <select value={form.pcap2} onChange={(event) => setForm({ ...form, pcap2: event.target.value })}>
              <option value="">选择 PCAP</option>
              {pcapFiles.map((file) => (
                <option key={file.path} value={file.path}>
                  {file.path} ({compactBytes(file.size)})
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>Max round</span>
            <input
              type="number"
              min={1}
              max={16}
              value={form.max_round}
              onChange={(event) => setForm({ ...form, max_round: Number(event.target.value) })}
            />
          </label>
        </div>
        <div className="progress-row">
          <div className="progress">
            <span style={{ width: `${Math.round((status?.progress ?? 0) * 100)}%` }} />
          </div>
          <strong>{Math.round((status?.progress ?? 0) * 100)}%</strong>
        </div>
        <div className="button-row">
          <button className={awdDirty ? "primary" : ""} disabled={!awdDirty} onClick={saveAwd}>
            <Save size={16} /> 保存 AWD
          </button>
          <button className="primary" disabled={status?.running} onClick={start}>
            {hasResult ? <RotateCcw size={16} /> : <Play size={16} />} {hasResult ? "重新分析" : "开始分析"}
          </button>
          <button disabled={!status?.running} onClick={cancel}>
            <Square size={16} /> 停止
          </button>
          <button disabled={status?.running || !status?.result || finalRun <= 0 || applying || applied} onClick={() => apply(finalRun)}>
            <CheckCircle2 size={16} /> {applied ? `已应用 run ${finalRun}` : `应用 run ${finalRun}`}
          </button>
        </div>
      </section>

      <section className="panel">
        <div className="panel-title">分析策略</div>
        <div className="toggle-grid strategy-grid">
          {strategies.map((strategy) => (
            <label key={strategy.name} className="toggle-card">
              <input
                type="checkbox"
                checked={selectedStrategies.includes(strategy.name)}
                disabled={status?.running || strategySaving === strategy.name}
                onChange={(event) => toggleStrategy(strategy.name, event.target.checked)}
              />
              <span>
                <strong>{strategy.name}</strong>
                <small>{strategy.type}</small>
              </span>
            </label>
          ))}
        </div>
      </section>

      <section className="panel-grid two">
        <div className="panel">
          <div className="panel-title">误报率 / 漏报率</div>
          <LineChart points={fpPoints} valueSuffix="" label="rate" />
          <div className="chart-legend">
            <span className="legend orange" /> False positive
            <span className="legend blue" /> Miss
          </div>
        </div>
        <div className="panel">
          <div className="panel-title">吞吐 / 规则耗时</div>
          <LineChart points={throughputPoints} label="throughput" />
          <div className="chart-legend">
            <span className="legend orange" /> Flows/s
            <span className="legend blue" /> Rule time s
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-title">轮次</div>
        <div className="run-list">
          {runs.map((run) => (
            <div key={run.run_id} className={`run-row ${run.rolled_back ? "rolled" : "committed"}`}>
              <div className="run-id">run {run.run_id}</div>
              {run.committed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
              <div>{run.reason}</div>
              <strong>{pct(run.evaluation.false_positive_rate)}</strong>
              <strong>{pct(run.evaluation.miss_rate)}</strong>
              <span>{fmtNumber(run.evaluation.real_rule_time_us / 1000, 0)} ms</span>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-title">提交规则</div>
        <div className="compact-list">
          {(status?.result?.top_decisions ?? []).map((item) => (
            <div key={`${item.run_id}-${item.gid}-${item.sid}`}>
              <strong>{item.gid}:{item.sid}</strong>
              <span>{item.msg}</span>
              <em>{item.committed ? "commit" : "rollback"}</em>
            </div>
          ))}
        </div>
        <div className="pager">
          <button disabled={decisionOffset === 0} onClick={() => pageDecisions(-1)}>上一页</button>
          <span>
            {decisionTotal === 0 ? 0 : fmtNumber(decisionOffset + 1)} - {fmtNumber(Math.min(decisionOffset + decisionLimit, decisionTotal))}
            {" / "}
            {fmtNumber(decisionTotal)}
          </span>
          <button disabled={decisionOffset + decisionLimit >= decisionTotal} onClick={() => pageDecisions(1)}>下一页</button>
        </div>
      </section>

      <RuleSwitchPanel settings={settings} />
    </div>
  );
}

function RuleSwitchPanel({ settings }: { settings?: Settings }) {
  const [rules, setRules] = useState<RuleList>();
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [togglingRule, setTogglingRule] = useState("");
  const limit = 100;

  async function loadRules(nextOffset = offset) {
    const params = new URLSearchParams({
      limit: String(limit),
      offset: String(nextOffset),
      run_id: String(settings?.active_run_id ?? 0)
    });
    const trimmed = query.trim();
    const pair = trimmed.match(/^(\d+)\s*:\s*(\d+)$/);
    if (pair) {
      params.set("gid", pair[1]);
      params.set("sid", pair[2]);
    } else if (/^\d+$/.test(trimmed)) {
      params.set("sid", trimmed);
    } else if (trimmed) {
      params.set("q", trimmed);
    }
    try {
      setRules(await api.rules(params));
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    setOffset(0);
    loadRules(0);
  }, [settings?.updated_at, settings?.active_run_id]);

  async function toggle(gid: number, sid: number, enabled: boolean) {
    const key = `${gid}:${sid}`;
    setTogglingRule(key);
    setMessage("");
    try {
      await api.toggleRule({ gid, sid, enabled, run_id: settings?.active_run_id ?? 0, reason: "manual" });
      await loadRules(offset);
      setMessage(`规则 ${key} 已${enabled ? "启用" : "禁用"}`);
      setError("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setTogglingRule("");
    }
  }

  function submitSearch() {
    setOffset(0);
    loadRules(0);
  }

  function page(delta: number) {
    const next = Math.max(0, offset + delta * limit);
    setOffset(next);
    loadRules(next);
  }

  return (
    <section className="panel">
      <div className="panel-title">规则开关</div>
      {error ? <div className="inline-error">{error}</div> : null}
      {message ? <div className="inline-message">{message}</div> : null}
      <div className="searchbar compact">
        <Search size={16} />
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") submitSearch();
          }}
          placeholder="SID、GID:SID、msg、source"
        />
        <button onClick={submitSearch}>查询</button>
      </div>
      <div className="compact-list">
        {(rules?.items ?? []).map((rule) => (
          <div key={`${rule.gid}-${rule.sid}`} className={!rule.enabled ? "row-disabled" : ""}>
            <strong>{rule.gid}:{rule.sid}</strong>
            <span>{rule.msg}</span>
            <em>{rule.enabled ? "已启用" : "已禁用"}</em>
            <button
              className={rule.enabled ? "danger" : "success"}
              disabled={togglingRule === `${rule.gid}:${rule.sid}`}
              onClick={() => toggle(rule.gid, rule.sid, !rule.enabled)}
            >
              {togglingRule === `${rule.gid}:${rule.sid}` ? "处理中" : rule.enabled ? "禁用" : "启用"}
            </button>
          </div>
        ))}
      </div>
      <div className="muted">
        显示 {fmtNumber(rules?.items.length ?? 0)} / {fmtNumber(rules?.total ?? 0)}
      </div>
      <div className="pager">
        <button disabled={offset === 0} onClick={() => page(-1)}>上一页</button>
        <span>
          {(rules?.total ?? 0) === 0 ? 0 : fmtNumber(offset + 1)} - {fmtNumber(Math.min(offset + limit, rules?.total ?? 0))}
          {" / "}
          {fmtNumber(rules?.total ?? 0)}
        </span>
        <button disabled={offset + limit >= (rules?.total ?? 0)} onClick={() => page(1)}>下一页</button>
      </div>
    </section>
  );
}
