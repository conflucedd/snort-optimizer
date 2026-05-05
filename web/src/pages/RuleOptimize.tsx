import { CheckCircle2, Play, RotateCcw, Save, Square, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, fmtNumber, pct } from "../api";
import { LineChart } from "../components/LineChart";
import { StatusPill } from "../components/StatusPill";
import type { AnalysisStrategy, AnalysisStatus, FileItem, Settings } from "../types";

type Props = {
  settings?: Settings;
  onSettings: (settings: Settings) => void;
};

export function RuleOptimize({ settings, onSettings }: Props) {
  const [status, setStatus] = useState<AnalysisStatus>();
  const [error, setError] = useState("");
  const [strategies, setStrategies] = useState<AnalysisStrategy[]>([]);
  const [selectedStrategies, setSelectedStrategies] = useState<string[]>([]);
  const [pcapFiles, setPcapFiles] = useState<FileItem[]>([]);
  const [awd, setAwd] = useState(settings?.awd ?? "AWD");
  const [form, setForm] = useState({
    pcap1: "data/Tuesday.pcap",
    db1: "data/Tuesday.db",
    pcap2: "data/Monday.pcap",
    max_round: 4,
    factor: 0.8
  });
  const awdDirty = Boolean(settings && awd !== settings.awd);

  async function load() {
    try {
      setStatus(await api.analysisStatus());
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 4000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    setAwd(settings?.awd ?? "AWD");
  }, [settings?.awd]);

  useEffect(() => {
    Promise.all([api.analysisStrategies(), api.pcapFiles()])
      .then(([strategyData, pcapData]) => {
        setStrategies(strategyData.items);
        setSelectedStrategies((current) => (current.length > 0 ? current : strategyData.items.map((item) => item.name)));
        setPcapFiles(pcapData.files);
      })
      .catch((err) => setError((err as Error).message));
  }, []);

  async function start() {
    setError("");
    try {
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
      await load();
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

  function toggleStrategy(name: string, enabled: boolean) {
    setSelectedStrategies((current) => {
      if (enabled) return Array.from(new Set([...current, name]));
      return current.filter((item) => item !== name);
    });
  }

  async function apply(runId: number) {
    try {
      await api.applyAnalysis(runId);
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
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
  const jobStatus = status?.job?.status;
  const statusText = status?.running ? "分析中" : jobStatus === "completed" ? "已完成" : status?.result ? "已有结果" : "空闲";
  const hasResult = Boolean(status?.result?.runs?.length);

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
            <input value={form.pcap1} onChange={(event) => setForm({ ...form, pcap1: event.target.value })} />
          </label>
          <label>
            <span>标签 DB</span>
            <input value={form.db1} onChange={(event) => setForm({ ...form, db1: event.target.value })} />
          </label>
          <label>
            <span>真实 PCAP</span>
            <input list="real-pcap-files" value={form.pcap2} onChange={(event) => setForm({ ...form, pcap2: event.target.value })} />
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
        <datalist id="real-pcap-files">
          {pcapFiles.map((file) => (
            <option key={file.path} value={file.path} />
          ))}
        </datalist>
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
          <button disabled={status?.running || !status?.result} onClick={() => apply(finalRun)}>
            <CheckCircle2 size={16} /> 应用 run {finalRun}
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

      <section className="panel-grid two">
        <div className="panel">
          <div className="panel-title">提交规则</div>
          <div className="compact-list">
            {(status?.result?.top_decisions ?? []).slice(0, 80).map((item) => (
              <div key={`${item.run_id}-${item.gid}-${item.sid}`}>
                <strong>{item.gid}:{item.sid}</strong>
                <span>{item.msg}</span>
                <em>{item.committed ? "commit" : "rollback"}</em>
              </div>
            ))}
          </div>
        </div>
        <div className="panel">
          <div className="panel-title">高误报规则</div>
          <div className="compact-list">
            {(status?.result?.rule_fp ?? []).slice(0, 80).map((item) => (
              <div key={`${item.run_id}-${item.gid}-${item.sid}`}>
                <strong>{item.gid}:{item.sid}</strong>
                <span>{item.msg}</span>
                <em>{pct(item.fp_rate)} / {pct(item.utilization)}</em>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}
