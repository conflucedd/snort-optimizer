import { Camera, Play, RotateCcw, Square, RefreshCw, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import { api, compactBytes, fmtNumber } from "../api";
import { LineChart } from "../components/LineChart";
import { MetricCard } from "../components/MetricCard";
import { StatusPill } from "../components/StatusPill";
import type {
  CaptureSummary,
  FileItem,
  Overview as OverviewType,
  Settings,
  SystemStatus,
  TelemetrySample
} from "../types";

type Props = {
  settings?: Settings;
  onSettingsReload: () => void;
};

export function Overview({ settings, onSettingsReload }: Props) {
  const [overview, setOverview] = useState<OverviewType>();
  const [history, setHistory] = useState<TelemetrySample[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");

  async function load() {
    try {
      const data = await api.overview();
      setOverview(data);
      setHistory((prev) => (data.running ? [...prev.slice(-59), data.telemetry] : []));
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 2500);
    return () => window.clearInterval(timer);
  }, []);

  async function action(name: string, fn: () => Promise<unknown>) {
    setBusy(name);
    setError("");
    try {
      await fn();
      await load();
      onSettingsReload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy("");
    }
  }

  const running = Boolean(overview?.running);
  const cpuPoints = running
    ? history.map((point) => ({
        label: new Date(point.time).toLocaleTimeString(),
        value: point.cpu_percent,
        alt: point.mem_mb
      }))
    : [];

  const tables = overview?.db_stats?.tables ?? {};
  const alerts = overview?.db_stats?.alerts ?? {};

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>概览</h1>
          <div className="muted">{settings?.interface ? `Interface ${settings.interface}` : "Interface 未设置"}</div>
        </div>
        <div className="head-actions">
          <StatusPill tone={running ? "good" : "neutral"}>{running ? "运行中" : "已停止"}</StatusPill>
          {overview?.needs_restart ? <StatusPill tone="warn">配置待重启</StatusPill> : null}
        </div>
      </header>

      {error ? <div className="banner bad">{error}</div> : null}

      <section className="metric-grid">
        <MetricCard label="CPU" value={`${fmtNumber(overview?.telemetry.cpu_percent ?? 0, 1)}%`} sub="当前 Snort 进程" />
        <MetricCard label="内存" value={`${fmtNumber(overview?.telemetry.mem_mb ?? 0, 1)} MB`} sub="RSS" />
        <MetricCard
          label="抓包状态"
          value={running ? "Active" : "Idle"}
          tone={running ? "good" : "neutral"}
          sub={String(overview?.status.config?.Mode ?? settings?.mode ?? "")}
        />
        <MetricCard
          label="系统连接"
          value={fmtNumber(overview?.telemetry.system_connections ?? 0)}
          sub={`${fmtNumber(overview?.telemetry.established_tcp ?? 0)} TCP / ${fmtNumber(
            overview?.telemetry.udp_connections ?? 0
          )} UDP`}
        />
      </section>

      <section className="panel-grid two">
        <div className="panel">
          <div className="panel-title">CPU / Mem</div>
          <LineChart points={cpuPoints} valueSuffix="" label="live" />
          <div className="chart-legend">
            <span className="legend orange" /> CPU %
            <span className="legend blue" /> Mem MB
          </div>
        </div>
        <CapturePanel settings={settings} />
      </section>

      <section className="panel-grid two">
        <div className="panel">
          <div className="panel-title">控制</div>
          <div className="button-row">
            <button className="primary" disabled={busy !== "" || running} onClick={() => action("start", api.startSnort)}>
              <Play size={16} /> 启动
            </button>
            <button
              className={overview?.needs_restart ? "warn" : ""}
              disabled={busy !== ""}
              onClick={() => action("restart", api.restartSnort)}
            >
              <RefreshCw size={16} /> 重启
            </button>
            <button disabled={busy !== "" || !running} onClick={() => action("stop", api.stopSnort)}>
              <Square size={16} /> 停止
            </button>
            <button disabled={busy !== ""} onClick={() => action("reset", api.resetSnort)}>
              <RotateCcw size={16} /> 重置
            </button>
          </div>
          <div className="stats-table">
            <div>
              <span>Alerts</span>
              <strong>{fmtNumber(alerts.total ?? 0)}</strong>
            </div>
            <div>
              <span>Rules</span>
              <strong>{fmtNumber(tables.rules?.run ?? 0)}</strong>
            </div>
            <div>
              <span>Rule profiler</span>
              <strong>{fmtNumber(tables.rule_profiler_metrics?.run ?? 0)}</strong>
            </div>
            <div>
              <span>DB</span>
              <strong>{overview?.db_stats?.exists ? "ready" : "missing"}</strong>
            </div>
          </div>
        </div>
        <PerfTestPanel />
      </section>
    </div>
  );
}

function CapturePanel({ settings }: { settings?: Settings }) {
  const [interfaces, setInterfaces] = useState<SystemStatus["interfaces"]>([]);
  const [selectedInterface, setSelectedInterface] = useState(settings?.interface ?? "");
  const [durationS, setDurationS] = useState(60);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [captures, setCaptures] = useState<CaptureSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    try {
      const [system, pcapData, captureData] = await Promise.all([api.system(), api.pcapFiles(), api.captureStatus()]);
      setInterfaces(system.interfaces);
      setFiles(pcapData.files);
      setCaptures(captureData.items);
      setSelectedInterface((current) => current || settings?.interface || system.interfaces.find((item) => item.up)?.name || "");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 3000);
    return () => window.clearInterval(timer);
  }, [settings?.interface]);

  async function start() {
    setError("");
    setBusy(true);
    try {
      await api.startCapture({ interface: selectedInterface, duration_s: durationS });
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const latestRunning = captures.find((item) => item.status === "running");

  return (
    <div className="panel">
      <div className="panel-title">真实流量抓包</div>
      {error ? <div className="inline-error">{error}</div> : null}
      <div className="form-grid capture-form">
        <label>
          <span>Interface</span>
          <select value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)}>
            <option value="">选择网卡</option>
            {interfaces.map((item) => (
              <option key={item.name} value={item.name}>
                {item.name}
                {item.up ? " up" : ""}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>时长</span>
          <input
            type="number"
            min={5}
            max={3600}
            value={durationS}
            onChange={(event) => setDurationS(Number(event.target.value))}
          />
        </label>
      </div>
      <button className="primary" disabled={busy || !selectedInterface || Boolean(latestRunning)} onClick={start}>
        <Camera size={16} /> {latestRunning ? "抓包中" : "开始抓包"}
      </button>
      <div className="compact-list mini-list">
        {files.slice(0, 5).map((file) => (
          <div key={file.path}>
            <strong>{file.name}</strong>
            <span>{file.path}</span>
            <em>{compactBytes(file.size)}</em>
          </div>
        ))}
      </div>
    </div>
  );
}

function PerfTestPanel() {
  const [pcapFile, setPcapFile] = useState("");
  const [durationS, setDurationS] = useState(30);
  const [message, setMessage] = useState("");

  async function start() {
    setMessage("");
    try {
      await api.startPerfTest({ mode: pcapFile ? "pcap" : "interface", pcap_file: pcapFile, duration_s: durationS });
      setMessage("已启动");
    } catch (err) {
      setMessage((err as Error).message);
    }
  }

  return (
    <div className="panel">
      <div className="panel-title">性能测试</div>
      <div className="form-grid">
        <label>
          <span>PCAP</span>
          <input value={pcapFile} onChange={(event) => setPcapFile(event.target.value)} placeholder="/path/to/sample.pcap" />
        </label>
        <label>
          <span>时长</span>
          <input
            type="number"
            min={5}
            max={3600}
            value={durationS}
            onChange={(event) => setDurationS(Number(event.target.value))}
          />
        </label>
      </div>
      <button className="primary" onClick={start}>
        <Zap size={16} /> 运行测试
      </button>
      {message ? <div className="inline-message">{message}</div> : null}
    </div>
  );
}
