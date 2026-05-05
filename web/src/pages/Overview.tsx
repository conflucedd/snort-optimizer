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
  PerfTestSummary,
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
      setHistory((prev) => (data.running ? [...prev.slice(-239), data.telemetry] : []));
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 1000);
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
        value: point.cpu_percent
      }))
    : [];
  const memPoints = running
    ? history.map((point) => ({
        label: new Date(point.time).toLocaleTimeString(),
        value: point.mem_mb
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
          <div className="telemetry-charts">
            <div>
              <div className="telemetry-chart-head">
                <strong>CPU</strong>
                <span>0 - 100%</span>
              </div>
              <LineChart points={cpuPoints} height={130} fixedPointSpacing={18} showDots={false} minValue={0} maxValue={100} />
            </div>
            <div>
              <div className="telemetry-chart-head">
                <strong>Mem</strong>
                <span>0 - auto MB</span>
              </div>
              <LineChart points={memPoints} height={130} color="#2563eb" fixedPointSpacing={18} showDots={false} minValue={0} />
            </div>
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
        <PerfTestPanel settings={settings} />
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

  async function stop() {
    setError("");
    setBusy(true);
    try {
      await api.stopCapture();
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
      <div className="button-row">
        <button
          className={latestRunning || busy ? "running" : "primary"}
          disabled={busy || !selectedInterface || Boolean(latestRunning)}
          onClick={start}
        >
          <Camera size={16} /> {busy ? "启动中" : latestRunning ? "抓包中" : "开始抓包"}
        </button>
        <button disabled={busy || !latestRunning} onClick={stop}>
          <Square size={16} /> 停止抓包
        </button>
      </div>
      <div className="compact-list mini-list path-list">
        {files.slice(0, 5).map((file) => (
          <div key={file.path}>
            <span>{file.path}</span>
            <em>{compactBytes(file.size)}</em>
          </div>
        ))}
      </div>
    </div>
  );
}

function PerfTestPanel({ settings }: { settings?: Settings }) {
  const [pcapFile, setPcapFile] = useState("");
  const [durationS, setDurationS] = useState(30);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [tests, setTests] = useState<PerfTestSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function load() {
    const [pcapData, perfData] = await Promise.all([api.pcapFiles(), api.perfTests()]);
    setFiles(pcapData.files);
    setTests(perfData.items);
  }

  useEffect(() => {
    load().catch((err) => setMessage((err as Error).message));
    const timer = window.setInterval(() => {
      load().catch((err) => setMessage((err as Error).message));
    }, 3000);
    return () => window.clearInterval(timer);
  }, []);

  async function start() {
    setMessage("");
    setBusy(true);
    try {
      await api.startPerfTest({ mode: pcapFile ? "pcap" : "interface", pcap_file: pcapFile, duration_s: durationS });
      await load();
    } catch (err) {
      setMessage((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setMessage("");
    setBusy(true);
    try {
      await api.stopPerfTest();
      await load();
    } catch (err) {
      setMessage((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const latestRunning = tests.find((item) => item.status === "running");
  const latest = tests[0];
  const latestResult = latest?.result;
  const configItems = latestRunning?.config?.length ? latestRunning.config : settings?.lua_overrides ?? latest?.config ?? [];
  const avgCPU =
    latestResult?.profiles && latestResult.profiles.length > 0
      ? latestResult.profiles.reduce((sum, item) => sum + item.avg_cpu, 0) / latestResult.profiles.length
      : 0;
  const avgMem =
    latestResult?.profiles && latestResult.profiles.length > 0
      ? latestResult.profiles.reduce((sum, item) => sum + item.avg_mem_mb, 0) / latestResult.profiles.length
      : 0;
  const statusMessage = latestRunning
    ? "性能测试运行中"
    : latest?.status === "completed"
      ? "上次测试已完成"
      : latest?.status === "failed"
        ? latest.error
        : message;

  return (
    <div className="panel">
      <div className="panel-title">性能测试</div>
      <div className="form-grid">
        <label>
          <span>PCAP</span>
          <select value={pcapFile} disabled={Boolean(latestRunning)} onChange={(event) => setPcapFile(event.target.value)}>
            <option value="">使用当前网卡</option>
            {files.map((file) => (
              <option key={file.path} value={file.path}>
                {file.path} ({compactBytes(file.size)})
              </option>
            ))}
          </select>
        </label>
        {!pcapFile ? (
          <label>
            <span>时长</span>
            <input
              type="number"
              min={5}
              max={3600}
              disabled={Boolean(latestRunning)}
              value={durationS}
              onChange={(event) => setDurationS(Number(event.target.value))}
            />
          </label>
        ) : null}
      </div>
      {configItems.length > 0 ? (
        <div className="perf-config-grid">
          {configItems.map((override) => (
            <label key={override.id || override.value}>
              <input type="checkbox" checked={override.enabled} disabled readOnly />
              <span>{override.label || override.id || override.value}</span>
            </label>
          ))}
        </div>
      ) : null}
      <div className="button-row">
        <button className={latestRunning || busy ? "running" : "primary"} disabled={busy || Boolean(latestRunning)} onClick={start}>
          <Zap size={16} /> {busy ? "启动中" : latestRunning ? "测试中" : "运行测试"}
        </button>
        <button disabled={busy || !latestRunning} onClick={stop}>
          <Square size={16} /> 停止测试
        </button>
      </div>
      {statusMessage ? <div className="inline-message">{statusMessage}</div> : null}
      {latestResult ? (
        <div className="stats-table perf-stats">
          <div>
            <span>Duration</span>
            <strong>{fmtNumber(latestResult.duration_ms / 1000, 1)} s</strong>
          </div>
          <div>
            <span>Rules</span>
            <strong>{fmtNumber(latestResult.loaded_rule_count || latestResult.rule_count)}</strong>
          </div>
          <div>
            <span>Alerts</span>
            <strong>{fmtNumber(latestResult.alert_count)}</strong>
          </div>
          <div>
            <span>Rule time</span>
            <strong>{fmtNumber(latestResult.rule_time_us / 1000, 0)} ms</strong>
          </div>
          <div>
            <span>Throughput</span>
            <strong>{fmtNumber(latestResult.throughput_pps, 0)} pkt/s</strong>
          </div>
          <div>
            <span>Avg CPU</span>
            <strong>{fmtNumber(avgCPU, 1)}%</strong>
          </div>
          <div>
            <span>Avg Mem</span>
            <strong>{fmtNumber(avgMem, 1)} MB</strong>
          </div>
        </div>
      ) : null}
    </div>
  );
}
