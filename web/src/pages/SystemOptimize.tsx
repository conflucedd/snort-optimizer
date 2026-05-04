import { Cpu, Network } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../api";
import type { SystemStatus } from "../types";

export function SystemOptimize() {
  const [status, setStatus] = useState<SystemStatus>();
  const [cpus, setCpus] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    try {
      setStatus(await api.system());
    } catch (err) {
      setMessage((err as Error).message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function offload(iface: string, feature: string, enabled: boolean) {
    const result = await api.setOffload({ interface: iface, feature, enabled });
    setMessage(JSON.stringify(result));
    await load();
  }

  async function affinity() {
    const result = await api.setAffinity(cpus);
    setMessage(JSON.stringify(result));
    await load();
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>系统优化</h1>
          <div className="muted">offload / affinity</div>
        </div>
      </header>
      {message ? <div className="banner">{message}</div> : null}

      <section className="panel-grid two">
        <div className="panel">
          <div className="panel-title">
            <Network size={16} /> 网卡
          </div>
          <div className="interface-list">
            {(status?.interfaces ?? []).map((iface) => (
              <div key={iface.name} className="interface-card">
                <div className="interface-head">
                  <strong>{iface.name}</strong>
                  <span className={iface.up ? "good-text" : "muted"}>{iface.up ? "up" : "down"}</span>
                </div>
                <div className="muted">{iface.mac} {iface.speed ? ` / ${iface.speed}` : ""}</div>
                <div className="offload-grid">
                  {(iface.offloads ?? [])
                    .filter((item) => ["generic-receive-offload", "tcp-segmentation-offload", "generic-segmentation-offload", "rx-checksumming", "tx-checksumming"].includes(item.name))
                    .map((item) => (
                      <button
                        key={item.name}
                        disabled={item.fixed}
                        className={item.enabled ? "toggle-on" : ""}
                        onClick={() => offload(iface.name, item.name, !item.enabled)}
                      >
                        {item.name.split("-").join(" ")}
                      </button>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="panel">
          <div className="panel-title">
            <Cpu size={16} /> CPU 亲和性
          </div>
          <div className="stats-table">
            <div>
              <span>CPU</span>
              <strong>{status?.cpu.cpu_count ?? 0}</strong>
            </div>
            <div>
              <span>Snort PID</span>
              <strong>{status?.cpu.snort_pid ?? 0}</strong>
            </div>
            <div>
              <span>Affinity</span>
              <strong>{status?.cpu.snort_affinity || "-"}</strong>
            </div>
          </div>
          <div className="form-grid">
            <label>
              <span>CPU list</span>
              <input value={cpus} onChange={(event) => setCpus(event.target.value)} placeholder="0-3 或 2,3" />
            </label>
          </div>
          <button className="primary" onClick={affinity}>应用亲和性</button>
        </div>
      </section>
    </div>
  );
}
