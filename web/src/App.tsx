import { useEffect, useState } from "react";
import { api } from "./api";
import { Sidebar } from "./components/Sidebar";
import { Alerts } from "./pages/Alerts";
import { ConfigOptimize } from "./pages/ConfigOptimize";
import { Overview } from "./pages/Overview";
import { RuleOptimize } from "./pages/RuleOptimize";
import { SystemOptimize } from "./pages/SystemOptimize";
import type { PageKey } from "./pages";
import type { Settings } from "./types";
import "./styles.css";

export function App() {
  const [page, setPage] = useState<PageKey>("overview");
  const [settings, setSettings] = useState<Settings>();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  async function loadSettings() {
    try {
      const response = await api.settings();
      setSettings(response.settings);
      setError("");
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function loadOverview() {
    try {
      const response = await api.overview();
      setRunning(response.running);
    } catch {
      setRunning(false);
    }
  }

  useEffect(() => {
    loadSettings();
    loadOverview();
    const timer = window.setInterval(loadOverview, 3000);
    return () => window.clearInterval(timer);
  }, []);

  return (
    <div className="app-shell">
      <Sidebar page={page} onChange={setPage} running={running} />
      <main className="main">
        {error ? <div className="banner bad">{error}</div> : null}
        {page === "overview" ? <Overview settings={settings} onSettingsReload={loadSettings} /> : null}
        {page === "alerts" ? <Alerts settings={settings} /> : null}
        {page === "rules" ? <RuleOptimize settings={settings} onSettings={setSettings} /> : null}
        {page === "config" ? <ConfigOptimize settings={settings} onSettings={setSettings} /> : null}
        {page === "system" ? <SystemOptimize /> : null}
      </main>
    </div>
  );
}
