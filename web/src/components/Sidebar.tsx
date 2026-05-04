import {
  Activity,
  Bell,
  Gauge,
  LayoutDashboard,
  Settings2,
  SlidersHorizontal
} from "lucide-react";
import type { PageKey } from "../pages";

const items: Array<{ key: PageKey; label: string; icon: typeof LayoutDashboard }> = [
  { key: "overview", label: "概览", icon: LayoutDashboard },
  { key: "alerts", label: "警告", icon: Bell },
  { key: "rules", label: "规则", icon: Gauge },
  { key: "config", label: "配置", icon: SlidersHorizontal },
  { key: "system", label: "系统", icon: Settings2 }
];

type Props = {
  page: PageKey;
  onChange: (page: PageKey) => void;
  running: boolean;
};

export function Sidebar({ page, onChange, running }: Props) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <Activity size={20} />
        <span>SO</span>
      </div>
      <nav>
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              className={`nav-button ${page === item.key ? "active" : ""}`}
              onClick={() => onChange(item.key)}
              title={item.label}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>
      <div className={`run-dot ${running ? "on" : ""}`} title={running ? "Snort 运行中" : "Snort 未运行"} />
    </aside>
  );
}
