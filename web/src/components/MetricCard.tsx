type Props = {
  label: string;
  value: string;
  tone?: "neutral" | "good" | "warn" | "bad";
  sub?: string;
};

export function MetricCard({ label, value, tone = "neutral", sub }: Props) {
  return (
    <div className={`metric-card ${tone}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {sub ? <div className="metric-sub">{sub}</div> : null}
    </div>
  );
}
