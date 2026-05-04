type Point = {
  label: string;
  value: number;
  alt?: number;
};

type Props = {
  points: Point[];
  height?: number;
  color?: string;
  altColor?: string;
  valueSuffix?: string;
  label?: string;
};

export function LineChart({
  points,
  height = 180,
  color = "#f38020",
  altColor = "#2563eb",
  valueSuffix = "",
  label
}: Props) {
  const width = 640;
  const pad = 20;
  const values = points.flatMap((point) => [point.value, point.alt ?? point.value]);
  const max = Math.max(1, ...values);
  const min = Math.min(0, ...values);
  const toX = (index: number) => pad + (index * (width - pad * 2)) / Math.max(1, points.length - 1);
  const toY = (value: number) => height - pad - ((value - min) * (height - pad * 2)) / Math.max(1, max - min);
  const line = (selector: (point: Point) => number | undefined) =>
    points
      .map((point, index) => {
        const value = selector(point);
        if (value === undefined) return "";
        return `${index === 0 ? "M" : "L"} ${toX(index).toFixed(1)} ${toY(value).toFixed(1)}`;
      })
      .join(" ");

  return (
    <div className="chart-wrap">
      {label ? <div className="chart-label">{label}</div> : null}
      <svg className="line-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label ?? "line chart"}>
        <line x1={pad} x2={width - pad} y1={height - pad} y2={height - pad} className="axis" />
        <line x1={pad} x2={pad} y1={pad} y2={height - pad} className="axis" />
        {[0.25, 0.5, 0.75].map((step) => {
          const y = pad + step * (height - pad * 2);
          return <line key={step} x1={pad} x2={width - pad} y1={y} y2={y} className="grid" />;
        })}
        {points.length > 0 ? (
          <>
            <path d={line((point) => point.value)} fill="none" stroke={color} strokeWidth="3" strokeLinecap="round" />
            {points.some((point) => point.alt !== undefined) ? (
              <path d={line((point) => point.alt)} fill="none" stroke={altColor} strokeWidth="3" strokeLinecap="round" />
            ) : null}
            {points.map((point, index) => (
              <circle key={`${point.label}-${index}`} cx={toX(index)} cy={toY(point.value)} r="3.5" fill={color}>
                <title>{`${point.label}: ${point.value.toFixed(2)}${valueSuffix}`}</title>
              </circle>
            ))}
          </>
        ) : (
          <text x={width / 2} y={height / 2} textAnchor="middle" className="empty-chart">
            暂无数据
          </text>
        )}
      </svg>
    </div>
  );
}
