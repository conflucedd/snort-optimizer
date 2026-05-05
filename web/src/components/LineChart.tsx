import {
  CartesianGrid,
  Line,
  LineChart as RechartsLineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

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
  const data = points.map((point, index) => ({ ...point, index }));
  const hasAlt = points.some((point) => point.alt !== undefined);
  const formatValue = (value: number) => `${value.toFixed(2)}${valueSuffix}`;

  return (
    <div className="chart-wrap" style={{ height }}>
      {label ? <div className="chart-label">{label}</div> : null}
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height="100%">
          <RechartsLineChart data={data} margin={{ top: 10, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="#eef0f4" vertical={false} />
            <XAxis dataKey="index" type="category" hide />
            <YAxis width={42} tickLine={false} axisLine={false} tick={{ fill: "#6b7280", fontSize: 11 }} />
            <Tooltip
              formatter={(value) => formatValue(Number(value))}
              labelFormatter={(_, payload) => payload?.[0]?.payload?.label ?? ""}
              contentStyle={{ borderRadius: 6, borderColor: "#d7dce5", fontSize: 12 }}
            />
            <Line
              type="monotone"
              dataKey="value"
              stroke={color}
              strokeWidth={2.5}
              dot={false}
              isAnimationActive={false}
              connectNulls
            />
            {hasAlt ? (
              <Line
                type="monotone"
                dataKey="alt"
                stroke={altColor}
                strokeWidth={2.5}
                dot={false}
                isAnimationActive={false}
                connectNulls
              />
            ) : null}
          </RechartsLineChart>
        </ResponsiveContainer>
      ) : (
        <div className="line-chart-empty" />
      )}
    </div>
  );
}
