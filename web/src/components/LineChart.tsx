import { useEffect, useRef, useState } from "react";
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
  showDots?: boolean;
  fixedPointSpacing?: number;
};

export function LineChart({
  points,
  height = 180,
  color = "#f38020",
  altColor = "#2563eb",
  valueSuffix = "",
  label,
  showDots,
  fixedPointSpacing
}: Props) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState({ width: 0, height: 0 });
  const spacing = fixedPointSpacing ?? 0;
  const maxVisible = spacing > 0 && viewport.width > 0 ? Math.max(2, Math.floor((viewport.width - 62) / spacing) + 1) : points.length;
  const visiblePoints = spacing > 0 ? points.slice(-maxVisible) : points;
  const data = visiblePoints.map((point, index) => ({ ...point, index }));
  const hasAlt = points.some((point) => point.alt !== undefined);
  const dots = showDots ?? data.length <= 28;
  const formatValue = (value: number) => `${value.toFixed(2)}${valueSuffix}`;
  const fixedWidth = spacing > 0 ? Math.max(86, (data.length - 1) * spacing + 62) : 0;

  useEffect(() => {
    if (!viewportRef.current) return;
    const observer = new ResizeObserver(([entry]) => {
      setViewport({
        width: entry.contentRect.width,
        height: entry.contentRect.height
      });
    });
    observer.observe(viewportRef.current);
    return () => observer.disconnect();
  }, []);

  function chart(width?: number, height?: number) {
    return (
      <RechartsLineChart width={width} height={height} data={data} margin={{ top: 8, right: 12, bottom: 0, left: -6 }}>
        <CartesianGrid stroke="#e8edf5" strokeDasharray="3 4" vertical={false} />
        <XAxis dataKey="index" type="category" hide />
        <YAxis
          width={42}
          tickLine={false}
          axisLine={false}
          tick={{ fill: "#6b7280", fontSize: 11 }}
          domain={["auto", "auto"]}
        />
        <Tooltip
          formatter={(value) => formatValue(Number(value))}
          labelFormatter={(_, payload) => payload?.[0]?.payload?.label ?? ""}
          contentStyle={{ borderRadius: 6, borderColor: "#d7dce5", fontSize: 12 }}
        />
        <Line
          type="linear"
          dataKey="value"
          stroke={color}
          strokeWidth={2}
          dot={dots ? { r: 2, strokeWidth: 1 } : false}
          activeDot={{ r: 4 }}
          isAnimationActive={false}
          connectNulls
        />
        {hasAlt ? (
          <Line
            type="linear"
            dataKey="alt"
            stroke={altColor}
            strokeWidth={2}
            dot={dots ? { r: 2, strokeWidth: 1 } : false}
            activeDot={{ r: 4 }}
            isAnimationActive={false}
            connectNulls
          />
        ) : null}
      </RechartsLineChart>
    );
  }

  return (
    <div className="chart-wrap" style={{ height }}>
      {label ? <div className="chart-label">{label}</div> : null}
      <div className="chart-viewport" ref={viewportRef}>
        {data.length > 0 && spacing > 0 ? (
          viewport.height > 0 ? (
            <div className="chart-fixed-inner" style={{ width: fixedWidth, height: viewport.height }}>
              {chart(fixedWidth, viewport.height)}
            </div>
          ) : (
            <div className="line-chart-empty" />
          )
        ) : data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            {chart()}
          </ResponsiveContainer>
        ) : (
          <div className="line-chart-empty" />
        )}
      </div>
    </div>
  );
}
