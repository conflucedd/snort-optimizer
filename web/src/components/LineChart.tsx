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
  minValue?: number;
  maxValue?: number;
  padZeroLine?: boolean;
};

export function LineChart({
  points,
  height = 180,
  color = "#f38020",
  altColor = "#2563eb",
  valueSuffix = "",
  label,
  showDots,
  fixedPointSpacing,
  minValue,
  maxValue,
  padZeroLine = true
}: Props) {
  const viewportRef = useRef<HTMLDivElement>(null);
  const [viewport, setViewport] = useState({ width: 0, height: 0 });
  const spacing = fixedPointSpacing ?? 0;
  const maxVisible = spacing > 0 && viewport.width > 0 ? Math.max(2, Math.floor((viewport.width - 58) / spacing) + 1) : points.length;
  const visiblePoints = spacing > 0 ? points.slice(-maxVisible) : points;
  const paddedCount = spacing > 0 && maxVisible > 0 ? maxVisible : visiblePoints.length;
  const leadingEmpty = Math.max(0, paddedCount - visiblePoints.length);
  const data =
    spacing > 0
      ? Array.from({ length: paddedCount }, (_, index) => {
          if (index < leadingEmpty) return { label: "", value: null as number | null, alt: null as number | null, index };
          const point = visiblePoints[index - leadingEmpty];
          return { ...point, index };
        })
      : visiblePoints.map((point, index) => ({ ...point, index }));
  const hasAlt = points.some((point) => point.alt !== undefined);
  const dots = showDots ?? data.length <= 28;
  const formatValue = (value: number) => `${value.toFixed(2)}${valueSuffix}`;
  const numericValues = points.flatMap((point) => [point.value, point.alt]).filter((value): value is number => typeof value === "number");
  const allZero = numericValues.length > 0 && numericValues.every((value) => value === 0);
  const yDomain: [number | "auto", number | "auto"] = [
    minValue ?? (padZeroLine && allZero ? -0.05 : "auto"),
    maxValue ?? (padZeroLine && allZero ? 1 : "auto")
  ];

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
      <RechartsLineChart width={width} height={height} data={data} margin={{ top: 4, right: 10, bottom: 4, left: 0 }}>
        <CartesianGrid stroke="#e8edf5" strokeDasharray="3 4" vertical={false} />
        <XAxis dataKey="index" type="category" hide />
        <YAxis
          width={44}
          tickLine={false}
          axisLine={false}
          tick={{ fill: "#6b7280", fontSize: 11 }}
          domain={yDomain}
          allowDataOverflow={maxValue !== undefined}
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
        {points.length > 0 && spacing > 0 ? (
          viewport.height > 0 ? (
            chart(viewport.width, viewport.height)
          ) : (
            <div className="line-chart-empty" />
          )
        ) : points.length > 0 ? (
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
