import type { Chart as ChartJS, ChartConfiguration, ChartOptions } from 'chart.js';
import React, { Suspense, useEffect, useMemo, useRef } from 'react';

import {
  chartJSResource as memoryChartJSResource,
  chartStyles as memoryChartStyles,
  commonDataSetProps as memoryDataSetProps,
  memoryChartOptions,
} from '../lib/chart-memory';
import {
  chartJSResource,
  chartStyles,
  commonChartOptions,
  commonDataSetProps,
} from '../lib/chart';
import { HistoryPoint, ThroughputPoint } from '../types';
import styles from './OverviewCharts.module.scss';

const canvasStyle: React.CSSProperties = {
  width: '100%',
  height: '100%',
  padding: '10px',
  borderRadius: '10px',
};

type TrafficData = {
  labels: number[];
  datasets: ChartConfiguration<'line'>['data']['datasets'];
};

type MemoryData = {
  labels: number[];
  datasets: ChartConfiguration<'line'>['data']['datasets'];
};

function useStableChart(
  elementId: string,
  chartFactory: () => typeof import('../lib/chart-lib'),
  data: TrafficData | MemoryData,
  options: ChartOptions<'line'>
) {
  const chartRef = useRef<ChartJS<'line'> | null>(null);
  const ChartMod = chartFactory();

  useEffect(() => {
    const canvas = document.getElementById(elementId) as HTMLCanvasElement | null;

    if (!canvas) {
      return;
    }

    const context = canvas.getContext('2d');

    if (!context) {
      return;
    }

    if (!chartRef.current) {
      chartRef.current = new ChartMod.Chart(context, {
        type: 'line',
        data,
        options,
      });
    }
    return () => {
      chartRef.current?.destroy();
      chartRef.current = null;
    };
  }, [ChartMod.Chart, elementId, options]);

  useEffect(() => {
    if (!chartRef.current) {
      return;
    }

    chartRef.current.data.labels = data.labels;
    chartRef.current.data.datasets.forEach((dataset, index) => {
      dataset.data = data.datasets[index]?.data ?? [];
      dataset.label = data.datasets[index]?.label;
      dataset.backgroundColor = data.datasets[index]?.backgroundColor;
      dataset.borderColor = data.datasets[index]?.borderColor;
      dataset.borderWidth = data.datasets[index]?.borderWidth;
      dataset.pointRadius = data.datasets[index]?.pointRadius;
      dataset.tension = data.datasets[index]?.tension;
      dataset.fill = data.datasets[index]?.fill;
    });
    chartRef.current.update();
  }, [data]);
}

function TrafficChart({ points }: { points: ThroughputPoint[] }) {
  const data = useMemo<TrafficData>(
    () => ({
      labels: points.map((point) => point.timestamp),
      datasets: [
        {
          ...commonDataSetProps,
          ...chartStyles[0].up,
          label: 'Up',
          data: points.map((point) => point.upload),
        },
        {
          ...commonDataSetProps,
          ...chartStyles[0].down,
          label: 'Down',
          data: points.map((point) => point.download),
        },
      ],
    }),
    [points]
  );

  useStableChart('re-traffic-chart', () => chartJSResource.read(), data, commonChartOptions);

  return (
    <div className={styles.wrapper}>
      <canvas id="re-traffic-chart" style={canvasStyle} className={styles.canvas} />
    </div>
  );
}

function MemoryChart({ points }: { points: HistoryPoint[] }) {
  const data = useMemo<MemoryData>(
    () => ({
      labels: points.map((point) => point.timestamp),
      datasets: [
        {
          ...memoryDataSetProps,
          ...memoryChartStyles[0].inuse,
          label: 'Memory',
          data: points.map((point) => point.value),
        },
      ],
    }),
    [points]
  );

  useStableChart('re-memory-chart', () => memoryChartJSResource.read(), data, memoryChartOptions);

  return (
    <div className={styles.wrapper}>
      <canvas id="re-memory-chart" style={canvasStyle} className={styles.canvas} />
    </div>
  );
}

export function OverviewCharts({
  trafficPoints,
  memoryPoints,
}: {
  trafficPoints: ThroughputPoint[];
  memoryPoints: HistoryPoint[];
}) {
  return (
    <Suspense fallback={<div className={styles.fallback} />}>
      <TrafficChart points={trafficPoints} />
      <MemoryChart points={memoryPoints} />
    </Suspense>
  );
}
