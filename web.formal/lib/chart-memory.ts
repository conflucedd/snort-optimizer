import { createResource } from './createResource';
import { formatBytes } from '../utils/format';

export const chartJSResource = createResource(() => import('./chart-lib'));

export const commonDataSetProps = {
  borderWidth: 1,
  pointRadius: 0,
  tension: 0.2,
  fill: true,
};

export const memoryChartOptions: import('chart.js').ChartOptions<'line'> = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: {
    legend: { labels: { boxWidth: 20 } },
  },
  scales: {
    x: { display: false, type: 'category' },
    y: {
      type: 'linear',
      display: true,
      grid: {
        display: true,
        color: '#555',
        drawTicks: false,
      },
      border: {
        dash: [3, 6],
      },
      ticks: {
        maxTicksLimit: 3,
        callback(value: number | string) {
          return formatBytes(Number(value));
        },
      },
    },
  },
};

export const chartStyles = [
  {
    inuse: {
      backgroundColor: 'rgba(81, 168, 221, 0.5)',
      borderColor: 'rgb(81, 168, 221)',
    },
  },
];
