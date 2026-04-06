import { createResource } from './createResource';
import { formatBytes } from '../utils/format';

export const chartJSResource = createResource(() => import('./chart-lib'));

export const commonDataSetProps = {
  borderWidth: 1,
  pointRadius: 0,
  tension: 0.2,
  fill: true,
};

export const commonChartOptions: import('chart.js').ChartOptions<'line'> = {
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
        maxTicksLimit: 5,
        callback(value: number | string) {
          return `${formatBytes(Number(value))}/s `;
        },
      },
    },
  },
};

export const chartStyles = [
  {
    down: {
      backgroundColor: 'rgba(81, 168, 221, 0.5)',
      borderColor: 'rgb(81, 168, 221)',
    },
    up: {
      backgroundColor: 'rgba(219, 77, 109, 0.5)',
      borderColor: 'rgb(219, 77, 109)',
    },
  },
];
