import React from 'react';

import { createMockOverviewStream } from '../api/mock';
import { OverviewCharts } from '../components/OverviewCharts';
import { useLiveSnapshot } from '../hooks/useLiveSnapshot';
import { OverviewSnapshot } from '../types';
import { formatBytes, formatRate } from '../utils/format';
import { ContentHeader } from '../components/ContentHeader';
import { StatCards } from '../components/StatCards';
import styles from './OverviewPage.module.scss';

const initialSnapshot: OverviewSnapshot = {
  throughput: {
    upload: 0,
    download: 0,
    uploadTotal: 0,
    downloadTotal: 0,
    history: [],
  },
  memory: {
    used: 0,
    total: 0,
    history: [],
  },
  connections: {
    active: 0,
  },
};

export function OverviewPage() {
  const snapshot = useLiveSnapshot({
    initialSnapshot,
    path: '/ws/overview',
    createMockStream: createMockOverviewStream,
  });

  const items = [
    { label: 'Upload', value: formatRate(snapshot.throughput.upload) },
    { label: 'Download', value: formatRate(snapshot.throughput.download) },
    { label: 'Upload Total', value: formatBytes(snapshot.throughput.uploadTotal) },
    { label: 'Download Total', value: formatBytes(snapshot.throughput.downloadTotal) },
    { label: 'Active Connections', value: snapshot.connections.active },
    {
      label: 'Memory Usage',
      value: `${formatBytes(snapshot.memory.used)} / ${formatBytes(snapshot.memory.total)}`,
    },
  ];

  return (
    <div>
      <ContentHeader title="Overview" />
      <div className={styles.root}>
        <StatCards items={items} />
        <div className={styles.charts}>
          <OverviewCharts
            trafficPoints={snapshot.throughput.history}
            memoryPoints={snapshot.memory.history}
          />
        </div>
      </div>
    </div>
  );
}
