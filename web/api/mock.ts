import { ConnectionsSnapshot, GenericRow, HistoryPoint, OverviewSnapshot, ThroughputPoint } from '../types';

const HISTORY_SIZE = 30;

function createHistory(seed: number, step: number, values: number[]): HistoryPoint[] {
  return values.map((value, index) => ({
    timestamp: seed - step * (values.length - 1 - index),
    value,
  }));
}

function createThroughputHistory(seed: number, step: number, values: Array<{ upload: number; download: number }>): ThroughputPoint[] {
  return values.map((value, index) => ({
    timestamp: seed - step * (values.length - 1 - index),
    upload: value.upload,
    download: value.download,
  }));
}

function jitter(base: number, ratio: number) {
  return Math.max(0, Math.round(base + (Math.random() - 0.5) * base * ratio));
}

function buildOverviewSnapshot(previous?: OverviewSnapshot): OverviewSnapshot {
  const now = Date.now();
  const upload = jitter(previous?.throughput.upload ?? 420_000, 0.35);
  const download = jitter(previous?.throughput.download ?? 810_000, 0.35);
  const used = jitter(previous?.memory.used ?? 1_180_000_000, 0.08);
  const total = previous?.memory.total ?? 2_147_483_648;

  const throughputHistory = previous?.throughput.history ?? createThroughputHistory(
    now,
    2_000,
    Array.from({ length: HISTORY_SIZE }, (_, index) => ({
      upload: 300_000 + index * 12_000,
      download: 700_000 + index * 18_000,
    }))
  );
  const memoryHistory = previous?.memory.history ?? createHistory(
    now,
    2_000,
    Array.from({ length: HISTORY_SIZE }, (_, index) => 1_000_000_000 + index * 7_500_000)
  );

  return {
    throughput: {
      upload,
      download,
      uploadTotal: (previous?.throughput.uploadTotal ?? 12_000_000_000) + upload,
      downloadTotal: (previous?.throughput.downloadTotal ?? 34_000_000_000) + download,
      history: [...throughputHistory.slice(-HISTORY_SIZE + 1), { timestamp: now, upload, download }],
    },
    memory: {
      used,
      total,
      history: [...memoryHistory.slice(-HISTORY_SIZE + 1), { timestamp: now, value: used }],
    },
    connections: {
      active: jitter(previous?.connections.active ?? 24, 0.2),
    },
  };
}

function buildRows(): GenericRow[] {
  const services = ['Gateway', 'Orders', 'Events', 'Archive', 'Media', 'Billing'];
  const regions = ['cn-east', 'cn-north', 'us-west', 'eu-central'];
  const statuses = ['healthy', 'degraded', 'warning'];
  const protocols = ['ws', 'http', 'tcp'];

  return Array.from({ length: 28 }, (_, index) => ({
    id: `row-${index + 1}`,
    service: services[index % services.length],
    region: regions[index % regions.length],
    status: statuses[index % statuses.length],
    protocol: protocols[index % protocols.length],
    host: `node-${String(index + 1).padStart(2, '0')}.example.net`,
    sessions: 40 + ((index * 7) % 90),
    latencyMs: 12 + ((index * 11) % 85),
    throughput: `${120 + index * 8} req/min`,
    owner: ['Ops', 'Data', 'Infra'][index % 3],
  }));
}

function buildConnectionsSnapshot(previous?: ConnectionsSnapshot): ConnectionsSnapshot {
  const baseRows = previous?.rows.length ? previous.rows : buildRows();
  const rows = baseRows.map((row, index) => {
    const latencyMs = jitter(Number(row.latencyMs) || 30, 0.18);
    const sessions = jitter(Number(row.sessions) || 60, 0.14);
    const statusPool = ['healthy', 'healthy', 'degraded', 'warning'];
    const throughputValue = 100 + ((index * 9 + Math.floor(Math.random() * 20)) % 220);

    return {
      ...row,
      latencyMs,
      sessions,
      status: statusPool[(index + Math.floor(Math.random() * statusPool.length)) % statusPool.length],
      throughput: `${throughputValue} req/min`,
    };
  });

  return {
    rows,
    updatedAt: Date.now(),
  };
}

export function createMockOverviewStream(onData: (snapshot: OverviewSnapshot) => void) {
  let current = buildOverviewSnapshot();
  onData(current);

  const timer = window.setInterval(() => {
    current = buildOverviewSnapshot(current);
    onData(current);
  }, 2_000);

  return () => window.clearInterval(timer);
}

export function createMockConnectionsStream(onData: (snapshot: ConnectionsSnapshot) => void) {
  let current = buildConnectionsSnapshot();
  onData(current);

  const timer = window.setInterval(() => {
    current = buildConnectionsSnapshot(current);
    onData(current);
  }, 2_500);

  return () => window.clearInterval(timer);
}
