export type Primitive = string | number | boolean | null;

export type HistoryPoint = {
  timestamp: number;
  value: number;
};

export type ThroughputPoint = {
  timestamp: number;
  upload: number;
  download: number;
};

export type GenericRow = {
  id: string;
  [key: string]: Primitive;
};

export type OverviewSnapshot = {
  throughput: {
    upload: number;
    download: number;
    uploadTotal: number;
    downloadTotal: number;
    history: ThroughputPoint[];
  };
  memory: {
    used: number;
    total: number;
    history: HistoryPoint[];
  };
  connections: {
    active: number;
  };
};

export type ConnectionsSnapshot = {
  rows: GenericRow[];
  updatedAt: number;
};
