export type LuaOverride = {
  id: string;
  label: string;
  value: string;
  enabled: boolean;
  description?: string;
  category?: string;
};

export type Settings = {
  root_dir: string;
  swd: string;
  awd: string;
  pcap_dir: string;
  snort_config_path: string;
  snort_db_path: string;
  raw_rule_path: string;
  raw_snort_sqlite: string;
  interface: string;
  mode: "interface" | "pcap";
  pcap_file: string;
  active_run_id: number;
  need_output: boolean;
  need_alert: boolean;
  need_profiler: boolean;
  lua_overrides: LuaOverride[];
  analysis_disabled_strategies?: string[];
  last_applied_hash: string;
  last_applied_at?: string;
  last_applied_final_run?: number;
  updated_at: string;
};

export type SettingsResponse = {
  settings: Settings;
  effective_lua: string[];
  config_hash: string;
  needs_restart: boolean;
};

export type TelemetrySample = {
  time: string;
  pid?: number;
  cpu_percent: number;
  mem_mb: number;
  system_connections: number;
  established_tcp: number;
  udp_connections: number;
};

export type SystemPoint = {
  run_id: number;
  avg_cpu: number;
  avg_mem_mb: number;
  fp: number;
  fn: number;
  samples: number;
  created_at: string;
};

export type Overview = {
  status: {
    run_info: { pid: number; pgid: number; running: boolean; start_time: string };
    config: Record<string, unknown>;
  };
  running: boolean;
  needs_restart: boolean;
  config_hash: string;
  telemetry: TelemetrySample;
  db_stats: Record<string, any>;
  profiles: SystemPoint[];
  perf_tests: PerfTestSummary[];
};

export type AlertItem = {
  id: number;
  run_id: number;
  timestamp: string;
  proto: string;
  src_ap: string;
  dst_ap: string;
  gid: number;
  sid: number;
  rev: number;
  rule: string;
  action: string;
  created_at: string;
};

export type AlertList = {
  items: AlertItem[];
  total: number;
  summary: Record<string, any>;
  limit: number;
  offset: number;
};

export type Evaluation = {
  run_id: number;
  total_flows: number;
  benign_flows: number;
  malicious_flows: number;
  alerted_flows: number;
  false_positive_flows: number;
  detected_malicious_flows: number;
  missed_flows: number;
  unmatched_alert_flows: number;
  false_positive_rate: number;
  miss_rate: number;
  real_rule_time_us: number;
  real_avg_cpu: number;
  real_avg_mem_mb: number;
  base_load_ms: number;
  exp_runtime_ms: number;
  real_runtime_ms: number;
};

export type RunResult = {
  run_id: number;
  committed: boolean;
  rolled_back: boolean;
  factor: number;
  reason: string;
  evaluation: Evaluation;
};

export type TrimDecision = {
  run_id: number;
  gid: number;
  sid: number;
  rev: number;
  msg: string;
  source_file: string;
  reasons: string;
  functions: string;
  type: string;
  committed: boolean;
};

export type RuleFP = {
  run_id: number;
  gid: number;
  sid: number;
  rev: number;
  msg: string;
  source_file: string;
  alerted_flows: number;
  benign_alerted_flows: number;
  malicious_alerted_flows: number;
  unmatched_alerts: number;
  fp_rate: number;
  utilization: number;
};

export type AnalysisResult = {
  analyser_db_path: string;
  final_run_id: number;
  runs: RunResult[];
  trimmed_count: number;
  top_decision_total: number;
  top_decision_limit: number;
  top_decision_offset: number;
  top_decisions: TrimDecision[];
  rule_fp: RuleFP[];
};

export type AnalysisStatus = {
  job?: {
    id: string;
    status: string;
    error?: string;
    started_at: string;
    finished_at?: string;
  };
  running: boolean;
  restored: boolean;
  progress: number;
  expected_runs: number;
  result?: AnalysisResult;
  work_dir: string;
};

export type AnalysisStrategy = {
  name: string;
  type: "SAFE" | "ITER" | string;
};

export type RuleItem = {
  run_id: number;
  gid: number;
  sid: number;
  rev: number;
  action: string;
  proto: string;
  msg: string;
  classtype: string;
  enabled: boolean;
  source_file: string;
};

export type RuleList = {
  items: RuleItem[];
  total: number;
  limit: number;
  offset: number;
};

export type Recommendation = {
  gid: number;
  sid: number;
  rev: number;
  run_id: number;
  msg: string;
  source_file: string;
  reason: string;
  function?: string;
  fp_rate?: number;
  utilization?: number;
  enabled?: boolean;
  recommendation: string;
};

export type PerfTestSummary = {
  id: string;
  status: string;
  error?: string;
  started_at: string;
  finished_at?: string;
  config?: LuaOverride[];
  result?: {
    run_id: number;
    mode: string;
    duration_ms: number;
    work_dir: string;
    db_path: string;
    profiles: SystemPoint[];
    throughput_pps: number;
    throughput_mbps: number;
    rule_time_us: number;
    alert_count: number;
    rule_count: number;
    loaded_rule_count: number;
  };
};

export type CaptureSummary = {
  id: string;
  status: string;
  error?: string;
  started_at: string;
  finished_at?: string;
  result?: {
    interface: string;
    duration_ms: number;
    path: string;
    size: number;
    command: string;
    output?: string;
  };
};

export type FileItem = {
  path: string;
  name: string;
  size: number;
  mod_time: string;
};

export type SystemStatus = {
  interfaces: Array<{
    name: string;
    up: boolean;
    mac?: string;
    mtu?: number;
    speed?: string;
    offloads?: Array<{ name: string; enabled: boolean; fixed: boolean; raw: string }>;
  }>;
  cpu: {
    cpu_count: number;
    snort_pid?: number;
    snort_affinity?: string;
  };
};
