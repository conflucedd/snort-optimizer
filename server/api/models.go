package api

import (
	"snort-optimizer/analyser/types"
	"snort-optimizer/server/store"
	"snort-optimizer/wrap"
)

type APIError struct {
	Error string `json:"error"`
}

type SettingsResponse struct {
	Settings     store.AppSettings `json:"settings"`
	EffectiveLua []string          `json:"effective_lua"`
	ConfigHash   string            `json:"config_hash"`
	NeedsRestart bool              `json:"needs_restart"`
}

type OverviewResponse struct {
	Status       wrap.Status       `json:"status"`
	Running      bool              `json:"running"`
	NeedsRestart bool              `json:"needs_restart"`
	ConfigHash   string            `json:"config_hash"`
	Telemetry    TelemetrySample   `json:"telemetry"`
	DBStats      map[string]any    `json:"db_stats"`
	Profiles     []SystemPoint     `json:"profiles"`
	PerfTests    []PerfTestSummary `json:"perf_tests"`
}

type TelemetrySample struct {
	Time              string  `json:"time"`
	PID               int     `json:"pid,omitempty"`
	CPUPercent        float64 `json:"cpu_percent"`
	MemMB             float64 `json:"mem_mb"`
	SystemConnections int     `json:"system_connections"`
	EstablishedTCP    int     `json:"established_tcp"`
	UDPConnections    int     `json:"udp_connections"`
}

type SystemPoint struct {
	RunID     int64   `json:"run_id"`
	AvgCPU    float64 `json:"avg_cpu"`
	AvgMemMB  float64 `json:"avg_mem_mb"`
	FP        float64 `json:"fp"`
	FN        float64 `json:"fn"`
	Samples   int64   `json:"samples"`
	CreatedAt string  `json:"created_at"`
}

type AlertListResponse struct {
	Items   []AlertItem    `json:"items"`
	Total   int64          `json:"total"`
	Summary map[string]any `json:"summary"`
	Limit   int            `json:"limit"`
	Offset  int            `json:"offset"`
}

type AlertItem struct {
	ID        int64  `json:"id"`
	RunID     int64  `json:"run_id"`
	Timestamp string `json:"timestamp"`
	Proto     string `json:"proto"`
	SrcAP     string `json:"src_ap"`
	DstAP     string `json:"dst_ap"`
	GID       int64  `json:"gid"`
	SID       int64  `json:"sid"`
	Rev       int64  `json:"rev"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
	CreatedAt string `json:"created_at"`
}

type AnalysisStartRequest struct {
	Pcap1               string   `json:"pcap1"`
	DB1                 string   `json:"db1"`
	Pcap2               string   `json:"pcap2"`
	SnortConfig         string   `json:"snort_config"`
	RawSnortSQLite      string   `json:"raw_snort_sqlite"`
	RawRulePath         string   `json:"raw_rule_path"`
	WorkDir             string   `json:"work_dir"`
	MaxRound            int      `json:"max_round"`
	Factor              float64  `json:"factor"`
	MaxMissRateIncrease float64  `json:"max_miss_rate_increase"`
	MaxFPRateIncrease   float64  `json:"max_fp_rate_increase"`
	Strategies          []string `json:"strategies"`
	DisabledStrategies  []string `json:"disabled_strategies"`
	ForceNew            bool     `json:"force_new"`
}

type AnalysisStatusResponse struct {
	Job          *store.JobRecord    `json:"job,omitempty"`
	Running      bool                `json:"running"`
	Restored     bool                `json:"restored"`
	Progress     float64             `json:"progress"`
	ExpectedRuns int                 `json:"expected_runs"`
	Result       *AnalysisResultView `json:"result,omitempty"`
	WorkDir      string              `json:"work_dir"`
}

type AnalysisResultView struct {
	AnalyserDBPath string             `json:"analyser_db_path"`
	FinalRunID     int64              `json:"final_run_id"`
	Runs           []types.RunResult  `json:"runs"`
	TrimmedCount   int64              `json:"trimmed_count"`
	TopDecisions   []TrimDecisionView `json:"top_decisions"`
	RuleFP         []RuleFPView       `json:"rule_fp"`
}

type TrimDecisionView struct {
	RunID      int64  `json:"run_id"`
	GID        int64  `json:"gid"`
	SID        int64  `json:"sid"`
	Rev        int64  `json:"rev"`
	Msg        string `json:"msg"`
	SourceFile string `json:"source_file"`
	Reasons    string `json:"reasons"`
	Functions  string `json:"functions"`
	Type       string `json:"type"`
	Committed  bool   `json:"committed"`
}

type RuleFPView struct {
	RunID                 int64   `json:"run_id"`
	GID                   int64   `json:"gid"`
	SID                   int64   `json:"sid"`
	Rev                   int64   `json:"rev"`
	Msg                   string  `json:"msg"`
	SourceFile            string  `json:"source_file"`
	AlertedFlows          int64   `json:"alerted_flows"`
	BenignAlertedFlows    int64   `json:"benign_alerted_flows"`
	MaliciousAlertedFlows int64   `json:"malicious_alerted_flows"`
	UnmatchedAlerts       int64   `json:"unmatched_alerts"`
	FPRate                float64 `json:"fp_rate"`
	Utilization           float64 `json:"utilization"`
}

type RuleListResponse struct {
	Items  []RuleItem `json:"items"`
	Total  int64      `json:"total"`
	Limit  int        `json:"limit"`
	Offset int        `json:"offset"`
}

type RuleItem struct {
	RunID      int64  `json:"run_id"`
	GID        int64  `json:"gid"`
	SID        int64  `json:"sid"`
	Rev        int64  `json:"rev"`
	Action     string `json:"action"`
	Proto      string `json:"proto"`
	Msg        string `json:"msg"`
	Classtype  string `json:"classtype"`
	Enabled    bool   `json:"enabled"`
	SourceFile string `json:"source_file"`
}

type RuleToggleRequest struct {
	GID     int64  `json:"gid"`
	SID     int64  `json:"sid"`
	RunID   int64  `json:"run_id"`
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
}

type RecommendationResponse struct {
	Items []Recommendation `json:"items"`
}

type Recommendation struct {
	GID            int64   `json:"gid"`
	SID            int64   `json:"sid"`
	Rev            int64   `json:"rev"`
	RunID          int64   `json:"run_id"`
	Msg            string  `json:"msg"`
	SourceFile     string  `json:"source_file"`
	Reason         string  `json:"reason"`
	Function       string  `json:"function,omitempty"`
	FPRate         float64 `json:"fp_rate,omitempty"`
	Utilization    float64 `json:"utilization,omitempty"`
	Enabled        *bool   `json:"enabled,omitempty"`
	Recommendation string  `json:"recommendation"`
}

type PerfTestStartRequest struct {
	Mode      string `json:"mode"`
	PcapFile  string `json:"pcap_file"`
	Interface string `json:"interface"`
	DurationS int    `json:"duration_s"`
}

type PerfTestSummary struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	StartedAt  string          `json:"started_at"`
	FinishedAt string          `json:"finished_at,omitempty"`
	Result     *PerfTestResult `json:"result,omitempty"`
}

type PerfTestResult struct {
	RunID      int64         `json:"run_id"`
	Mode       string        `json:"mode"`
	DurationMS int64         `json:"duration_ms"`
	DBPath     string        `json:"db_path"`
	Profiles   []SystemPoint `json:"profiles"`
	RuleTimeUS int64         `json:"rule_time_us"`
	AlertCount int64         `json:"alert_count"`
	RuleCount  int64         `json:"rule_count"`
}

type FileListResponse struct {
	Files []FileItem `json:"files"`
}

type FileItem struct {
	Path    string `json:"path"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}
