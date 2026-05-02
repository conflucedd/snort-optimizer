package types

import (
	"context"
	"time"
)

const (
	DefaultMaxRound       = 4
	DefaultInitialFactor  = 0.8
	DefaultPollInterval   = 500 * time.Millisecond
	DefaultMissIncrease   = 0.01
	DefaultFPIncrease     = 0.02
	DefaultAnalyserDBName = "analyser.db"
)

type FunctionType string

const (
	SAFE FunctionType = "SAFE"
	ITER FunctionType = "ITER"
)

type Config struct {
	Pcap1               string
	DB1                 string
	Pcap2               string
	AnalyserWorkingDir  string
	SnortConfig         string
	LuaOverrides        []string
	RawSnortSQLite      string
	RawRulePath         string
	EmptyPcap           string
	MaxRound            int
	InitialFactor       float64
	MaxMissRateIncrease float64
	MaxFPRateIncrease   float64
	PreserveWorkDBs     bool
	PollInterval        time.Duration
}

type FunctionInput struct {
	ExpDBPath   string
	RealDBPath  string
	BaseDBPath  string
	Round       int
	SourceRunID int64
	Factor      float64
}

type TrimFunction func(context.Context, FunctionInput) ([]TrimDecision, error)

type RegisteredFunction struct {
	Name string
	Type FunctionType
	Fn   TrimFunction
}

type RuleRef struct {
	GID int64 `json:"gid"`
	SID int64 `json:"sid"`
	Rev int64 `json:"rev"`
}

type TrimDecision struct {
	RuleRef
	SourceFile string             `json:"source_file,omitempty"`
	Msg        string             `json:"msg,omitempty"`
	Reason     string             `json:"reason"`
	Function   string             `json:"function,omitempty"`
	Type       FunctionType       `json:"type,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
}

type TrimmedRule struct {
	RuleRef
	SourceFile string             `json:"source_file,omitempty"`
	Msg        string             `json:"msg,omitempty"`
	Reasons    []string           `json:"reasons"`
	Functions  []string           `json:"functions"`
	RunID      int64              `json:"run_id"`
	Type       FunctionType       `json:"type"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
}

type Evaluation struct {
	RunID                  int64   `json:"run_id"`
	TotalFlows             int64   `json:"total_flows"`
	BenignFlows            int64   `json:"benign_flows"`
	MaliciousFlows         int64   `json:"malicious_flows"`
	AlertedFlows           int64   `json:"alerted_flows"`
	FalsePositiveFlows     int64   `json:"false_positive_flows"`
	DetectedMaliciousFlows int64   `json:"detected_malicious_flows"`
	MissedFlows            int64   `json:"missed_flows"`
	UnmatchedAlertFlows    int64   `json:"unmatched_alert_flows"`
	FalsePositiveRate      float64 `json:"false_positive_rate"`
	MissRate               float64 `json:"miss_rate"`
	RealRuleTimeUS         int64   `json:"real_rule_time_us"`
	RealAvgCPU             float64 `json:"real_avg_cpu"`
	RealAvgMemMB           float64 `json:"real_avg_mem_mb"`
	BaseLoadMS             int64   `json:"base_load_ms"`
	ExpRuntimeMS           int64   `json:"exp_runtime_ms"`
	RealRuntimeMS          int64   `json:"real_runtime_ms"`
}

type RunResult struct {
	RunID      int64      `json:"run_id"`
	Committed  bool       `json:"committed"`
	RolledBack bool       `json:"rolled_back"`
	Factor     float64    `json:"factor"`
	Reason     string     `json:"reason,omitempty"`
	Evaluation Evaluation `json:"evaluation"`
}

type Result struct {
	AnalyserDBPath string        `json:"analyser_db_path"`
	FinalRunID     int64         `json:"final_run_id"`
	TrimmedRules   []TrimmedRule `json:"trimmed_rules"`
	Runs           []RunResult   `json:"runs"`
}
