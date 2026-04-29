package types

import "time"

type RunInfo struct {
	PID       int       `json:"pid"`
	PGID      int       `json:"pgid"`
	Running   bool      `json:"running"`
	StartTime time.Time `json:"start_time"`
}

type Status struct {
	RunInfo RunInfo `json:"run_info"`
	Config  Config  `json:"config"`
}

type DBTableCount struct {
	Total int64 `json:"total"`
	Run   int64 `json:"run"`
}

type StartupStats struct {
	RunID           int64                   `json:"run_id"`
	Mode            string                  `json:"mode"`
	SnortWorkingDir string                  `json:"snort_working_dir"`
	SnortConfigPath string                  `json:"snort_config_path"`
	SnortDBPath     string                  `json:"snort_db_path"`
	RawRulePath     string                  `json:"raw_rule_path"`
	AllRulesPath    string                  `json:"all_rules_path"`
	LoadedRuleCount int64                   `json:"loaded_rule_count"`
	TableCounts     map[string]DBTableCount `json:"table_counts"`
	NeedAlert       bool                    `json:"need_alert"`
	NeedProfiler    bool                    `json:"need_profiler"`
	NeedOutput      bool                    `json:"need_output"`
}
