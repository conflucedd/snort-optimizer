package model

import "time"

type AlertRecord struct {
	ID                  int64
	RuleGID             *int64
	RuleSID             *int64
	RuleREV             *int64
	RuleText            string
	SrcIP               string
	SrcPort             int
	DstIP               string
	DstPort             int
	Protocol            string
	FlowTimestamp       time.Time
	FirstAlertTimestamp time.Time
	FalsePositive       bool
	MissedDetection     bool
	AlertCount          int
	Source              string
}

type RuleProfiler struct {
	ID             int64
	RuleGID        *int64
	RuleSID        *int64
	RuleREV        *int64
	Checks         int64
	Matches        int64
	Alerts         int64
	NoMatches      int64
	TotalTimeUS    float64
	AvgMatchTime   float64
	AvgNoMatchTime float64
	AvgCheckTime   float64
	RawLine        string
}

type CSVFlow struct {
	Key          string
	SrcIP        string
	SrcPort      int
	DstIP        string
	DstPort      int
	Protocol     string
	Start        time.Time
	Duration     time.Duration
	Label        string
	IsBenign     bool
	IsMalicious  bool
	OriginalTime string
}

type RuleMetrics struct {
	GID                 int64    `json:"gid"`
	SID                 int64    `json:"sid"`
	REV                 int64    `json:"rev"`
	HitCount            int64    `json:"hit_count"`
	PacketAlertCount    int64    `json:"packet_alert_count"`
	FalsePositiveCount  int64    `json:"false_positive_count"`
	FalsePositiveRate   float64  `json:"false_positive_rate"`
	CheckCount          int64    `json:"check_count,omitempty"`
	MatchCount          int64    `json:"match_count,omitempty"`
	ProfilerAlertCount  int64    `json:"profiler_alert_count,omitempty"`
	TotalTimeUS         float64  `json:"total_time_us,omitempty"`
	AvgMatchTime        float64  `json:"avg_match_time,omitempty"`
	AvgNoMatchTime      float64  `json:"avg_no_match_time,omitempty"`
	AvgCheckTime        float64  `json:"avg_check_time,omitempty"`
	OverlapRatio        *float64 `json:"overlap_ratio,omitempty"`
	OverlapWith         string   `json:"overlap_with,omitempty"`
	ServiceMismatchHint string   `json:"service_mismatch_hint,omitempty"`
}

type CandidateRule struct {
	GID     int64                  `json:"gid"`
	SID     int64                  `json:"sid"`
	REV     int64                  `json:"rev"`
	Reasons []string               `json:"reasons"`
	Metrics map[string]interface{} `json:"metrics"`
}

type AnalysisStats struct {
	TotalAlertFlows            int64
	FalsePositiveAlertFlows    int64
	OverallFalsePositiveRate   float64
	TotalMaliciousCSVFlows     int64
	MissedMaliciousCSVFlows    int64
	OverallMissedDetectionRate float64
	MissedByLabel              map[string]int64
}
