package types

type ProfilerMetric struct {
	ID         int64   `json:"id,omitempty"`
	RunID      int64   `json:"run_id"`
	Section    string  `json:"section"`
	Module     string  `json:"module"`
	Metric     string  `json:"metric"`
	Value      float64 `json:"value"`
	Percent    float64 `json:"percent,omitempty"`
	Unit       string  `json:"unit,omitempty"`
	RawLine    string  `json:"raw_line"`
	SourceFile string  `json:"source_file,omitempty"`
	CreatedAt  string  `json:"created_at,omitempty"`
}

type RuleProfilerMetric struct {
	ID          int64   `json:"id,omitempty"`
	RunID       int64   `json:"run_id"`
	GID         int64   `json:"gid"`
	SID         int64   `json:"sid"`
	Rev         int64   `json:"rev"`
	Checks      int64   `json:"checks"`
	Matches     int64   `json:"matches"`
	Alerts      int64   `json:"alerts"`
	TimeUS      int64   `json:"time_us"`
	AvgCheck    float64 `json:"avg_check"`
	AvgMatch    float64 `json:"avg_match"`
	AvgNonMatch float64 `json:"avg_non_match"`
	Timeouts    int64   `json:"timeouts"`
	Suspends    int64   `json:"suspends"`
	RuleTimePct float64 `json:"rule_time_pct"`
	RawLine     string  `json:"raw_line"`
	SourceFile  string  `json:"source_file,omitempty"`
	CreatedAt   string  `json:"created_at,omitempty"`
}

type ModuleProfileMetric struct {
	ID         int64   `json:"id,omitempty"`
	RunID      int64   `json:"run_id"`
	Rank       int64   `json:"rank"`
	Module     string  `json:"module"`
	Layer      string  `json:"layer"`
	Checks     int64   `json:"checks"`
	TimeUS     int64   `json:"time_us"`
	AvgCheck   float64 `json:"avg_check"`
	CallerPct  float64 `json:"caller_pct"`
	TotalPct   float64 `json:"total_pct"`
	RawLine    string  `json:"raw_line"`
	SourceFile string  `json:"source_file,omitempty"`
	CreatedAt  string  `json:"created_at,omitempty"`
}

type SystemProfile struct {
	ID        int64   `json:"id,omitempty"`
	RunID     int64   `json:"run_id"`
	AvgCPU    float64 `json:"avg_cpu"`
	AvgMemMB  float64 `json:"avg_mem_mb"`
	Samples   int64   `json:"samples"`
	CreatedAt string  `json:"created_at,omitempty"`
}
