package types

type ProfilerMetric struct {
	ID         int64   `json:"id,omitempty"`
	RunID      string  `json:"run_id"`
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
