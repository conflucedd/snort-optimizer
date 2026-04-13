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
