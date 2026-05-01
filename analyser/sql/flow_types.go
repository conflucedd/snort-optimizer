package sql

import "time"

type FlowRecord struct {
	ID          string
	SrcIP       string
	SrcPort     int
	DstIP       string
	DstPort     int
	Protocol    string
	Start       time.Time
	Duration    time.Duration
	Label       string
	IsBenign    bool
	IsMalicious bool
}

type FlowSet struct {
	Flows []FlowRecord
	index map[string][]int
	year  int
}

type AlertForEval struct {
	ID        int64
	Timestamp string
	Proto     string
	SrcAP     string
	DstAP     string
	GID       int64
	SID       int64
	Rev       int64
}

type matchedAlert struct {
	Alert AlertForEval
	Flow  int
}
