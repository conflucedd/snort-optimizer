package types

type Rule struct {
	ID         int64  `json:"id"`
	RunID      int64  `json:"run_id"`
	SID        int64  `json:"sid"`
	GID        int64  `json:"gid"`
	Rev        int64  `json:"rev"`
	Action     string `json:"action"`
	Proto      string `json:"proto"`
	SrcNet     string `json:"src_net"`
	SrcPort    string `json:"src_port"`
	Direction  string `json:"direction"`
	DstNet     string `json:"dst_net"`
	DstPort    string `json:"dst_port"`
	Msg        string `json:"msg"`
	Classtype  string `json:"classtype"`
	Enabled    bool   `json:"enabled"`
	SourceFile string `json:"source_file"`
	RawText    string `json:"raw_text"`
}
