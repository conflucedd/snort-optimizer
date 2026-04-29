package types

type Alert struct {
	ID        int64  `json:"id,omitempty"`
	RunID     int64  `json:"run_id"`
	Timestamp string `json:"timestamp"`
	PktNum    int64  `json:"pkt_num"`
	Proto     string `json:"proto"`
	PktGen    string `json:"pkt_gen"`
	PktLen    int64  `json:"pkt_len"`
	Dir       string `json:"dir"`
	SrcAP     string `json:"src_ap"`
	DstAP     string `json:"dst_ap"`
	GID       int64  `json:"gid"`
	SID       int64  `json:"sid"`
	Rev       int64  `json:"rev"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
	RawJSON   string `json:"raw_json"`
	CreatedAt string `json:"created_at,omitempty"`
}
