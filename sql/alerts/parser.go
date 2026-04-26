package alerts

import (
	"encoding/json"
	"strconv"
	"strings"

	"snort-optimizer/types"
)

type rawAlert struct {
	Timestamp string `json:"timestamp"`
	PktNum    int64  `json:"pkt_num"`
	Proto     string `json:"proto"`
	PktGen    string `json:"pkt_gen"`
	PktLen    int64  `json:"pkt_len"`
	Dir       string `json:"dir"`
	SrcAP     string `json:"src_ap"`
	DstAP     string `json:"dst_ap"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
}

func ParseLine(line string) (types.Alert, error) {
	rawJSON := strings.TrimSpace(line)
	var raw rawAlert
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return types.Alert{}, err
	}
	gid, sid, rev := parseRuleID(raw.Rule)
	return types.Alert{
		Timestamp: raw.Timestamp,
		PktNum:    raw.PktNum,
		Proto:     raw.Proto,
		PktGen:    raw.PktGen,
		PktLen:    raw.PktLen,
		Dir:       raw.Dir,
		SrcAP:     raw.SrcAP,
		DstAP:     raw.DstAP,
		GID:       gid,
		SID:       sid,
		Rev:       rev,
		Rule:      raw.Rule,
		Action:    raw.Action,
		RawJSON:   rawJSON,
	}, nil
}

func parseRuleID(rule string) (int64, int64, int64) {
	parts := strings.Split(rule, ":")
	if len(parts) != 3 {
		return 0, 0, 0
	}
	gid, _ := strconv.ParseInt(parts[0], 10, 64)
	sid, _ := strconv.ParseInt(parts[1], 10, 64)
	rev, _ := strconv.ParseInt(parts[2], 10, 64)
	return gid, sid, rev
}
