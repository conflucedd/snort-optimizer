package alerts

import "testing"

func TestParseLineSplitsRuleID(t *testing.T) {
	line := `{ "timestamp" : "07/07-20:00:35.492196", "pkt_num" : 399, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 390, "dir" : "C2S", "src_ap" : "192.168.10.9:1035", "dst_ap" : "192.168.10.3:389", "rule" : "1:44604:1", "action" : "would_block" }`
	alert, err := ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if alert.GID != 1 || alert.SID != 44604 || alert.Rev != 1 {
		t.Fatalf("unexpected rule id split: gid=%d sid=%d rev=%d", alert.GID, alert.SID, alert.Rev)
	}
}
