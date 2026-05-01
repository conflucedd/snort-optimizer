package sql

import (
	dbsql "database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshRuleFPUsesRunIDAndUniqueRuleFlows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snort.sqlite")
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE rules (
run_id INTEGER NOT NULL,
sid INTEGER NOT NULL,
gid INTEGER NOT NULL,
rev INTEGER,
enabled INTEGER NOT NULL,
source_file TEXT,
msg TEXT,
raw_text TEXT NOT NULL
);
CREATE TABLE alerts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
run_id INTEGER NOT NULL,
timestamp TEXT,
proto TEXT,
src_ap TEXT,
dst_ap TEXT,
gid INTEGER,
sid INTEGER,
rev INTEGER
);
INSERT INTO rules (run_id, sid, gid, rev, enabled, source_file, msg, raw_text) VALUES
(7, 1001, 1, 1, 1, 'a.rules', 'benign rule', 'alert tcp any any -> any any (sid:1001;)'),
(7, 1002, 1, 1, 1, 'b.rules', 'attack rule', 'alert tcp any any -> any any (sid:1002;)'),
(7, 1003, 1, 1, 1, 'c.rules', 'unused rule', 'alert tcp any any -> any any (sid:1003;)'),
(8, 1001, 1, 1, 1, 'a.rules', 'other run', 'alert tcp any any -> any any (sid:1001;)');
INSERT INTO alerts (run_id, timestamp, proto, src_ap, dst_ap, gid, sid, rev) VALUES
(7, '07/04-10:00:10.000000', 'TCP', '10.0.0.1:12345', '10.0.0.2:80', 1, 1001, 1),
(7, '07/04-10:00:20.000000', 'TCP', '10.0.0.1:12345', '10.0.0.2:80', 1, 1001, 1),
(7, '07/04-10:02:05.000000', 'TCP', '10.0.0.4:443', '10.0.0.3:23456', 1, 1002, 1),
(8, '07/04-10:00:10.000000', 'TCP', '10.0.0.1:12345', '10.0.0.2:80', 1, 1001, 1);`)
	if err != nil {
		t.Fatal(err)
	}

	flows := testFlowSet()
	if err := RefreshRuleFP(dbPath, 7, flows); err != nil {
		t.Fatal(err)
	}

	var alerted, benign, malicious int64
	var fpRate, utilization float64
	if err := conn.QueryRow(`SELECT alerted_flows, benign_alerted_flows, malicious_alerted_flows, fp_rate, utilization
FROM rule_FP WHERE run_id = 7 AND gid = 1 AND sid = 1001;`).Scan(&alerted, &benign, &malicious, &fpRate, &utilization); err != nil {
		t.Fatal(err)
	}
	if alerted != 1 || benign != 1 || malicious != 0 || fpRate != 1 || utilization != 0 {
		t.Fatalf("rule 1001 stats = alerted:%d benign:%d malicious:%d fp:%f util:%f", alerted, benign, malicious, fpRate, utilization)
	}

	if err := conn.QueryRow(`SELECT alerted_flows, benign_alerted_flows, malicious_alerted_flows, fp_rate, utilization
FROM rule_FP WHERE run_id = 7 AND gid = 1 AND sid = 1002;`).Scan(&alerted, &benign, &malicious, &fpRate, &utilization); err != nil {
		t.Fatal(err)
	}
	if alerted != 1 || benign != 0 || malicious != 1 || fpRate != 0 || utilization != 1 {
		t.Fatalf("rule 1002 stats = alerted:%d benign:%d malicious:%d fp:%f util:%f", alerted, benign, malicious, fpRate, utilization)
	}

	var count int64
	if err := conn.QueryRow(`SELECT count(*) FROM rule_FP WHERE run_id = 8;`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("run 8 rule_FP rows = %d, want 0", count)
	}
}

func testFlowSet() FlowSet {
	base := time.Date(2017, 7, 4, 10, 0, 0, 0, time.Local)
	flows := FlowSet{
		Flows: []FlowRecord{
			{
				ID:       "1",
				SrcIP:    "10.0.0.1",
				SrcPort:  12345,
				DstIP:    "10.0.0.2",
				DstPort:  80,
				Protocol: "TCP",
				Start:    base,
				Duration: time.Minute,
				Label:    "BENIGN",
				IsBenign: true,
			},
			{
				ID:          "2",
				SrcIP:       "10.0.0.3",
				SrcPort:     23456,
				DstIP:       "10.0.0.4",
				DstPort:     443,
				Protocol:    "TCP",
				Start:       base.Add(2 * time.Minute),
				Duration:    time.Minute,
				Label:       "ATTACK",
				IsMalicious: true,
			},
		},
		index: map[string][]int{},
		year:  2017,
	}
	for i, flow := range flows.Flows {
		flows.index[tupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)] = append(flows.index[tupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)], i)
		flows.index[tupleKey(flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort, flow.Protocol)] = append(flows.index[tupleKey(flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort, flow.Protocol)], i)
	}
	return flows
}
