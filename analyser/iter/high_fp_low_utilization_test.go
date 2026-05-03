package iter

import (
	"context"
	dbsql "database/sql"
	"path/filepath"
	"strings"
	"testing"

	"snort-optimizer/analyser/types"

	_ "modernc.org/sqlite"
)

func TestHighFPLowUtilizationSelectsHighFPRules(t *testing.T) {
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
CREATE TABLE rule_FP (
run_id INTEGER NOT NULL,
gid INTEGER NOT NULL,
sid INTEGER NOT NULL,
rev INTEGER NOT NULL,
source_file TEXT,
msg TEXT,
alerted_flows INTEGER NOT NULL,
benign_alerted_flows INTEGER NOT NULL,
malicious_alerted_flows INTEGER NOT NULL,
unmatched_alerts INTEGER NOT NULL,
fp_rate REAL NOT NULL,
utilization REAL NOT NULL,
created_at TEXT NOT NULL
);
INSERT INTO rules (run_id, sid, gid, rev, enabled, source_file, msg, raw_text) VALUES
(0, 1001, 1, 1, 1, 'snort3-protocol-dns.rules', 'bad candidate', 'alert udp any any -> any any (sid:1001;)'),
(0, 1002, 1, 1, 1, 'snort3-protocol-dns.rules', 'useful rule', 'alert udp any any -> any any (sid:1002;)'),
(0, 1003, 1, 1, 0, 'snort3-protocol-dns.rules', 'disabled', 'alert udp any any -> any any (sid:1003;)');
INSERT INTO rule_FP (run_id, gid, sid, rev, source_file, msg, alerted_flows, benign_alerted_flows, malicious_alerted_flows, unmatched_alerts, fp_rate, utilization, created_at) VALUES
(0, 1, 1001, 1, 'snort3-protocol-dns.rules', 'bad candidate', 10, 10, 0, 0, 1.0, 0.0, 'now'),
(0, 1, 1002, 1, 'snort3-protocol-dns.rules', 'useful rule', 10, 2, 8, 0, 0.2, 0.8, 'now'),
(0, 1, 1003, 1, 'snort3-protocol-dns.rules', 'disabled', 10, 10, 0, 0, 1.0, 0.0, 'now');`)
	if err != nil {
		t.Fatal(err)
	}

	got, err := HighFPLowUtilizationFunc(context.Background(), types.FunctionInput{
		ExpDBPath:   dbPath,
		SourceRunID: 0,
		Factor:      1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].SID != 1001 {
		t.Fatalf("SID = %d, want 1001", got[0].SID)
	}
	if !strings.Contains(got[0].Reason, "rule_fp_rate=1.0000") {
		t.Fatalf("reason = %q, want rule_fp_rate", got[0].Reason)
	}
	if got[0].Metrics["rule_fp_rate"] != 1 {
		t.Fatalf("rule_fp_rate metric = %v, want 1", got[0].Metrics["rule_fp_rate"])
	}
}
