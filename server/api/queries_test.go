package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyRulesBetweenDBsUsesAbsoluteAttachPath(t *testing.T) {
	dir := t.TempDir()
	sourceDB := filepath.Join(dir, "source.sqlite")
	targetDB := filepath.Join(dir, "nested", "target.sqlite")
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	sourceRel, err := filepath.Rel(cwd, sourceDB)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := sqlOpen(sourceDB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(`
CREATE TABLE rules (
	run_id INTEGER NOT NULL DEFAULT 0,
	sid INTEGER NOT NULL,
	gid INTEGER NOT NULL DEFAULT 1,
	rev INTEGER,
	action TEXT,
	proto TEXT,
	src_net TEXT,
	src_port TEXT,
	direction TEXT,
	dst_net TEXT,
	dst_port TEXT,
	msg TEXT,
	classtype TEXT,
	enabled INTEGER NOT NULL DEFAULT 1,
	source_file TEXT,
	raw_text TEXT NOT NULL,
	created_at TEXT NOT NULL,
	PRIMARY KEY (run_id, gid, sid)
);
INSERT INTO rules (run_id, sid, gid, rev, action, proto, msg, classtype, enabled, source_file, raw_text, created_at)
VALUES (0, 1001, 1, 1, 'alert', 'tcp', 'test rule', 'attempted-admin', 1, 'test.rules', 'alert tcp any any -> any any (sid:1001;)', datetime('now'));
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if err := copyRulesBetweenDBs(sourceRel, targetDB, 0, 42); err != nil {
		t.Fatal(err)
	}

	target, err := sqlOpen(targetDB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var count int64
	if err := target.QueryRow("SELECT count(*) FROM rules WHERE run_id = 42;").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("copied %d rules, want 1", count)
	}
}

func TestEnrichAnalyserRunProfilerMetricsUsesProfilerMetricSources(t *testing.T) {
	workDir := t.TempDir()
	createProfilerMetricsDB(t, filepath.Join(workDir, "real", "snort.sqlite"), 3, map[string]float64{
		"seconds":   304.5,
		"pkts/sec":  38446,
		"Mbits/sec": 196,
	})
	createProfilerMetricsDB(t, filepath.Join(workDir, "exp", "snort.sqlite"), 3, map[string]float64{
		"seconds": 330.450117,
	})
	createProfilerMetricsDB(t, filepath.Join(workDir, "base", "snort.sqlite"), 3, map[string]float64{
		"seconds": 0.026462,
	})

	runs := []AnalysisRunView{{RunID: 3}}
	enrichAnalyserRunProfilerMetrics(workDir, runs)

	eval := runs[0].Evaluation
	if eval.RealThroughputPPS != 38446 {
		t.Fatalf("RealThroughputPPS = %g, want 38446", eval.RealThroughputPPS)
	}
	wantRuntime := 330.450117 - 0.026462
	if eval.ProfileRuntimeSeconds != wantRuntime {
		t.Fatalf("ProfileRuntimeSeconds = %.6f, want %.6f", eval.ProfileRuntimeSeconds, wantRuntime)
	}
	if eval.ExpSeconds != 330.450117 || eval.BaseSeconds != 0.026462 {
		t.Fatalf("Exp/Base seconds = %.6f/%.6f", eval.ExpSeconds, eval.BaseSeconds)
	}
}

func createProfilerMetricsDB(t *testing.T, path string, runID int64, metrics map[string]float64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	conn, err := sqlOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE profiler_metrics (
id INTEGER PRIMARY KEY AUTOINCREMENT,
run_id INTEGER NOT NULL DEFAULT 0,
section TEXT NOT NULL,
module TEXT NOT NULL,
metric TEXT NOT NULL,
value REAL NOT NULL,
percent REAL,
unit TEXT,
raw_line TEXT NOT NULL,
source_file TEXT,
created_at TEXT NOT NULL
);`)
	if err != nil {
		t.Fatal(err)
	}
	for metric, value := range metrics {
		if _, err := conn.Exec(`INSERT INTO profiler_metrics
(run_id, section, module, metric, value, raw_line, created_at)
VALUES (?, 'summary', 'timing', ?, ?, '', datetime('now'));`, runID, metric, value); err != nil {
			t.Fatal(err)
		}
	}
}
