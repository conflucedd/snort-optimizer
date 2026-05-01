package sql

import (
	dbsql "database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"snort-optimizer/analyser/types"
)

func AnalyserDBPath(cfg types.Config) string {
	return filepath.Join(cfg.AnalyserWorkingDir, types.DefaultAnalyserDBName)
}

func EnsureAnalyserStore(path string) error {
	conn, err := dbsql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS runs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL,
	committed INTEGER NOT NULL,
	rolled_back INTEGER NOT NULL,
	factor REAL NOT NULL,
	reason TEXT,
	total_flows INTEGER NOT NULL,
	benign_flows INTEGER NOT NULL,
	malicious_flows INTEGER NOT NULL,
	alerted_flows INTEGER NOT NULL,
	false_positive_flows INTEGER NOT NULL,
	detected_malicious_flows INTEGER NOT NULL,
	missed_flows INTEGER NOT NULL,
	unmatched_alert_flows INTEGER NOT NULL,
	false_positive_rate REAL NOT NULL,
	miss_rate REAL NOT NULL,
	real_rule_time_us INTEGER NOT NULL,
	real_avg_cpu REAL NOT NULL,
	real_avg_mem_mb REAL NOT NULL,
	base_load_ms INTEGER NOT NULL,
	exp_runtime_ms INTEGER NOT NULL,
	real_runtime_ms INTEGER NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyser_runs_run_id ON runs (run_id);
CREATE TABLE IF NOT EXISTS trim_decisions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL,
	gid INTEGER NOT NULL,
	sid INTEGER NOT NULL,
	rev INTEGER NOT NULL,
	source_file TEXT,
	msg TEXT,
	reasons TEXT NOT NULL,
	functions TEXT NOT NULL,
	type TEXT NOT NULL,
	metrics TEXT,
	committed INTEGER NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trim_decisions_rule ON trim_decisions (gid, sid);
CREATE INDEX IF NOT EXISTS idx_trim_decisions_run_id ON trim_decisions (run_id);
`)
	return err
}

func InsertRunResult(path string, result types.RunResult) error {
	conn, err := dbsql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	e := result.Evaluation
	_, err = conn.Exec(`INSERT INTO runs
(run_id, committed, rolled_back, factor, reason, total_flows, benign_flows, malicious_flows,
alerted_flows, false_positive_flows, detected_malicious_flows, missed_flows, unmatched_alert_flows,
false_positive_rate, miss_rate, real_rule_time_us, real_avg_cpu, real_avg_mem_mb, base_load_ms,
exp_runtime_ms, real_runtime_ms, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		result.RunID, boolInt(result.Committed), boolInt(result.RolledBack), result.Factor, result.Reason,
		e.TotalFlows, e.BenignFlows, e.MaliciousFlows, e.AlertedFlows, e.FalsePositiveFlows,
		e.DetectedMaliciousFlows, e.MissedFlows, e.UnmatchedAlertFlows, e.FalsePositiveRate,
		e.MissRate, e.RealRuleTimeUS, e.RealAvgCPU, e.RealAvgMemMB, e.BaseLoadMS,
		e.ExpRuntimeMS, e.RealRuntimeMS, time.Now().UTC().Format(time.RFC3339Nano),
	)
	return err
}

func InsertTrimDecisions(path string, runID int64, decisions []types.TrimmedRule, committed bool) error {
	if len(decisions) == 0 {
		return nil
	}
	conn, err := dbsql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO trim_decisions
(run_id, gid, sid, rev, source_file, msg, reasons, functions, type, metrics, committed, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, d := range decisions {
		if _, err := stmt.Exec(
			runID, d.GID, d.SID, d.Rev, d.SourceFile, d.Msg, strings.Join(d.Reasons, "\n"),
			strings.Join(d.Functions, "\n"), string(d.Type), encodeMetrics(d.Metrics),
			boolInt(committed), now,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func encodeMetrics(metrics map[string]float64) string {
	if len(metrics) == 0 {
		return ""
	}
	keys := make([]string, 0, len(metrics))
	for k := range metrics {
		keys = append(keys, k)
	}
	sortStrings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%g", k, metrics[k]))
	}
	return strings.Join(parts, ",")
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
