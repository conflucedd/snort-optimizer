package store

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"analyser/internal/model"
)

func BuildSQLite(dbPath string, alerts []*model.AlertRecord, profilers []*model.RuleProfiler) error {
	if _, err := exec.LookPath("sqlite3"); err != nil {
		return fmt.Errorf("sqlite3 not found in PATH: %w", err)
	}

	sql := &strings.Builder{}
	sql.WriteString(`
PRAGMA journal_mode=WAL;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS rule_profiler;
CREATE TABLE alerts (
  id INTEGER PRIMARY KEY,
  rule_gid INTEGER,
  rule_sid INTEGER,
  rule_rev INTEGER,
  rule_text TEXT,
  src_ip TEXT NOT NULL,
  src_port INTEGER NOT NULL,
  dst_ip TEXT NOT NULL,
  dst_port INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  flow_timestamp TEXT NOT NULL,
  first_alert_timestamp TEXT NOT NULL,
  false_positive INTEGER NOT NULL DEFAULT 0,
  missed_detection INTEGER NOT NULL DEFAULT 0,
  alert_count INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL
);
CREATE INDEX idx_alerts_tuple_time ON alerts (src_ip, src_port, dst_ip, dst_port, protocol, flow_timestamp);
CREATE INDEX idx_alerts_rule ON alerts (rule_gid, rule_sid, rule_rev);
CREATE TABLE rule_profiler (
  id INTEGER PRIMARY KEY,
  rule_gid INTEGER,
  rule_sid INTEGER,
  rule_rev INTEGER,
  checks INTEGER,
  matches INTEGER,
  alerts INTEGER,
  no_matches INTEGER,
  total_ticks_or_time REAL,
  avg_match_time REAL,
  avg_no_match_time REAL,
  avg_check_time REAL,
  raw_line TEXT
);
CREATE INDEX idx_rule_profiler_rule ON rule_profiler (rule_gid, rule_sid, rule_rev);
BEGIN TRANSACTION;
`)
	for _, alert := range alerts {
		fmt.Fprintf(sql, "INSERT INTO alerts (id, rule_gid, rule_sid, rule_rev, rule_text, src_ip, src_port, dst_ip, dst_port, protocol, flow_timestamp, first_alert_timestamp, false_positive, missed_detection, alert_count, source) VALUES (%d, %s, %s, %s, %s, %s, %d, %s, %d, %s, %s, %s, %d, %d, %d, %s);\n",
			alert.ID, sqlNullableInt(alert.RuleGID), sqlNullableInt(alert.RuleSID), sqlNullableInt(alert.RuleREV), sqlString(alert.RuleText),
			sqlString(alert.SrcIP), alert.SrcPort, sqlString(alert.DstIP), alert.DstPort, sqlString(alert.Protocol),
			sqlString(alert.FlowTimestamp.Format(time.RFC3339Nano)), sqlString(alert.FirstAlertTimestamp.Format(time.RFC3339Nano)),
			boolToInt(alert.FalsePositive), boolToInt(alert.MissedDetection), alert.AlertCount, sqlString(alert.Source))
	}
	for _, profiler := range profilers {
		fmt.Fprintf(sql, "INSERT INTO rule_profiler (id, rule_gid, rule_sid, rule_rev, checks, matches, alerts, no_matches, total_ticks_or_time, avg_match_time, avg_no_match_time, avg_check_time, raw_line) VALUES (%d, %s, %s, %s, %d, %d, %d, %d, %.6f, %.6f, %.6f, %.6f, %s);\n",
			profiler.ID, sqlNullableInt(profiler.RuleGID), sqlNullableInt(profiler.RuleSID), sqlNullableInt(profiler.RuleREV),
			profiler.Checks, profiler.Matches, profiler.Alerts, profiler.NoMatches, profiler.TotalTimeUS, profiler.AvgMatchTime,
			profiler.AvgNoMatchTime, profiler.AvgCheckTime, sqlString(profiler.RawLine))
	}
	sql.WriteString("COMMIT;\n")

	cmd := exec.Command("sqlite3", dbPath)
	cmd.Stdin = strings.NewReader(sql.String())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sqlite3 failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func sqlString(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func sqlNullableInt(v *int64) string {
	if v == nil {
		return "NULL"
	}
	return strconv.FormatInt(*v, 10)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
