package sql

import (
	dbsql "database/sql"
	"time"
)

type ruleFPStat struct {
	AlertedFlows          int64
	BenignAlertedFlows    int64
	MaliciousAlertedFlows int64
	UnmatchedAlerts       int64
	seenFlows             map[int]struct{}
}

func RefreshRuleFP(dbPath string, runID int64, flows FlowSet) error {
	if err := EnsureRuleFP(dbPath); err != nil {
		return err
	}
	alerts, err := loadEvalAlerts(dbPath, runID)
	if err != nil {
		return err
	}
	stats := buildRuleFPStats(flows, alerts)
	rules, err := ListRulesFromDB(dbPath, runID, true)
	if err != nil {
		return err
	}
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM rule_FP WHERE run_id = ?;", runID); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO rule_FP
(run_id, gid, sid, rev, source_file, msg, alerted_flows, benign_alerted_flows, malicious_alerted_flows, unmatched_alerts, fp_rate, utilization, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, rule := range rules {
		stat := stats[ruleKey(rule.GID, rule.SID)]
		var fpRate, utilization float64
		if stat.AlertedFlows > 0 {
			fpRate = float64(stat.BenignAlertedFlows) / float64(stat.AlertedFlows)
			utilization = float64(stat.MaliciousAlertedFlows) / float64(stat.AlertedFlows)
		}
		if _, err := stmt.Exec(
			runID, rule.GID, rule.SID, rule.Rev, rule.SourceFile, rule.Msg,
			stat.AlertedFlows, stat.BenignAlertedFlows, stat.MaliciousAlertedFlows,
			stat.UnmatchedAlerts, fpRate, utilization, now,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func EnsureRuleFP(dbPath string) error {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS rule_FP (
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
	created_at TEXT NOT NULL,
	PRIMARY KEY (run_id, gid, sid)
);
CREATE INDEX IF NOT EXISTS idx_rule_FP_run_id ON rule_FP (run_id);
CREATE INDEX IF NOT EXISTS idx_rule_FP_fp_rate ON rule_FP (run_id, fp_rate);
CREATE INDEX IF NOT EXISTS idx_rule_FP_utilization ON rule_FP (run_id, utilization);
`)
	return err
}

func buildRuleFPStats(flows FlowSet, alerts []AlertForEval) map[string]ruleFPStat {
	stats := map[string]ruleFPStat{}
	for _, alert := range alerts {
		key := ruleKey(alert.GID, alert.SID)
		stat := stats[key]
		if stat.seenFlows == nil {
			stat.seenFlows = map[int]struct{}{}
		}
		flowIndex, ok := matchAlertToFlow(flows, alert)
		if !ok {
			stat.UnmatchedAlerts++
			stats[key] = stat
			continue
		}
		if _, exists := stat.seenFlows[flowIndex]; exists {
			stats[key] = stat
			continue
		}
		stat.seenFlows[flowIndex] = struct{}{}
		stat.AlertedFlows++
		flow := flows.Flows[flowIndex]
		if flow.IsBenign {
			stat.BenignAlertedFlows++
		} else if flow.IsMalicious {
			stat.MaliciousAlertedFlows++
		}
		stats[key] = stat
	}
	return stats
}
