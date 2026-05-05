package api

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"snort-optimizer/analyser/types"
)

type alertQuery struct {
	RunID  int64
	Limit  int
	Offset int
	GID    int64
	SID    int64
	Proto  string
	Action string
	Search string
}

type ruleQuery struct {
	RunID     int64
	Limit     int
	Offset    int
	GID       int64
	SID       int64
	Search    string
	Classtype string
	Enabled   *bool
}

func queryAlerts(dbPath string, q alertQuery) (AlertListResponse, error) {
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return AlertListResponse{Items: []AlertItem{}, Summary: map[string]any{}, Limit: q.Limit, Offset: q.Offset}, nil
		}
		return AlertListResponse{}, err
	}
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return AlertListResponse{}, err
	}
	defer conn.Close()
	where, args := alertWhere(q)
	total, err := countRows(conn, "alerts", where, args)
	if err != nil {
		return AlertListResponse{}, err
	}
	query := `SELECT id, run_id, timestamp, proto, src_ap, dst_ap, gid, sid, rev, rule, action, created_at
FROM alerts WHERE ` + where + ` ORDER BY id DESC LIMIT ? OFFSET ?;`
	args = append(args, q.Limit, q.Offset)
	rows, err := conn.Query(query, args...)
	if err != nil {
		return AlertListResponse{}, err
	}
	defer rows.Close()
	items := []AlertItem{}
	for rows.Next() {
		var item AlertItem
		if err := rows.Scan(&item.ID, &item.RunID, &item.Timestamp, &item.Proto, &item.SrcAP, &item.DstAP,
			&item.GID, &item.SID, &item.Rev, &item.Rule, &item.Action, &item.CreatedAt); err != nil {
			return AlertListResponse{}, err
		}
		items = append(items, item)
	}
	summary, _ := queryAlertSummary(dbPath, q.RunID)
	return AlertListResponse{Items: items, Total: total, Summary: summary, Limit: q.Limit, Offset: q.Offset}, rows.Err()
}

func alertWhere(q alertQuery) (string, []any) {
	where := []string{"run_id = ?"}
	args := []any{q.RunID}
	if q.GID > 0 {
		where = append(where, "gid = ?")
		args = append(args, q.GID)
	}
	if q.SID > 0 {
		where = append(where, "sid = ?")
		args = append(args, q.SID)
	}
	if q.Proto != "" {
		where = append(where, "proto = ?")
		args = append(args, q.Proto)
	}
	if q.Action != "" {
		where = append(where, "action = ?")
		args = append(args, q.Action)
	}
	if q.Search != "" {
		where = append(where, "(rule LIKE ? OR src_ap LIKE ? OR dst_ap LIKE ?)")
		like := "%" + q.Search + "%"
		args = append(args, like, like, like)
	}
	return strings.Join(where, " AND "), args
}

func queryAlertSummary(dbPath string, runID int64) (map[string]any, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return map[string]any{}, nil
	}
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	out := map[string]any{}
	var total int64
	_ = conn.QueryRow("SELECT count(*) FROM alerts WHERE run_id = ?;", runID).Scan(&total)
	out["total"] = total
	out["by_action"] = groupedCounts(conn, "SELECT COALESCE(action, ''), count(*) FROM alerts WHERE run_id = ? GROUP BY action ORDER BY count(*) DESC LIMIT 12;", runID)
	out["by_proto"] = groupedCounts(conn, "SELECT COALESCE(proto, ''), count(*) FROM alerts WHERE run_id = ? GROUP BY proto ORDER BY count(*) DESC LIMIT 12;", runID)
	out["top_rules"] = groupedRuleCounts(conn, runID)
	return out, nil
}

func queryRules(dbPath string, q ruleQuery) (RuleListResponse, error) {
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return RuleListResponse{Items: []RuleItem{}, Limit: q.Limit, Offset: q.Offset}, nil
		}
		return RuleListResponse{}, err
	}
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return RuleListResponse{}, err
	}
	defer conn.Close()
	where, args := ruleWhere(q)
	total, err := countRows(conn, "rules", where, args)
	if err != nil {
		return RuleListResponse{}, err
	}
	query := `SELECT run_id, gid, sid, rev, action, proto, msg, classtype, enabled, source_file
FROM rules WHERE ` + where + ` ORDER BY gid, sid LIMIT ? OFFSET ?;`
	args = append(args, q.Limit, q.Offset)
	rows, err := conn.Query(query, args...)
	if err != nil {
		return RuleListResponse{}, err
	}
	defer rows.Close()
	items := []RuleItem{}
	for rows.Next() {
		var item RuleItem
		var enabled int
		if err := rows.Scan(&item.RunID, &item.GID, &item.SID, &item.Rev, &item.Action, &item.Proto,
			&item.Msg, &item.Classtype, &enabled, &item.SourceFile); err != nil {
			return RuleListResponse{}, err
		}
		item.Enabled = enabled != 0
		items = append(items, item)
	}
	return RuleListResponse{Items: items, Total: total, Limit: q.Limit, Offset: q.Offset}, rows.Err()
}

func ruleWhere(q ruleQuery) (string, []any) {
	where := []string{"run_id = ?"}
	args := []any{q.RunID}
	if q.GID > 0 {
		where = append(where, "gid = ?")
		args = append(args, q.GID)
	}
	if q.SID > 0 {
		where = append(where, "sid = ?")
		args = append(args, q.SID)
	}
	if q.Search != "" {
		where = append(where, "(msg LIKE ? OR source_file LIKE ? OR raw_text LIKE ?)")
		like := "%" + q.Search + "%"
		args = append(args, like, like, like)
	}
	if q.Classtype != "" {
		where = append(where, "classtype = ?")
		args = append(args, q.Classtype)
	}
	if q.Enabled != nil {
		value := 0
		if *q.Enabled {
			value = 1
		}
		where = append(where, "enabled = ?")
		args = append(args, value)
	}
	return strings.Join(where, " AND "), args
}

func querySystemProfiles(dbPath string, runID int64, limit int) ([]SystemPoint, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return []SystemPoint{}, nil
	}
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT run_id, avg_cpu, avg_mem_mb, fp, fn, samples, created_at
FROM system_profiles WHERE run_id = ? ORDER BY id DESC LIMIT ?;`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SystemPoint{}
	for rows.Next() {
		var point SystemPoint
		if err := rows.Scan(&point.RunID, &point.AvgCPU, &point.AvgMemMB, &point.FP, &point.FN, &point.Samples, &point.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, point)
	}
	reverseSystemPoints(out)
	return out, rows.Err()
}

func loadAnalysisResult(workDir string, decisionLimit, fpLimit int) (*AnalysisResultView, error) {
	dbPath := filepath.Join(workDir, "analyser.db")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	runs, err := queryAnalyserRuns(conn)
	if err != nil {
		return nil, err
	}
	finalRunID := int64(0)
	for _, run := range runs {
		if run.Committed && run.RunID >= finalRunID {
			finalRunID = run.RunID
		}
	}
	var trimmedCount int64
	_ = conn.QueryRow("SELECT count(*) FROM trim_decisions WHERE committed = 1;").Scan(&trimmedCount)
	decisions, _ := queryTrimDecisions(conn, decisionLimit)
	ruleFP, _ := queryRuleFP(filepath.Join(workDir, "exp", "snort.sqlite"), finalRunID, fpLimit)
	return &AnalysisResultView{
		AnalyserDBPath: dbPath,
		FinalRunID:     finalRunID,
		Runs:           runs,
		TrimmedCount:   trimmedCount,
		TopDecisions:   decisions,
		RuleFP:         ruleFP,
	}, nil
}

func queryAnalyserRuns(conn *sql.DB) ([]types.RunResult, error) {
	rows, err := conn.Query(`SELECT run_id, committed, rolled_back, factor, COALESCE(reason, ''),
total_flows, benign_flows, malicious_flows, alerted_flows, false_positive_flows,
detected_malicious_flows, missed_flows, unmatched_alert_flows, false_positive_rate, miss_rate,
real_rule_time_us, real_avg_cpu, real_avg_mem_mb, base_load_ms, exp_runtime_ms, real_runtime_ms
FROM runs ORDER BY id;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []types.RunResult{}
	for rows.Next() {
		var result types.RunResult
		var committed, rolledBack int
		e := &result.Evaluation
		if err := rows.Scan(&result.RunID, &committed, &rolledBack, &result.Factor, &result.Reason,
			&e.TotalFlows, &e.BenignFlows, &e.MaliciousFlows, &e.AlertedFlows, &e.FalsePositiveFlows,
			&e.DetectedMaliciousFlows, &e.MissedFlows, &e.UnmatchedAlertFlows, &e.FalsePositiveRate, &e.MissRate,
			&e.RealRuleTimeUS, &e.RealAvgCPU, &e.RealAvgMemMB, &e.BaseLoadMS, &e.ExpRuntimeMS, &e.RealRuntimeMS); err != nil {
			return nil, err
		}
		result.Committed = committed != 0
		result.RolledBack = rolledBack != 0
		e.RunID = result.RunID
		out = append(out, result)
	}
	return out, rows.Err()
}

func queryTrimDecisions(conn *sql.DB, limit int) ([]TrimDecisionView, error) {
	rows, err := conn.Query(`SELECT run_id, gid, sid, rev, COALESCE(source_file, ''), COALESCE(msg, ''),
reasons, functions, type, committed
FROM trim_decisions ORDER BY committed DESC, run_id DESC, id DESC LIMIT ?;`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrimDecisionView{}
	for rows.Next() {
		var item TrimDecisionView
		var committed int
		if err := rows.Scan(&item.RunID, &item.GID, &item.SID, &item.Rev, &item.SourceFile, &item.Msg,
			&item.Reasons, &item.Functions, &item.Type, &committed); err != nil {
			return nil, err
		}
		item.Committed = committed != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

func queryRuleFP(dbPath string, runID int64, limit int) ([]RuleFPView, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return []RuleFPView{}, nil
	}
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT run_id, gid, sid, rev, COALESCE(msg, ''), COALESCE(source_file, ''),
alerted_flows, benign_alerted_flows, malicious_alerted_flows, unmatched_alerts, fp_rate, utilization
FROM rule_FP WHERE run_id = ? AND alerted_flows > 0
ORDER BY fp_rate DESC, alerted_flows DESC LIMIT ?;`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleFPView{}
	for rows.Next() {
		var item RuleFPView
		if err := rows.Scan(&item.RunID, &item.GID, &item.SID, &item.Rev, &item.Msg, &item.SourceFile,
			&item.AlertedFlows, &item.BenignAlertedFlows, &item.MaliciousAlertedFlows, &item.UnmatchedAlerts,
			&item.FPRate, &item.Utilization); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func queryRecommendations(awd, prodDB string, prodRunID int64, limit int) ([]Recommendation, error) {
	result, err := loadAnalysisResult(awd, limit, limit)
	if err != nil {
		if os.IsNotExist(err) {
			return []Recommendation{}, nil
		}
		return nil, err
	}
	enabled := map[string]*bool{}
	if _, err := os.Stat(prodDB); err == nil {
		conn, err := sqlOpen(prodDB)
		if err == nil {
			rows, err := conn.Query("SELECT gid, sid, enabled FROM rules WHERE run_id = ?;", prodRunID)
			if err == nil {
				for rows.Next() {
					var gid, sid int64
					var value int
					if rows.Scan(&gid, &sid, &value) == nil {
						v := value != 0
						enabled[ruleKey(gid, sid)] = &v
					}
				}
				rows.Close()
			}
			conn.Close()
		}
	}
	items := []Recommendation{}
	for _, d := range result.TopDecisions {
		if !d.Committed {
			continue
		}
		item := Recommendation{
			GID: d.GID, SID: d.SID, Rev: d.Rev, RunID: d.RunID, Msg: d.Msg, SourceFile: d.SourceFile,
			Reason: d.Reasons, Function: d.Functions, Recommendation: "建议禁用",
			Enabled: enabled[ruleKey(d.GID, d.SID)],
		}
		items = append(items, item)
	}
	for _, fp := range result.RuleFP {
		if len(items) >= limit {
			break
		}
		if fp.FPRate < 0.8 && fp.Utilization > 0.05 {
			continue
		}
		items = append(items, Recommendation{
			GID: fp.GID, SID: fp.SID, Rev: fp.Rev, RunID: fp.RunID, Msg: fp.Msg, SourceFile: fp.SourceFile,
			Reason: fmt.Sprintf("fp_rate %.3f, utilization %.3f, alerted_flows %d", fp.FPRate, fp.Utilization, fp.AlertedFlows),
			FPRate: fp.FPRate, Utilization: fp.Utilization, Recommendation: "建议复核后禁用",
			Enabled: enabled[ruleKey(fp.GID, fp.SID)],
		})
	}
	if len(items) > limit {
		return items[:limit], nil
	}
	return items, nil
}

func copyRulesBetweenDBs(sourceDB, targetDB string, sourceRunID, targetRunID int64) error {
	sourceAbs, err := filepath.Abs(sourceDB)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(targetDB)
	if err != nil {
		return err
	}
	if _, err := os.Stat(sourceAbs); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetAbs), 0755); err != nil {
		return err
	}
	conn, err := sqlOpen(targetAbs)
	if err != nil {
		return err
	}
	defer conn.Close()
	attach := "srcdb"
	if _, err := conn.Exec("ATTACH DATABASE " + quote(sourceAbs) + " AS " + attach + ";"); err != nil {
		return err
	}
	defer conn.Exec("DETACH DATABASE " + attach + ";")
	if _, err := conn.Exec(`
CREATE TABLE IF NOT EXISTS rules (
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
DELETE FROM rules WHERE run_id = ?;`, targetRunID); err != nil {
		return err
	}
	if _, err := conn.Exec(`
INSERT INTO rules
(run_id, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, created_at)
SELECT ?, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, datetime('now')
FROM srcdb.rules WHERE run_id = ?;`, targetRunID, sourceRunID); err != nil {
		return err
	}
	var copied int64
	if err := conn.QueryRow("SELECT count(*) FROM rules WHERE run_id = ?;", targetRunID).Scan(&copied); err != nil {
		return err
	}
	if copied == 0 {
		return fmt.Errorf("source db %s has no rules for run-id %d", sourceAbs, sourceRunID)
	}
	return nil
}

func countRows(conn *sql.DB, table, where string, args []any) (int64, error) {
	var total int64
	err := conn.QueryRow("SELECT count(*) FROM "+table+" WHERE "+where+";", args...).Scan(&total)
	return total, err
}

func groupedCounts(conn *sql.DB, query string, args ...any) []map[string]any {
	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var key string
		var count int64
		if rows.Scan(&key, &count) == nil {
			out = append(out, map[string]any{"key": key, "count": count})
		}
	}
	return out
}

func groupedRuleCounts(conn *sql.DB, runID int64) []map[string]any {
	rows, err := conn.Query(`SELECT gid, sid, COALESCE(rule, ''), count(*) AS c
FROM alerts WHERE run_id = ? GROUP BY gid, sid, rule ORDER BY c DESC LIMIT 10;`, runID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var gid, sid, count int64
		var rule string
		if rows.Scan(&gid, &sid, &rule, &count) == nil {
			out = append(out, map[string]any{"gid": gid, "sid": sid, "rule": rule, "count": count})
		}
	}
	return out
}

func reverseSystemPoints(points []SystemPoint) {
	for i, j := 0, len(points)-1; i < j; i, j = i+1, j-1 {
		points[i], points[j] = points[j], points[i]
	}
}

func ruleKey(gid, sid int64) string {
	return fmt.Sprintf("%d:%d", gid, sid)
}
