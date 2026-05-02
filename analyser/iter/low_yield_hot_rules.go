package iter

import (
	"context"
	"database/sql"
	"fmt"

	"snort-optimizer/analyser/types"
)

type lowYieldFPStat struct {
	types.TrimDecision
	AlertedFlows          int64
	MaliciousAlertedFlows int64
	FPRate                float64
	Utilization           float64
}

type lowYieldHotRule struct {
	types.TrimDecision
	Checks                int64
	Matches               int64
	Alerts                int64
	TimeUS                int64
	RuleTimePct           float64
	AlertedFlows          int64
	MaliciousAlertedFlows int64
	FPRate                float64
	Utilization           float64
}

func LowYieldHotRules() types.RegisteredFunction {
	return types.RegisteredFunction{
		Name: "iter_low_yield_hot_rules",
		Type: types.ITER,
		Fn:   LowYieldHotRulesFunc,
	}
}

func LowYieldHotRulesFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
	factor := boundedFactor(input.Factor)
	if factor <= 0 {
		return nil, nil
	}
	fpStats, err := queryLowYieldFPStats(ctx, input.ExpDBPath, input.SourceRunID)
	if err != nil || len(fpStats) == 0 {
		return nil, err
	}
	rows, err := queryLowYieldHotRules(ctx, input.RealDBPath, input.SourceRunID, fpStats)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		rows, err = queryLowYieldHotRules(ctx, input.ExpDBPath, input.SourceRunID, fpStats)
		if err != nil {
			return nil, err
		}
	}
	if len(rows) == 0 {
		return nil, nil
	}
	limit := scaledLimit(len(rows), 0.20, factor)
	out := make([]types.TrimDecision, 0, limit)
	for i := 0; i < limit; i++ {
		row := rows[i]
		row.Reason = fmt.Sprintf("frequently checked rule has low malicious yield: checks=%d matches=%d alerts=%d malicious_flows=%d utilization=%.4f fp_rate=%.4f",
			row.Checks, row.Matches, row.Alerts, row.MaliciousAlertedFlows, row.Utilization, row.FPRate)
		row.Metrics = map[string]float64{
			"checks":                  float64(row.Checks),
			"matches":                 float64(row.Matches),
			"alerts":                  float64(row.Alerts),
			"time_us":                 float64(row.TimeUS),
			"rule_time_pct":           row.RuleTimePct,
			"alerted_flows":           float64(row.AlertedFlows),
			"malicious_alerted_flows": float64(row.MaliciousAlertedFlows),
			"fp_rate":                 row.FPRate,
			"utilization":             row.Utilization,
		}
		out = append(out, row.TrimDecision)
	}
	return out, nil
}

func queryLowYieldFPStats(ctx context.Context, dbPath string, runID int64) (map[string]lowYieldFPStat, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT r.gid, r.sid, r.rev, COALESCE(r.source_file, ''), COALESCE(r.msg, ''),
       fp.alerted_flows, fp.malicious_alerted_flows, fp.fp_rate, fp.utilization
FROM rules r
JOIN rule_FP fp
  ON fp.run_id = r.run_id AND fp.gid = r.gid AND fp.sid = r.sid
WHERE r.run_id = ? AND r.enabled = 1
  AND fp.malicious_alerted_flows <= 1
  AND fp.utilization <= 0.05;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]lowYieldFPStat{}
	for rows.Next() {
		var row lowYieldFPStat
		if err := rows.Scan(
			&row.GID, &row.SID, &row.Rev, &row.SourceFile, &row.Msg,
			&row.AlertedFlows, &row.MaliciousAlertedFlows, &row.FPRate, &row.Utilization,
		); err != nil {
			return nil, err
		}
		out[iterRuleKey(row.GID, row.SID)] = row
	}
	return out, rows.Err()
}

func queryLowYieldHotRules(ctx context.Context, dbPath string, runID int64, fpStats map[string]lowYieldFPStat) ([]lowYieldHotRule, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT r.gid, r.sid, p.checks, p.matches, p.alerts, p.time_us, p.rule_time_pct
FROM rules r
JOIN rule_profiler_metrics p
  ON p.run_id = r.run_id AND p.gid = r.gid AND p.sid = r.sid
WHERE r.run_id = ? AND r.enabled = 1
  AND p.checks >= 1000
ORDER BY p.checks DESC, p.matches ASC, p.alerts ASC, p.time_us DESC, r.gid, r.sid;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []lowYieldHotRule
	for rows.Next() {
		var gid, sid int64
		var row lowYieldHotRule
		if err := rows.Scan(&gid, &sid, &row.Checks, &row.Matches, &row.Alerts, &row.TimeUS, &row.RuleTimePct); err != nil {
			return nil, err
		}
		stat, ok := fpStats[iterRuleKey(gid, sid)]
		if !ok {
			continue
		}
		row.TrimDecision = stat.TrimDecision
		row.AlertedFlows = stat.AlertedFlows
		row.MaliciousAlertedFlows = stat.MaliciousAlertedFlows
		row.FPRate = stat.FPRate
		row.Utilization = stat.Utilization
		out = append(out, row)
	}
	return out, rows.Err()
}

func iterRuleKey(gid, sid int64) string {
	return fmt.Sprintf("%d:%d", gid, sid)
}
