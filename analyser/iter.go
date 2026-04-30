package analyser

import (
	"context"
	"database/sql"
	"fmt"
	"math"
)

type highCostRule struct {
	TrimDecision
	TimeUS      int64
	RuleTimePct float64
	Checks      int64
	Matches     int64
	Alerts      int64
}

func IterHighCostRules(ctx context.Context, input FunctionInput) ([]TrimDecision, error) {
	factor := input.Factor
	if factor <= 0 {
		return nil, nil
	}
	if factor > 1 {
		factor = 1
	}
	rows, err := queryHighCostRules(ctx, input.RealDBPath, input.SourceRunID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		rows, err = queryHighCostRules(ctx, input.ExpDBPath, input.SourceRunID)
		if err != nil {
			return nil, err
		}
	}
	if len(rows) == 0 {
		return nil, nil
	}
	limit := int(math.Ceil(float64(len(rows)) * 0.20 * factor))
	if limit < 1 {
		limit = 1
	}
	if limit > len(rows) {
		limit = len(rows)
	}
	out := make([]TrimDecision, 0, limit)
	for i := 0; i < limit; i++ {
		row := rows[i]
		row.Reason = fmt.Sprintf("high real-traffic rule profiler cost: rank=%d time_us=%d pct=%.4f checks=%d matches=%d alerts=%d",
			i+1, row.TimeUS, row.RuleTimePct, row.Checks, row.Matches, row.Alerts)
		row.Metrics = map[string]float64{
			"time_us":       float64(row.TimeUS),
			"rule_time_pct": row.RuleTimePct,
			"checks":        float64(row.Checks),
			"matches":       float64(row.Matches),
			"alerts":        float64(row.Alerts),
		}
		out = append(out, row.TrimDecision)
	}
	return out, nil
}

func queryHighCostRules(ctx context.Context, dbPath string, runID int64) ([]highCostRule, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT r.gid, r.sid, r.rev, COALESCE(r.source_file, ''), COALESCE(r.msg, ''),
       p.time_us, p.rule_time_pct, p.checks, p.matches, p.alerts
FROM rules r
JOIN rule_profiler_metrics p
  ON p.run_id = r.run_id AND p.gid = r.gid AND p.sid = r.sid
WHERE r.run_id = ? AND r.enabled = 1 AND p.time_us > 0
ORDER BY p.time_us DESC, p.rule_time_pct DESC, r.gid, r.sid;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []highCostRule
	for rows.Next() {
		var row highCostRule
		if err := rows.Scan(
			&row.GID, &row.SID, &row.Rev, &row.SourceFile, &row.Msg,
			&row.TimeUS, &row.RuleTimePct, &row.Checks, &row.Matches, &row.Alerts,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
