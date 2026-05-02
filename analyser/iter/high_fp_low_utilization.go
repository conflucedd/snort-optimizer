package iter

import (
	"context"
	"database/sql"
	"fmt"

	"snort-optimizer/analyser/types"
)

type fpLowUtilizationRule struct {
	types.TrimDecision
	AlertedFlows          int64
	BenignAlertedFlows    int64
	MaliciousAlertedFlows int64
	FPRate                float64
	Utilization           float64
}

func HighFPLowUtilization() types.RegisteredFunction {
	return types.RegisteredFunction{
		Name: "iter_high_fp_low_utilization",
		Type: types.ITER,
		Fn:   HighFPLowUtilizationFunc,
	}
}

func HighFPLowUtilizationFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
	factor := boundedFactor(input.Factor)
	if factor <= 0 {
		return nil, nil
	}
	rows, err := queryHighFPLowUtilization(ctx, input.ExpDBPath, input.SourceRunID)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	limit := scaledLimit(len(rows), 0.30, factor)
	out := make([]types.TrimDecision, 0, limit)
	for i := 0; i < limit; i++ {
		row := rows[i]
		row.Reason = fmt.Sprintf("high false-positive and low malicious utilization: fp_rate=%.4f utilization=%.4f benign_flows=%d malicious_flows=%d alerted_flows=%d",
			row.FPRate, row.Utilization, row.BenignAlertedFlows, row.MaliciousAlertedFlows, row.AlertedFlows)
		row.Metrics = map[string]float64{
			"alerted_flows":           float64(row.AlertedFlows),
			"benign_alerted_flows":    float64(row.BenignAlertedFlows),
			"malicious_alerted_flows": float64(row.MaliciousAlertedFlows),
			"fp_rate":                 row.FPRate,
			"utilization":             row.Utilization,
		}
		out = append(out, row.TrimDecision)
	}
	return out, nil
}

func queryHighFPLowUtilization(ctx context.Context, dbPath string, runID int64) ([]fpLowUtilizationRule, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT r.gid, r.sid, r.rev, COALESCE(r.source_file, ''), COALESCE(r.msg, ''),
       fp.alerted_flows, fp.benign_alerted_flows, fp.malicious_alerted_flows, fp.fp_rate, fp.utilization
FROM rules r
JOIN rule_FP fp
  ON fp.run_id = r.run_id AND fp.gid = r.gid AND fp.sid = r.sid
WHERE r.run_id = ? AND r.enabled = 1
  AND fp.alerted_flows > 0
  AND fp.benign_alerted_flows > 0
  AND fp.fp_rate >= 0.80
  AND fp.utilization <= 0.10
  AND fp.malicious_alerted_flows <= 1
ORDER BY fp.fp_rate DESC, fp.utilization ASC, fp.benign_alerted_flows DESC, r.gid, r.sid;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fpLowUtilizationRule
	for rows.Next() {
		var row fpLowUtilizationRule
		if err := rows.Scan(
			&row.GID, &row.SID, &row.Rev, &row.SourceFile, &row.Msg,
			&row.AlertedFlows, &row.BenignAlertedFlows, &row.MaliciousAlertedFlows,
			&row.FPRate, &row.Utilization,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
