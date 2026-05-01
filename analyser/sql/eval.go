package sql

import (
	dbsql "database/sql"

	"snort-optimizer/analyser/types"
)

type RuntimeStats struct {
	BaseLoadMS    int64
	ExpRuntimeMS  int64
	RealRuntimeMS int64
}

func EvaluateRun(expDBPath, realDBPath string, runID int64, flows FlowSet, stats RuntimeStats) (types.Evaluation, error) {
	alerts, err := loadEvalAlerts(expDBPath, runID)
	if err != nil {
		return types.Evaluation{}, err
	}
	eval := evaluateAlerts(flows, alerts)
	eval.RunID = runID
	eval.RealRuleTimeUS, _ = SumRuleTimeUS(realDBPath, runID)
	eval.RealAvgCPU, eval.RealAvgMemMB, _ = LatestSystemProfile(realDBPath, runID)
	eval.BaseLoadMS = stats.BaseLoadMS
	eval.ExpRuntimeMS = stats.ExpRuntimeMS
	eval.RealRuntimeMS = stats.RealRuntimeMS
	return eval, nil
}

func evaluateAlerts(flows FlowSet, alerts []AlertForEval) types.Evaluation {
	alerted := make(map[int]bool)
	matches, unmatched := matchAlertsToFlows(flows, alerts)
	for _, match := range matches {
		alerted[match.Flow] = true
	}

	var eval types.Evaluation
	eval.TotalFlows = int64(len(flows.Flows))
	eval.AlertedFlows = int64(len(alerted))
	eval.UnmatchedAlertFlows = unmatched
	for i, flow := range flows.Flows {
		if flow.IsBenign {
			eval.BenignFlows++
			if alerted[i] {
				eval.FalsePositiveFlows++
			}
			continue
		}
		if flow.IsMalicious {
			eval.MaliciousFlows++
			if alerted[i] {
				eval.DetectedMaliciousFlows++
			} else {
				eval.MissedFlows++
			}
		}
	}
	if eval.TotalFlows > 0 {
		eval.FalsePositiveRate = float64(eval.FalsePositiveFlows) / float64(eval.TotalFlows)
	}
	if eval.MaliciousFlows > 0 {
		eval.MissRate = float64(eval.MissedFlows) / float64(eval.MaliciousFlows)
	}
	return eval
}

func SumRuleTimeUS(dbPath string, runID int64) (int64, error) {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var value dbsql.NullInt64
	err = conn.QueryRow("SELECT COALESCE(sum(time_us), 0) FROM rule_profiler_metrics WHERE run_id = ?;", runID).Scan(&value)
	if err != nil || !value.Valid {
		return 0, err
	}
	return value.Int64, nil
}

func LatestSystemProfile(dbPath string, runID int64) (float64, float64, error) {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	var cpu, mem dbsql.NullFloat64
	err = conn.QueryRow("SELECT avg_cpu, avg_mem_mb FROM system_profiles WHERE run_id = ? ORDER BY id DESC LIMIT 1;", runID).Scan(&cpu, &mem)
	if err == dbsql.ErrNoRows {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return nullFloat(cpu), nullFloat(mem), nil
}

func nullFloat(value dbsql.NullFloat64) float64 {
	if value.Valid {
		return value.Float64
	}
	return 0
}
