package iter

import (
	"context"
	"database/sql"
	"fmt"
	"path"
	"sort"
	"strings"

	"snort-optimizer/analyser/types"
)

type protocolAlertRule struct {
	types.TrimDecision
	Group                  string
	AlertedFlows           int64
	BenignAlertedFlows     int64
	MaliciousAlertedFlows  int64
	FPRate                 float64
	Utilization            float64
	GroupAlertedFlows      int64
	GroupKeptRules         int
	GroupCoverageThreshold float64
}

func ProtocolAlertOverlap() types.RegisteredFunction {
	return types.RegisteredFunction{
		Name: "iter_protocol_alert_overlap",
		Type: types.ITER,
		Fn:   ProtocolAlertOverlapFunc,
	}
}

func ProtocolAlertOverlapFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
	factor := boundedFactor(input.Factor)
	if factor <= 0 {
		return nil, nil
	}
	groups, err := queryProtocolAlertGroups(ctx, input.ExpDBPath, input.SourceRunID)
	if err != nil {
		return nil, err
	}
	var candidates []protocolAlertRule
	for _, group := range groups {
		candidates = append(candidates, lowCoverageProtocolRules(group)...)
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].GroupAlertedFlows != candidates[j].GroupAlertedFlows {
			return candidates[i].GroupAlertedFlows > candidates[j].GroupAlertedFlows
		}
		if candidates[i].AlertedFlows != candidates[j].AlertedFlows {
			return candidates[i].AlertedFlows < candidates[j].AlertedFlows
		}
		if candidates[i].Utilization != candidates[j].Utilization {
			return candidates[i].Utilization < candidates[j].Utilization
		}
		return candidates[i].SID < candidates[j].SID
	})
	limit := scaledLimit(len(candidates), 0.25, factor)
	out := make([]types.TrimDecision, 0, limit)
	for i := 0; i < limit; i++ {
		row := candidates[i]
		row.Reason = fmt.Sprintf("protocol group %q has concentrated alert coverage; trimming lower-coverage rule outside top %.0f%% coverage: rule_alerted=%d group_alerted=%d kept_rules=%d utilization=%.4f fp_rate=%.4f",
			row.Group, row.GroupCoverageThreshold*100, row.AlertedFlows, row.GroupAlertedFlows, row.GroupKeptRules, row.Utilization, row.FPRate)
		row.Metrics = map[string]float64{
			"alerted_flows":            float64(row.AlertedFlows),
			"benign_alerted_flows":     float64(row.BenignAlertedFlows),
			"malicious_alerted_flows":  float64(row.MaliciousAlertedFlows),
			"fp_rate":                  row.FPRate,
			"utilization":              row.Utilization,
			"group_alerted_flows":      float64(row.GroupAlertedFlows),
			"group_kept_rules":         float64(row.GroupKeptRules),
			"group_coverage_threshold": row.GroupCoverageThreshold,
		}
		out = append(out, row.TrimDecision)
	}
	return out, nil
}

func queryProtocolAlertGroups(ctx context.Context, dbPath string, runID int64) (map[string][]protocolAlertRule, error) {
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
ORDER BY r.source_file, fp.alerted_flows DESC, r.gid, r.sid;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := map[string][]protocolAlertRule{}
	for rows.Next() {
		var row protocolAlertRule
		if err := rows.Scan(
			&row.GID, &row.SID, &row.Rev, &row.SourceFile, &row.Msg,
			&row.AlertedFlows, &row.BenignAlertedFlows, &row.MaliciousAlertedFlows,
			&row.FPRate, &row.Utilization,
		); err != nil {
			return nil, err
		}
		group := iterSourceFileBase(row.SourceFile)
		if !isProtocolGroup(group) {
			continue
		}
		row.Group = group
		groups[group] = append(groups[group], row)
	}
	return groups, rows.Err()
}

func lowCoverageProtocolRules(group []protocolAlertRule) []protocolAlertRule {
	if len(group) < 4 {
		return nil
	}
	sort.Slice(group, func(i, j int) bool {
		if group[i].MaliciousAlertedFlows != group[j].MaliciousAlertedFlows {
			return group[i].MaliciousAlertedFlows > group[j].MaliciousAlertedFlows
		}
		if group[i].AlertedFlows != group[j].AlertedFlows {
			return group[i].AlertedFlows > group[j].AlertedFlows
		}
		if group[i].Utilization != group[j].Utilization {
			return group[i].Utilization > group[j].Utilization
		}
		return group[i].SID < group[j].SID
	})
	var total int64
	for _, row := range group {
		total += row.AlertedFlows
	}
	if total < 3 {
		return nil
	}
	const coverageThreshold = 0.80
	var cumulative int64
	keep := len(group)
	for i, row := range group {
		cumulative += row.AlertedFlows
		if float64(cumulative)/float64(total) >= coverageThreshold {
			keep = i + 1
			break
		}
	}
	if keep >= len(group) || keep > len(group)/2 {
		return nil
	}
	out := make([]protocolAlertRule, 0, len(group)-keep)
	for _, row := range group[keep:] {
		row.GroupAlertedFlows = total
		row.GroupKeptRules = keep
		row.GroupCoverageThreshold = coverageThreshold
		out = append(out, row)
	}
	return out
}

func iterSourceFileBase(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "\\", "/")))
	return path.Base(value)
}

func isProtocolGroup(source string) bool {
	return strings.HasPrefix(source, "snort3-protocol-") || source == "snort3-netbios.rules" || source == "snort3-x11.rules"
}
