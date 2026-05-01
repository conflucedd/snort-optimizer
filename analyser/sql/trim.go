package sql

import (
	"fmt"
	"sort"
	"strings"

	atypes "snort-optimizer/analyser/types"
)

func AggregateAndEnrich(dbPath string, runID int64, typ atypes.FunctionType, raw []atypes.TrimDecision) ([]atypes.TrimmedRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	enabled, err := enabledRuleMap(dbPath, runID)
	if err != nil {
		return nil, err
	}
	merged := map[string]*atypes.TrimmedRule{}
	for _, d := range raw {
		key := ruleKey(d.GID, d.SID)
		rule, ok := enabled[key]
		if !ok {
			continue
		}
		current := merged[key]
		if current == nil {
			current = &atypes.TrimmedRule{
				RuleRef:    atypes.RuleRef{GID: d.GID, SID: d.SID, Rev: chooseRev(d.Rev, rule.Rev)},
				SourceFile: firstNonEmpty(d.SourceFile, rule.SourceFile),
				Msg:        firstNonEmpty(d.Msg, rule.Msg),
				RunID:      runID,
				Type:       typ,
				Metrics:    map[string]float64{},
			}
			merged[key] = current
		}
		appendUnique(&current.Reasons, strings.TrimSpace(d.Reason))
		appendUnique(&current.Functions, strings.TrimSpace(d.Function))
		for k, v := range d.Metrics {
			current.Metrics[k] = v
		}
	}
	out := make([]atypes.TrimmedRule, 0, len(merged))
	for _, d := range merged {
		if len(d.Metrics) == 0 {
			d.Metrics = nil
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GID != out[j].GID {
			return out[i].GID < out[j].GID
		}
		return out[i].SID < out[j].SID
	})
	return out, nil
}

func ruleKey(gid, sid int64) string {
	return fmt.Sprintf("%d:%d", gid, sid)
}

func chooseRev(candidate, fallback int64) int64 {
	if candidate != 0 {
		return candidate
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func appendUnique(values *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}
