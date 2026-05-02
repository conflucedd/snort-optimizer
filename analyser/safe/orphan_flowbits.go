package safe

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"snort-optimizer/analyser/types"
)

type flowbitRule struct {
	types.TrimDecision
	provides []string
	requires []string
}

func OrphanFlowbits() types.RegisteredFunction {
	return types.RegisteredFunction{
		Name: "safe_orphan_flowbits",
		Type: types.SAFE,
		Fn:   OrphanFlowbitsFunc,
	}
}

func OrphanFlowbitsFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
	conn, err := sql.Open("sqlite", input.ExpDBPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT gid, sid, rev, COALESCE(source_file, ''), COALESCE(msg, ''), COALESCE(raw_text, '')
FROM rules
WHERE run_id = ? AND enabled = 1
ORDER BY gid, sid;`, input.SourceRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	provided := map[string]struct{}{}
	var rules []flowbitRule
	for rows.Next() {
		var row flowbitRule
		var raw string
		if err := rows.Scan(&row.GID, &row.SID, &row.Rev, &row.SourceFile, &row.Msg, &raw); err != nil {
			return nil, err
		}
		row.provides, row.requires = parseFlowbits(raw)
		for _, bit := range row.provides {
			provided[bit] = struct{}{}
		}
		if len(row.requires) > 0 {
			rules = append(rules, row)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []types.TrimDecision
	for _, rule := range rules {
		var missing []string
		for _, bit := range rule.requires {
			if _, ok := provided[bit]; !ok {
				missing = appendUniqueString(missing, bit)
			}
		}
		if len(missing) == 0 {
			continue
		}
		rule.Reason = fmt.Sprintf("flowbits dependency has no enabled provider: %s", strings.Join(missing, ","))
		out = append(out, rule.TrimDecision)
	}
	return out, nil
}

func parseFlowbits(raw string) ([]string, []string) {
	lower := strings.ToLower(raw)
	var provides []string
	var requires []string
	for offset := 0; offset < len(lower); {
		pos := strings.Index(lower[offset:], "flowbits:")
		if pos < 0 {
			break
		}
		start := offset + pos + len("flowbits:")
		end := strings.Index(lower[start:], ";")
		if end < 0 {
			break
		}
		value := lower[start : start+end]
		parts := strings.Split(value, ",")
		if len(parts) == 0 {
			offset = start + end + 1
			continue
		}
		op := strings.TrimSpace(parts[0])
		args := ""
		if len(parts) > 1 {
			args = strings.Join(parts[1:], ",")
		}
		switch op {
		case "set", "toggle":
			for _, bit := range flowbitNames(args) {
				provides = appendUniqueString(provides, bit)
			}
		case "isset":
			for _, bit := range flowbitNames(args) {
				requires = appendUniqueString(requires, bit)
			}
		}
		offset = start + end + 1
	}
	return provides, requires
}

func flowbitNames(value string) []string {
	var out []string
	for _, bit := range strings.FieldsFunc(value, func(r rune) bool {
		switch r {
		case ',', '&', '|', '!', '(', ')', ' ', '\t', '\n', '\r':
			return true
		default:
			return false
		}
	}) {
		bit = strings.TrimSpace(bit)
		if bit != "" {
			out = append(out, bit)
		}
	}
	return out
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
