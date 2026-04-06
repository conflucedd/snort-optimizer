package main

import (
	"fmt"
	"strings"
)

type DashboardRuleRecord struct {
	SID     int    `json:"sid"`
	Enabled bool   `json:"enabled"`
	RawText string `json:"raw_text"`
}

type RuleQuery struct {
	Limit  int
	Offset int
	Search string
}

type RuleQueryResult struct {
	Total int                   `json:"total"`
	Items []DashboardRuleRecord `json:"items"`
}

func QueryRules(dbPath string, query RuleQuery) (RuleQueryResult, error) {
	where := buildRuleWhere(query)
	countRows, err := QuerySQLiteJSON(dbPath, "SELECT COUNT(*) AS total FROM rules "+where+";")
	if err != nil {
		return RuleQueryResult{}, err
	}

	total := 0
	if len(countRows) > 0 {
		total = toInt(countRows[0]["total"])
	}

	sql := fmt.Sprintf(`SELECT sid, enabled, raw_text
FROM rules %s
ORDER BY sid ASC
LIMIT %d OFFSET %d;`, where, query.Limit, query.Offset)

	rows, err := QuerySQLiteJSON(dbPath, sql)
	if err != nil {
		return RuleQueryResult{}, err
	}

	items := make([]DashboardRuleRecord, 0, len(rows))
	for _, row := range rows {
		items = append(items, DashboardRuleRecord{
			SID:     toInt(row["sid"]),
			Enabled: toInt(row["enabled"]) != 0,
			RawText: toString(row["raw_text"]),
		})
	}

	return RuleQueryResult{Total: total, Items: items}, nil
}

func CountRules(dbPath string) (int, error) {
	rows, err := QuerySQLiteJSON(dbPath, "SELECT COUNT(*) AS total FROM rules;")
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return toInt(rows[0]["total"]), nil
}

func buildRuleWhere(query RuleQuery) string {
	search := strings.TrimSpace(query.Search)
	if search == "" {
		return ""
	}
	escaped := SQLQuote("%" + search + "%")
	return "WHERE raw_text LIKE " + escaped + " OR CAST(sid AS TEXT) LIKE " + escaped
}
