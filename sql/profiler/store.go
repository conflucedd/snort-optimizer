package profiler

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
	"snort-optimizer/sql/schema"
	"snort-optimizer/types"
)

type Query struct {
	RunID   int64
	Section string
	Module  string
	Metric  string
	Limit   int
}

func ImportFile(cfg config.Config, logger *log.Logger) (int, error) {
	runID := cfg.RunID
	file, err := os.Open(cfg.ProfilerPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open profiler file: %w", err)
	}
	defer file.Close()
	metrics, rules, modules, err := Parse(file, runID, cfg.ProfilerPath)
	if err != nil {
		return 0, err
	}
	if err := InsertBatch(cfg, metrics); err != nil {
		return 0, err
	}
	if err := InsertRuleBatch(cfg, rules); err != nil {
		return 0, err
	}
	if err := InsertModuleBatch(cfg, modules); err != nil {
		return 0, err
	}
	total := len(metrics) + len(rules) + len(modules)
	logger.Printf("imported profiler metrics: generic=%d rule=%d module=%d", len(metrics), len(rules), len(modules))
	return total, nil
}

func InsertBatch(cfg config.Config, metrics []types.ProfilerMetric) error {
	if len(metrics) == 0 {
		return nil
	}
	if err := schema.Ensure(cfg); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, m := range metrics {
		if m.CreatedAt == "" {
			m.CreatedAt = now
		}
		runID := effectiveRunID(cfg, m.RunID)
		fmt.Fprintf(&script, `INSERT INTO profiler_metrics (run_id, section, module, metric, value, percent, unit, raw_line, source_file, created_at)
VALUES (%d, %s, %s, %s, %g, %g, %s, %s, %s, %s);
`,
			runID, db.Quote(m.Section), db.Quote(m.Module), db.Quote(m.Metric),
			m.Value, m.Percent, db.Quote(m.Unit), db.Quote(m.RawLine), db.Quote(m.SourceFile), db.Quote(m.CreatedAt),
		)
	}
	script.WriteString("COMMIT;\n")
	return db.RunScript(cfg.DBPath, script.Bytes())
}

func List(cfg config.Config, q Query) ([]types.ProfilerMetric, error) {
	where := []string{"1=1"}
	where = append(where, fmt.Sprintf("run_id = %d", effectiveRunID(cfg, q.RunID)))
	if q.Section != "" {
		where = append(where, "section LIKE "+db.Like(q.Section))
	}
	if q.Module != "" {
		where = append(where, "module LIKE "+db.Like(q.Module))
	}
	if q.Metric != "" {
		where = append(where, "metric LIKE "+db.Like(q.Metric))
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	sql := fmt.Sprintf(`SELECT id,run_id,section,module,metric,value,percent,unit,raw_line,source_file,created_at FROM profiler_metrics WHERE %s ORDER BY id DESC LIMIT %d;`, strings.Join(where, " AND "), limit)
	rows, err := db.QueryJSON(cfg.DBPath, sql)
	if err != nil {
		return nil, err
	}
	out := make([]types.ProfilerMetric, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToMetric(row))
	}
	return out, nil
}

func InsertRuleBatch(cfg config.Config, metrics []types.RuleProfilerMetric) error {
	if len(metrics) == 0 {
		return nil
	}
	if err := schema.Ensure(cfg); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, m := range metrics {
		if m.CreatedAt == "" {
			m.CreatedAt = now
		}
		runID := effectiveRunID(cfg, m.RunID)
		fmt.Fprintf(&script, `INSERT INTO rule_profiler_metrics (run_id, gid, sid, rev, checks, matches, alerts, time_us, avg_check, avg_match, avg_non_match, timeouts, suspends, rule_time_pct, raw_line, source_file, created_at)
VALUES (%d, %d, %d, %d, %d, %d, %d, %d, %g, %g, %g, %d, %d, %g, %s, %s, %s);
`,
			runID, m.GID, m.SID, m.Rev, m.Checks, m.Matches, m.Alerts, m.TimeUS,
			m.AvgCheck, m.AvgMatch, m.AvgNonMatch, m.Timeouts, m.Suspends, m.RuleTimePct,
			db.Quote(m.RawLine), db.Quote(m.SourceFile), db.Quote(m.CreatedAt),
		)
	}
	script.WriteString("COMMIT;\n")
	return db.RunScript(cfg.DBPath, script.Bytes())
}

func InsertModuleBatch(cfg config.Config, metrics []types.ModuleProfileMetric) error {
	if len(metrics) == 0 {
		return nil
	}
	if err := schema.Ensure(cfg); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, m := range metrics {
		if m.CreatedAt == "" {
			m.CreatedAt = now
		}
		runID := effectiveRunID(cfg, m.RunID)
		fmt.Fprintf(&script, `INSERT INTO module_profile_metrics (run_id, rank, module, layer, checks, time_us, avg_check, caller_pct, total_pct, raw_line, source_file, created_at)
VALUES (%d, %d, %s, %s, %d, %d, %g, %g, %g, %s, %s, %s);
`,
			runID, m.Rank, db.Quote(m.Module), db.Quote(m.Layer), m.Checks, m.TimeUS,
			m.AvgCheck, m.CallerPct, m.TotalPct, db.Quote(m.RawLine), db.Quote(m.SourceFile), db.Quote(m.CreatedAt),
		)
	}
	script.WriteString("COMMIT;\n")
	return db.RunScript(cfg.DBPath, script.Bytes())
}

func InsertSystemProfile(cfg config.Config, profile types.SystemProfile) error {
	if err := schema.Ensure(cfg); err != nil {
		return err
	}
	if profile.CreatedAt == "" {
		profile.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	runID := effectiveRunID(cfg, profile.RunID)
	script := fmt.Sprintf(`INSERT INTO system_profiles (run_id, avg_cpu, avg_mem_mb, samples, created_at)
VALUES (%d, %g, %g, %d, %s);`,
		runID, profile.AvgCPU, profile.AvgMemMB, profile.Samples, db.Quote(profile.CreatedAt))
	return db.RunScript(cfg.DBPath, []byte(script))
}

func rowToMetric(row map[string]any) types.ProfilerMetric {
	return types.ProfilerMetric{
		ID:         asInt(row["id"]),
		RunID:      asInt(row["run_id"]),
		Section:    asString(row["section"]),
		Module:     asString(row["module"]),
		Metric:     asString(row["metric"]),
		Value:      asFloat(row["value"]),
		Percent:    asFloat(row["percent"]),
		Unit:       asString(row["unit"]),
		RawLine:    asString(row["raw_line"]),
		SourceFile: asString(row["source_file"]),
		CreatedAt:  asString(row["created_at"]),
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asInt(v any) int64 {
	if n, ok := v.(float64); ok {
		return int64(n)
	}
	return 0
}

func asFloat(v any) float64 {
	if n, ok := v.(float64); ok {
		return n
	}
	return 0
}

func effectiveRunID(cfg config.Config, runID int64) int64 {
	if runID != 0 {
		return runID
	}
	return cfg.RunID
}
