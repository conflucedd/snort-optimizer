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
	RunID   string
	Section string
	Module  string
	Metric  string
	Limit   int
}

func ImportFile(cfg config.Config, runID string, logger *log.Logger) (int, error) {
	if runID == "" {
		runID = time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	file, err := os.Open(cfg.ProfilerPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open profiler file: %w", err)
	}
	defer file.Close()
	metrics, err := Parse(file, runID, cfg.ProfilerPath)
	if err != nil {
		return 0, err
	}
	if err := InsertBatch(cfg, metrics); err != nil {
		return 0, err
	}
	logger.Printf("imported profiler metrics: %d", len(metrics))
	return len(metrics), nil
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
		fmt.Fprintf(&script, `INSERT INTO profiler_metrics (run_id, section, module, metric, value, percent, unit, raw_line, source_file, created_at)
VALUES (%s, %s, %s, %s, %g, %g, %s, %s, %s, %s);
`,
			db.Quote(m.RunID), db.Quote(m.Section), db.Quote(m.Module), db.Quote(m.Metric),
			m.Value, m.Percent, db.Quote(m.Unit), db.Quote(m.RawLine), db.Quote(m.SourceFile), db.Quote(m.CreatedAt),
		)
	}
	script.WriteString("COMMIT;\n")
	return db.RunScript(cfg.DBPath, script.Bytes())
}

func List(cfg config.Config, q Query) ([]types.ProfilerMetric, error) {
	where := []string{"1=1"}
	if q.RunID != "" {
		where = append(where, "run_id = "+db.Quote(q.RunID))
	}
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

func rowToMetric(row map[string]any) types.ProfilerMetric {
	return types.ProfilerMetric{
		ID:         asInt(row["id"]),
		RunID:      asString(row["run_id"]),
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
