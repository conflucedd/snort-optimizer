package db

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func EnsureParent(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

func RunScript(dbPath string, script []byte) error {
	if err := EnsureParent(dbPath); err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Exec(string(script))
	return err
}

func QueryJSON(dbPath, sql string) ([]map[string]any, error) {
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			row[col] = normalizeValue(values[i])
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func Quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func Like(value string) string {
	return Quote("%" + value + "%")
}

func sqlOpen(dbPath string) (*sql.DB, error) {
	if err := EnsureParent(dbPath); err != nil {
		return nil, err
	}
	return sql.Open("sqlite", dbPath)
}

func normalizeValue(v any) any {
	switch value := v.(type) {
	case []byte:
		return string(value)
	case int64:
		return float64(value)
	default:
		return value
	}
}
