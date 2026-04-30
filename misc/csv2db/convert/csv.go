package convert

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type CSVData struct {
	TableName string
	Headers   []string
	Columns   []ColumnInfo
	Rows      [][]string
}

func ReadCSV(csvPath string) (*CSVData, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	all, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(all) < 2 {
		return nil, fmt.Errorf("CSV has no data rows")
	}

	headers := all[0]
	rows := all[1:]
	cols := make([]string, len(headers))
	for i, h := range headers {
		cols[i] = sanitizeColumn(h)
	}

	return &CSVData{
		TableName: tableName(csvPath),
		Headers:   headers,
		Columns:   inferTypes(cols, rows),
		Rows:      rows,
	}, nil
}

func tableName(csvPath string) string {
	return strings.TrimSuffix(filepath.Base(csvPath), ".csv")
}

func sanitizeColumn(s string) string {
	r := strings.NewReplacer(
		" ", "_",
		"/", "_",
		".", "_",
		"-", "_",
	)
	return strings.ToLower(strings.TrimSpace(r.Replace(s)))
}
