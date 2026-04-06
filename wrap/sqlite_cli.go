package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func RunSQLiteScript(dbPath string, script []byte) error {
	cmd := exec.Command("sqlite3", dbPath)
	cmd.Stdin = bytes.NewReader(script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func QuerySQLiteJSON(dbPath string, sql string) ([]map[string]any, error) {
	cmd := exec.Command("sqlite3", "-json", dbPath, sql)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}

	trimmed := bytes.TrimSpace(output)
	if len(trimmed) == 0 {
		return []map[string]any{}, nil
	}

	var rows []map[string]any
	if err := json.Unmarshal(trimmed, &rows); err != nil {
		return nil, fmt.Errorf("parse sqlite json: %w", err)
	}
	return rows, nil
}

func SQLQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
