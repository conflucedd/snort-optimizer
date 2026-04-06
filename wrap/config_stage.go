package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var sidPattern = regexp.MustCompile(`\bsid\s*:\s*(\d+)\s*;`)

type RuleRecord struct {
	SID     int
	RawText string
}

func EnsureRulesDB(configDir string, logger *log.Logger) error {
	rulesDBPath := filepath.Join(configDir, "rules.db")
	if _, err := os.Stat(rulesDBPath); err == nil {
		logger.Printf("using existing rules db: %s", rulesDBPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat rules.db: %w", err)
	}

	rulesDir := filepath.Join(configDir, "rules")
	records, err := LoadRuleFiles(rulesDir)
	if err != nil {
		return err
	}
	if len(records) == 0 {
		return fmt.Errorf("no rules with sid found in %s", rulesDir)
	}

	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	script.WriteString("CREATE TABLE IF NOT EXISTS rules (\n")
	script.WriteString("    sid INTEGER PRIMARY KEY,\n")
	script.WriteString("    enabled INTEGER DEFAULT 1,\n")
	script.WriteString("    raw_text TEXT\n")
	script.WriteString(");\n")
	script.WriteString("DELETE FROM rules;\n")
	for _, record := range records {
		fmt.Fprintf(&script, "INSERT INTO rules (sid, enabled, raw_text) VALUES (%d, 1, %s);\n",
			record.SID, SQLQuote(record.RawText))
	}
	script.WriteString("COMMIT;\n")

	if err := RunSQLiteScript(rulesDBPath, script.Bytes()); err != nil {
		return fmt.Errorf("create rules.db: %w", err)
	}
	logger.Printf("generated rules.db with %d rules", len(records))
	return nil
}

func GenerateAllRules(configDir string, logger *log.Logger) error {
	rulesDBPath := filepath.Join(configDir, "rules.db")
	rows, err := QuerySQLiteJSON(rulesDBPath, "SELECT sid, raw_text FROM rules WHERE enabled = 1 ORDER BY sid;")
	if err != nil {
		return fmt.Errorf("query enabled rules: %w", err)
	}

	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		rawText, _ := row["raw_text"].(string)
		rawText = strings.TrimSpace(rawText)
		if rawText != "" {
			lines = append(lines, rawText)
		}
	}

	allRulesPath := filepath.Join(configDir, "all.rules")
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(allRulesPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write all.rules: %w", err)
	}
	logger.Printf("generated all.rules with %d enabled rules", len(lines))
	return nil
}

func LoadRuleFiles(rulesDir string) ([]RuleRecord, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}

	recordsBySID := make(map[int]RuleRecord)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".rules" {
			continue
		}
		path := filepath.Join(rulesDir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 128*1024), 2*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			matches := sidPattern.FindStringSubmatch(line)
			if len(matches) != 2 {
				continue
			}

			sid, err := ParseInt(matches[1], "sid")
			if err != nil {
				file.Close()
				return nil, fmt.Errorf("parse sid in %s: %w", path, err)
			}
			recordsBySID[sid] = RuleRecord{SID: sid, RawText: line}
		}

		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("scan %s: %w", path, err)
		}
		file.Close()
	}

	records := make([]RuleRecord, 0, len(recordsBySID))
	for _, record := range recordsBySID {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].SID < records[j].SID
	})
	return records, nil
}
