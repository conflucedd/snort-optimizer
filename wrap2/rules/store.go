package rules

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	commontypes "snort-optimizer/types"
	"snort-optimizer/wrap2/sqliteutil"
)

func DBPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "rules.db")
}

func AllRulesPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "all.rules")
}

func EnsureDB(snortWorkingDir string, logger *log.Logger) error {
	dbPath := DBPath(snortWorkingDir)
	if _, err := os.Stat(dbPath); err == nil {
		return ensureSchema(dbPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat rules db: %w", err)
	}

	if err := os.MkdirAll(snortWorkingDir, 0755); err != nil {
		return fmt.Errorf("create snort working dir: %w", err)
	}
	if err := ensureSchema(dbPath); err != nil {
		return err
	}
	records, err := LoadRuleFiles(filepath.Join(snortWorkingDir, "rules"), logger)
	if err != nil {
		return err
	}
	return insertRules(dbPath, records)
}

func Reset(snortWorkingDir string) error {
	err := os.Remove(DBPath(snortWorkingDir))
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}

func SetEnabled(snortWorkingDir string, id int64, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	sql := fmt.Sprintf("UPDATE rules SET enabled = %d WHERE id = %d;", value, id)
	return sqliteutil.RunScript(DBPath(snortWorkingDir), []byte(sql))
}

func GenerateAllRules(snortWorkingDir string) error {
	if err := EnsureDB(snortWorkingDir, log.New(os.Stderr, "wrap2 rules: ", log.LstdFlags)); err != nil {
		return err
	}
	rows, err := sqliteutil.QueryJSON(DBPath(snortWorkingDir), "SELECT raw_text FROM rules WHERE enabled = 1 ORDER BY id;")
	if err != nil {
		return fmt.Errorf("query enabled rules: %w", err)
	}
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		if raw, ok := row["raw_text"].(string); ok && strings.TrimSpace(raw) != "" {
			lines = append(lines, strings.TrimSpace(raw))
		}
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(AllRulesPath(snortWorkingDir), []byte(content), 0644); err != nil {
		return fmt.Errorf("write all.rules: %w", err)
	}
	return nil
}

func LoadRuleFiles(rulesDir string, logger *log.Logger) ([]commontypes.Rule, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var records []commontypes.Rule
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".rules" {
			continue
		}
		path := filepath.Join(rulesDir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open rule file %s: %w", path, err)
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 128*1024), 4*1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			record, err := ParseRule(line, entry.Name())
			if err != nil {
				logger.Printf("skip invalid rule %s:%d: %v", path, lineNo, err)
				continue
			}
			records = append(records, record)
		}
		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, fmt.Errorf("scan rule file %s: %w", path, err)
		}
		file.Close()
	}
	return records, nil
}

func ensureSchema(dbPath string) error {
	schema := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	sid INTEGER NOT NULL,
	gid INTEGER NOT NULL DEFAULT 1,
	rev INTEGER,
	action TEXT,
	proto TEXT,
	src_net TEXT,
	src_port TEXT,
	direction TEXT,
	dst_net TEXT,
	dst_port TEXT,
	msg TEXT,
	classtype TEXT,
	enabled INTEGER NOT NULL DEFAULT 1,
	source_file TEXT,
	raw_text TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_source_raw ON rules (source_file, raw_text);
CREATE INDEX IF NOT EXISTS idx_rules_sid ON rules (sid);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
`
	return sqliteutil.RunScript(dbPath, []byte(schema))
}

func insertRules(dbPath string, records []commontypes.Rule) error {
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, rule := range records {
		fmt.Fprintf(&script, `INSERT OR IGNORE INTO rules (sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text)
VALUES (%d, %d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, %s, %s);
`,
			rule.SID,
			rule.GID,
			rule.Rev,
			sqliteutil.Quote(rule.Action),
			sqliteutil.Quote(rule.Proto),
			sqliteutil.Quote(rule.SrcNet),
			sqliteutil.Quote(rule.SrcPort),
			sqliteutil.Quote(rule.Direction),
			sqliteutil.Quote(rule.DstNet),
			sqliteutil.Quote(rule.DstPort),
			sqliteutil.Quote(rule.Msg),
			sqliteutil.Quote(rule.Classtype),
			sqliteutil.Quote(rule.SourceFile),
			sqliteutil.Quote(rule.RawText),
		)
	}
	script.WriteString("COMMIT;\n")
	if err := sqliteutil.RunScript(dbPath, script.Bytes()); err != nil {
		return fmt.Errorf("insert rules: %w", err)
	}
	return nil
}
