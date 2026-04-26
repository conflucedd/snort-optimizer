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
	"time"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
	"snort-optimizer/sql/schema"
	"snort-optimizer/types"
)

type Query struct {
	SID       int64
	GID       int64
	Msg       string
	Classtype string
	Enabled   *bool
	Limit     int
}

func ImportDir(cfg config.Config, logger *log.Logger) (int, error) {
	records, err := LoadDir(cfg.RulesDir, logger)
	if err != nil {
		return 0, err
	}
	if err := InsertBatch(cfg, records); err != nil {
		return 0, err
	}
	return len(records), nil
}

func LoadDir(rulesDir string, logger *log.Logger) ([]types.Rule, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var records []types.Rule
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
			if line == "" {
				continue
			}
			record, err := ParseLine(line, entry.Name())
			if err != nil {
				if !strings.Contains(err.Error(), "comment") {
					logger.Printf("skip invalid rule %s:%d: %v", path, lineNo, err)
				}
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

func InsertBatch(cfg config.Config, records []types.Rule) error {
	if len(records) == 0 {
		return nil
	}
	if err := schema.Ensure(cfg); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, r := range records {
		enabled := 0
		if r.Enabled {
			enabled = 1
		}
		fmt.Fprintf(&script, `INSERT OR IGNORE INTO rules (sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, created_at)
VALUES (%d, %d, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s);
`,
			r.SID, r.GID, r.Rev, db.Quote(r.Action), db.Quote(r.Proto), db.Quote(r.SrcNet),
			db.Quote(r.SrcPort), db.Quote(r.Direction), db.Quote(r.DstNet), db.Quote(r.DstPort),
			db.Quote(r.Msg), db.Quote(r.Classtype), enabled, db.Quote(r.SourceFile), db.Quote(r.RawText), db.Quote(now),
		)
	}
	script.WriteString("COMMIT;\n")
	return db.RunScript(cfg.DBPath, script.Bytes())
}

func List(cfg config.Config, q Query) ([]types.Rule, error) {
	where := []string{"1=1"}
	if q.SID > 0 {
		where = append(where, fmt.Sprintf("sid = %d", q.SID))
	}
	if q.GID > 0 {
		where = append(where, fmt.Sprintf("gid = %d", q.GID))
	}
	if q.Msg != "" {
		where = append(where, "msg LIKE "+db.Like(q.Msg))
	}
	if q.Classtype != "" {
		where = append(where, "classtype = "+db.Quote(q.Classtype))
	}
	if q.Enabled != nil {
		value := 0
		if *q.Enabled {
			value = 1
		}
		where = append(where, fmt.Sprintf("enabled = %d", value))
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	sql := fmt.Sprintf(`SELECT id,sid,gid,rev,action,proto,src_net,src_port,direction,dst_net,dst_port,msg,classtype,enabled,source_file,raw_text FROM rules WHERE %s ORDER BY id LIMIT %d;`, strings.Join(where, " AND "), limit)
	rows, err := db.QueryJSON(cfg.DBPath, sql)
	if err != nil {
		return nil, err
	}
	out := make([]types.Rule, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToRule(row))
	}
	return out, nil
}

func SetEnabled(cfg config.Config, id int64, enabled bool) error {
	value := 0
	if enabled {
		value = 1
	}
	return db.RunScript(cfg.DBPath, []byte(fmt.Sprintf("UPDATE rules SET enabled = %d WHERE id = %d;", value, id)))
}

func rowToRule(row map[string]any) types.Rule {
	return types.Rule{
		ID:         asInt(row["id"]),
		SID:        asInt(row["sid"]),
		GID:        asInt(row["gid"]),
		Rev:        asInt(row["rev"]),
		Action:     asString(row["action"]),
		Proto:      asString(row["proto"]),
		SrcNet:     asString(row["src_net"]),
		SrcPort:    asString(row["src_port"]),
		Direction:  asString(row["direction"]),
		DstNet:     asString(row["dst_net"]),
		DstPort:    asString(row["dst_port"]),
		Msg:        asString(row["msg"]),
		Classtype:  asString(row["classtype"]),
		Enabled:    asInt(row["enabled"]) != 0,
		SourceFile: asString(row["source_file"]),
		RawText:    asString(row["raw_text"]),
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
