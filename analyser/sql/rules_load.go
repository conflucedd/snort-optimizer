package sql

import (
	dbsql "database/sql"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	atypes "snort-optimizer/analyser/types"
	sqlstore "snort-optimizer/sql"
	stypes "snort-optimizer/types"
)

func InitRuleDB(cfg atypes.Config, dstDBPath string) error {
	if cfg.RawSnortSQLite != "" {
		rules, err := ListRulesFromDB(cfg.RawSnortSQLite, 0, false)
		if err != nil {
			return err
		}
		if len(rules) == 0 {
			return fmt.Errorf("raw snort sqlite has no rules with run_id=0")
		}
		if err := sqlstore.EnsureRules(sqlstore.Config{DBPath: dstDBPath, RunID: 0}); err != nil {
			return err
		}
		return insertRules(dstDBPath, 0, rules)
	}
	logger := log.New(io.Discard, "", 0)
	_, err := sqlstore.ImportRules(sqlstore.Config{
		DBPath:      dstDBPath,
		RawRulePath: cfg.RawRulePath,
		RunID:       0,
	}, logger)
	return err
}

func ListRulesFromDB(dbPath string, runID int64, enabledOnly bool) ([]stypes.Rule, error) {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	columns, err := ruleTableColumns(conn)
	if err != nil {
		return nil, err
	}
	if !columns["sid"] || !columns["raw_text"] {
		return nil, fmt.Errorf("rules table in %s must contain sid and raw_text", dbPath)
	}
	expr := func(name, fallback string) string {
		if !columns[name] {
			return fallback
		}
		return "COALESCE(" + quoteIdent(name) + ", " + fallback + ")"
	}
	query := fmt.Sprintf(`SELECT %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
FROM rules`, quoteIdent("sid"), expr("gid", "1"), expr("rev", "0"), expr("action", "''"), expr("proto", "''"),
		expr("src_net", "''"), expr("src_port", "''"), expr("direction", "''"), expr("dst_net", "''"), expr("dst_port", "''"),
		expr("msg", "''"), expr("classtype", "''"), expr("enabled", "1"), expr("source_file", "''"), quoteIdent("raw_text"))
	var where []string
	var args []any
	if columns["run_id"] {
		where = append(where, "run_id = ?")
		args = append(args, runID)
	}
	if enabledOnly && columns["enabled"] {
		where = append(where, "enabled = 1")
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY gid, sid;"
	rows, err := conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stypes.Rule
	for rows.Next() {
		var r stypes.Rule
		var enabled int64
		if err := rows.Scan(
			&r.SID, &r.GID, &r.Rev, &r.Action, &r.Proto,
			&r.SrcNet, &r.SrcPort, &r.Direction, &r.DstNet, &r.DstPort,
			&r.Msg, &r.Classtype, &enabled, &r.SourceFile, &r.RawText,
		); err != nil {
			return nil, err
		}
		r.RunID = runID
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func CountEnabledRules(dbPath string, runID int64) (int64, error) {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var count int64
	err = conn.QueryRow("SELECT count(*) FROM rules WHERE run_id = ? AND enabled = 1;", runID).Scan(&count)
	return count, err
}

func ruleTableColumns(conn *dbsql.DB) (map[string]bool, error) {
	rows, err := conn.Query("PRAGMA table_info(rules);")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func insertRules(dbPath string, runID int64, records []stypes.Rule) error {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO rules
(run_id, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, r := range records {
		enabled := 0
		if r.Enabled {
			enabled = 1
		}
		if _, err := stmt.Exec(
			runID, r.SID, r.GID, r.Rev, r.Action, r.Proto, r.SrcNet, r.SrcPort,
			r.Direction, r.DstNet, r.DstPort, r.Msg, r.Classtype, enabled,
			r.SourceFile, r.RawText, now,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func enabledRuleMap(dbPath string, runID int64) (map[string]stypes.Rule, error) {
	rules, err := ListRulesFromDB(dbPath, runID, true)
	if err != nil {
		return nil, err
	}
	out := make(map[string]stypes.Rule, len(rules))
	for _, r := range rules {
		out[ruleKey(r.GID, r.SID)] = r
	}
	return out, nil
}
