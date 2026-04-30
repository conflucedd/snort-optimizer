package analyser

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sqlstore "snort-optimizer/sql"
	"snort-optimizer/types"

	_ "modernc.org/sqlite"
)

const maxAnalyserRules = 1_000_000

func prepareRuleDatabases(cfg Config, set instanceSet) error {
	if !cfg.PreserveWorkDBs {
		if err := resetAnalyserWorkingDir(cfg.AnalyserWorkingDir); err != nil {
			return err
		}
	}
	if err := ensureInstanceDirs(set); err != nil {
		return err
	}
	if err := ensureEmptyPCAP(cfg.EmptyPcap); err != nil {
		return err
	}
	for _, inst := range set.ordered() {
		if err := initRuleDB(cfg, inst.DBPath); err != nil {
			return fmt.Errorf("%s init rules: %w", inst.Name, err)
		}
	}
	return nil
}

func resetAnalyserWorkingDir(path string) error {
	clean := filepath.Clean(path)
	if err := validateRemoveAllTarget(clean); err != nil {
		return err
	}
	if err := os.RemoveAll(clean); err != nil {
		return fmt.Errorf("remove analyser working dir %s: %w", clean, err)
	}
	return nil
}

func validateRemoveAllTarget(path string) error {
	if path == "" || path == "." || path == string(os.PathSeparator) {
		return fmt.Errorf("refuse to remove unsafe analyser working dir %q", path)
	}
	cwd, err := os.Getwd()
	if err == nil && filepath.Clean(cwd) == path {
		return fmt.Errorf("refuse to remove current working directory %s", path)
	}
	home, err := os.UserHomeDir()
	if err == nil && filepath.Clean(home) == path {
		return fmt.Errorf("refuse to remove home directory %s", path)
	}
	tmp := filepath.Clean(os.TempDir())
	if tmp == path {
		return fmt.Errorf("refuse to remove temp root %s", path)
	}
	return nil
}

func initRuleDB(cfg Config, dstDBPath string) error {
	if cfg.RawSnortSQLite != "" {
		rules, err := listRulesFromDB(cfg.RawSnortSQLite, 0, false)
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

func listRulesFromDB(dbPath string, runID int64, enabledOnly bool) ([]types.Rule, error) {
	conn, err := sql.Open("sqlite", dbPath)
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
	var out []types.Rule
	for rows.Next() {
		var r types.Rule
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

func ruleTableColumns(conn *sql.DB) (map[string]bool, error) {
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

func insertRules(dbPath string, runID int64, records []types.Rule) error {
	conn, err := sql.Open("sqlite", dbPath)
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

func cloneRulesForRun(set instanceSet, fromRunID, toRunID int64, decisions []TrimmedRule) error {
	for _, inst := range set.ordered() {
		if err := cloneRulesInDB(inst.DBPath, fromRunID, toRunID, decisions); err != nil {
			return fmt.Errorf("%s clone rules: %w", inst.Name, err)
		}
	}
	return nil
}

func cloneRulesInDB(dbPath string, fromRunID, toRunID int64, decisions []TrimmedRule) error {
	if err := sqlstore.EnsureRules(sqlstore.Config{DBPath: dbPath, RunID: toRunID}); err != nil {
		return err
	}
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM rules WHERE run_id = ?;", toRunID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO rules
(run_id, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, created_at)
SELECT ?, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, ?
FROM rules WHERE run_id = ?;`, toRunID, time.Now().UTC().Format(time.RFC3339Nano), fromRunID); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare("UPDATE rules SET enabled = 0 WHERE run_id = ? AND gid = ? AND sid = ?;")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, d := range decisions {
		if _, err := stmt.Exec(toRunID, d.GID, d.SID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func aggregateAndEnrich(dbPath string, runID int64, typ FunctionType, raw []TrimDecision) ([]TrimmedRule, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	enabled, err := enabledRuleMap(dbPath, runID)
	if err != nil {
		return nil, err
	}
	merged := map[string]*TrimmedRule{}
	for _, d := range raw {
		key := ruleKey(d.GID, d.SID)
		rule, ok := enabled[key]
		if !ok {
			continue
		}
		current := merged[key]
		if current == nil {
			current = &TrimmedRule{
				RuleRef:    RuleRef{GID: d.GID, SID: d.SID, Rev: chooseRev(d.Rev, rule.Rev)},
				SourceFile: firstNonEmpty(d.SourceFile, rule.SourceFile),
				Msg:        firstNonEmpty(d.Msg, rule.Msg),
				RunID:      runID,
				Type:       typ,
				Metrics:    map[string]float64{},
			}
			merged[key] = current
		}
		appendUnique(&current.Reasons, strings.TrimSpace(d.Reason))
		appendUnique(&current.Functions, strings.TrimSpace(d.Function))
		for k, v := range d.Metrics {
			current.Metrics[k] = v
		}
	}
	out := make([]TrimmedRule, 0, len(merged))
	for _, d := range merged {
		if len(d.Metrics) == 0 {
			d.Metrics = nil
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].GID != out[j].GID {
			return out[i].GID < out[j].GID
		}
		return out[i].SID < out[j].SID
	})
	return out, nil
}

func enabledRuleMap(dbPath string, runID int64) (map[string]types.Rule, error) {
	rules, err := listRulesFromDB(dbPath, runID, true)
	if err != nil {
		return nil, err
	}
	out := make(map[string]types.Rule, len(rules))
	for _, r := range rules {
		out[ruleKey(r.GID, r.SID)] = r
	}
	return out, nil
}

func countEnabledRules(dbPath string, runID int64) (int64, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var count int64
	err = conn.QueryRow("SELECT count(*) FROM rules WHERE run_id = ? AND enabled = 1;", runID).Scan(&count)
	return count, err
}

func ruleKey(gid, sid int64) string {
	return fmt.Sprintf("%d:%d", gid, sid)
}

func chooseRev(candidate, fallback int64) int64 {
	if candidate != 0 {
		return candidate
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func appendUnique(values *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}
