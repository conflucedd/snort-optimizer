package schema

import (
	"fmt"
	"os"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
)

type TableCount struct {
	Total int64 `json:"total"`
	Run   int64 `json:"run"`
}

func Ensure(cfg config.Config) error {
	return EnsureAll(cfg)
}

func EnsureAll(cfg config.Config) error {
	if err := EnsureAlerts(cfg); err != nil {
		return err
	}
	if err := EnsureProfiler(cfg); err != nil {
		return err
	}
	if err := EnsureSystemProfiles(cfg); err != nil {
		return err
	}
	return EnsureRules(cfg)
}

func EnsureAlerts(cfg config.Config) error {
	if err := recreateIncompatibleTable(cfg.DBPath, "alerts", []string{"run_id"}, nil); err != nil {
		return err
	}
	script := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	timestamp TEXT,
	pkt_num INTEGER,
	proto TEXT,
	pkt_gen TEXT,
	pkt_len INTEGER,
	dir TEXT,
	src_ap TEXT,
	dst_ap TEXT,
	gid INTEGER,
	sid INTEGER,
	rev INTEGER,
	rule TEXT,
	action TEXT,
	raw_json TEXT NOT NULL,
	source_file TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts (sid);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_source_file ON alerts (source_file);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	return db.RunScript(cfg.DBPath, []byte("CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON alerts (run_id);"))
}

func EnsureProfiler(cfg config.Config) error {
	if err := EnsureProfilerMetrics(cfg); err != nil {
		return err
	}
	if err := EnsureRuleProfilerMetrics(cfg); err != nil {
		return err
	}
	return EnsureModuleProfileMetrics(cfg)
}

func EnsureProfilerMetrics(cfg config.Config) error {
	if err := recreateIncompatibleTable(cfg.DBPath, "profiler_metrics", []string{"run_id"}, nil); err != nil {
		return err
	}
	script := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS profiler_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	section TEXT NOT NULL,
	module TEXT NOT NULL,
	metric TEXT NOT NULL,
	value REAL NOT NULL,
	percent REAL,
	unit TEXT,
	raw_line TEXT NOT NULL,
	source_file TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profiler_section_module ON profiler_metrics (section, module);
CREATE INDEX IF NOT EXISTS idx_profiler_created_at ON profiler_metrics (created_at);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	return db.RunScript(cfg.DBPath, []byte("CREATE INDEX IF NOT EXISTS idx_profiler_run_id ON profiler_metrics (run_id);"))
}

func EnsureRuleProfilerMetrics(cfg config.Config) error {
	if err := recreateIncompatibleTable(cfg.DBPath, "rule_profiler_metrics", []string{"run_id"}, nil); err != nil {
		return err
	}
	script := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS rule_profiler_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	gid INTEGER NOT NULL,
	sid INTEGER NOT NULL,
	rev INTEGER NOT NULL,
	checks INTEGER NOT NULL,
	matches INTEGER NOT NULL,
	alerts INTEGER NOT NULL,
	time_us INTEGER NOT NULL,
	avg_check REAL NOT NULL,
	avg_match REAL NOT NULL,
	avg_non_match REAL NOT NULL,
	timeouts INTEGER NOT NULL,
	suspends INTEGER NOT NULL,
	rule_time_pct REAL NOT NULL,
	raw_line TEXT NOT NULL,
	source_file TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rule_profiler_rule ON rule_profiler_metrics (gid, sid, rev);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	return db.RunScript(cfg.DBPath, []byte("CREATE INDEX IF NOT EXISTS idx_rule_profiler_run_id ON rule_profiler_metrics (run_id);"))
}

func EnsureModuleProfileMetrics(cfg config.Config) error {
	if err := recreateIncompatibleTable(cfg.DBPath, "module_profile_metrics", []string{"run_id"}, nil); err != nil {
		return err
	}
	script := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS module_profile_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	rank INTEGER NOT NULL,
	module TEXT NOT NULL,
	layer TEXT NOT NULL,
	checks INTEGER NOT NULL,
	time_us INTEGER NOT NULL,
	avg_check REAL NOT NULL,
	caller_pct REAL NOT NULL,
	total_pct REAL NOT NULL,
	raw_line TEXT NOT NULL,
	source_file TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_module_profile_module ON module_profile_metrics (module);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	return db.RunScript(cfg.DBPath, []byte("CREATE INDEX IF NOT EXISTS idx_module_profile_run_id ON module_profile_metrics (run_id);"))
}

func EnsureSystemProfiles(cfg config.Config) error {
	if err := recreateIncompatibleTable(cfg.DBPath, "system_profiles", []string{"run_id", "fp", "fn"}, nil); err != nil {
		return err
	}
	script := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS system_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	avg_cpu REAL NOT NULL,
	avg_mem_mb REAL NOT NULL,
	fp REAL NOT NULL DEFAULT 0,
	fn REAL NOT NULL DEFAULT 0,
	samples INTEGER NOT NULL,
	created_at TEXT NOT NULL
);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	return db.RunScript(cfg.DBPath, []byte("CREATE INDEX IF NOT EXISTS idx_system_profiles_run_id ON system_profiles (run_id);"))
}

func EnsureRules(cfg config.Config) error {
	if err := recreateIncompatibleTable(cfg.DBPath, "rules", []string{"run_id"}, []string{"id"}); err != nil {
		return err
	}
	script := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS rules (
	run_id INTEGER NOT NULL DEFAULT 0,
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
	raw_text TEXT NOT NULL,
	created_at TEXT NOT NULL,
	PRIMARY KEY (run_id, gid, sid)
);
CREATE INDEX IF NOT EXISTS idx_rules_sid ON rules (sid);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	return db.RunScript(cfg.DBPath, []byte(`
CREATE INDEX IF NOT EXISTS idx_rules_run_id ON rules (run_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_run_source_raw ON rules (run_id, source_file, raw_text);
`))
}

func recreateIncompatibleTable(dbPath, table string, requiredColumns, forbiddenColumns []string) error {
	exists, err := tableExists(dbPath, table)
	if err != nil || !exists {
		return err
	}
	columns, err := tableColumns(dbPath, table)
	if err != nil {
		return err
	}
	for _, column := range requiredColumns {
		if !columns[column] {
			return dropTable(dbPath, table)
		}
	}
	for _, column := range forbiddenColumns {
		if columns[column] {
			return dropTable(dbPath, table)
		}
	}
	return nil
}

func tableColumns(dbPath, table string) (map[string]bool, error) {
	rows, err := db.QueryJSON(dbPath, "PRAGMA table_info("+table+");")
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(rows))
	for _, row := range rows {
		name, _ := row["name"].(string)
		if name != "" {
			out[name] = true
		}
	}
	return out, nil
}

func dropTable(dbPath, table string) error {
	return db.RunScript(dbPath, []byte("DROP TABLE IF EXISTS "+table+";"))
}

func Reset(cfg config.Config) error {
	for _, path := range []string{cfg.DBPath, cfg.DBPath + "-wal", cfg.DBPath + "-shm"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func CountTables(cfg config.Config) (map[string]TableCount, error) {
	tables := []string{
		"alerts",
		"rules",
		"profiler_metrics",
		"rule_profiler_metrics",
		"module_profile_metrics",
		"system_profiles",
	}
	out := make(map[string]TableCount, len(tables))
	for _, table := range tables {
		exists, err := tableExists(cfg.DBPath, table)
		if err != nil {
			return nil, err
		}
		if !exists {
			out[table] = TableCount{}
			continue
		}
		total, err := countTable(cfg.DBPath, table, "")
		if err != nil {
			return nil, err
		}
		run, err := countTable(cfg.DBPath, table, fmt.Sprintf("run_id = %d", cfg.RunID))
		if err != nil {
			return nil, err
		}
		out[table] = TableCount{Total: total, Run: run}
	}
	return out, nil
}

func tableExists(dbPath, table string) (bool, error) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	rows, err := db.QueryJSON(dbPath, "SELECT name FROM sqlite_master WHERE type = 'table' AND name = "+db.Quote(table)+";")
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

func countTable(dbPath, table, where string) (int64, error) {
	query := fmt.Sprintf("SELECT count(*) AS count FROM %s", table)
	if where != "" {
		query += " WHERE " + where
	}
	query += ";"
	rows, err := db.QueryJSON(dbPath, query)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return asInt(rows[0]["count"]), nil
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}
