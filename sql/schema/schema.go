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
CREATE INDEX IF NOT EXISTS idx_profiler_run_id ON profiler_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_profiler_section_module ON profiler_metrics (section, module);
CREATE INDEX IF NOT EXISTS idx_profiler_created_at ON profiler_metrics (created_at);

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
CREATE INDEX IF NOT EXISTS idx_rule_profiler_run_id ON rule_profiler_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_rule_profiler_rule ON rule_profiler_metrics (gid, sid, rev);

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
CREATE INDEX IF NOT EXISTS idx_module_profile_run_id ON module_profile_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_module_profile_module ON module_profile_metrics (module);

CREATE TABLE IF NOT EXISTS system_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	avg_cpu REAL NOT NULL,
	avg_mem_mb REAL NOT NULL,
	samples INTEGER NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_system_profiles_run_id ON system_profiles (run_id);

CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
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
	created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_run_source_raw ON rules (run_id, source_file, raw_text);
CREATE INDEX IF NOT EXISTS idx_rules_sid ON rules (sid);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
`
	if err := db.RunScript(cfg.DBPath, []byte(script)); err != nil {
		return err
	}
	migrations := []string{
		"ALTER TABLE alerts ADD COLUMN run_id INTEGER NOT NULL DEFAULT 0;",
		"ALTER TABLE rules ADD COLUMN run_id INTEGER NOT NULL DEFAULT 0;",
	}
	for _, migration := range migrations {
		if err := db.RunScript(cfg.DBPath, []byte(migration)); err != nil && !db.IsDuplicateColumn(err) {
			return err
		}
	}
	return db.RunScript(cfg.DBPath, []byte(`
DROP INDEX IF EXISTS idx_rules_source_raw;
CREATE INDEX IF NOT EXISTS idx_alerts_run_id ON alerts (run_id);
CREATE INDEX IF NOT EXISTS idx_rules_run_id ON rules (run_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_run_source_raw ON rules (run_id, source_file, raw_text);
`))
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
	if err := Ensure(cfg); err != nil {
		return nil, err
	}
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
