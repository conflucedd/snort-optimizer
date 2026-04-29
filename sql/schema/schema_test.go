package schema

import (
	"path/filepath"
	"testing"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
)

func TestEnsureMigratesProfilerRunIDColumns(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "snort.sqlite")}
	if err := db.RunScript(cfg.DBPath, []byte(`
CREATE TABLE profiler_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	section TEXT NOT NULL,
	module TEXT NOT NULL,
	metric TEXT NOT NULL,
	value REAL NOT NULL,
	raw_line TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE rule_profiler_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
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
	created_at TEXT NOT NULL
);
CREATE TABLE module_profile_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	rank INTEGER NOT NULL,
	module TEXT NOT NULL,
	layer TEXT NOT NULL,
	checks INTEGER NOT NULL,
	time_us INTEGER NOT NULL,
	avg_check REAL NOT NULL,
	caller_pct REAL NOT NULL,
	total_pct REAL NOT NULL,
	raw_line TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE system_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	avg_cpu REAL NOT NULL,
	avg_mem_mb REAL NOT NULL,
	samples INTEGER NOT NULL,
	created_at TEXT NOT NULL
);
`)); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"profiler_metrics", "rule_profiler_metrics", "module_profile_metrics", "system_profiles"} {
		if !hasColumn(t, cfg.DBPath, table, "run_id") {
			t.Fatalf("expected %s to have run_id after migration", table)
		}
	}
}

func TestEnsureMigratesRulesToRunGIDSIDPrimaryKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "snort.sqlite")}
	if err := db.RunScript(cfg.DBPath, []byte(`
CREATE TABLE rules (
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
INSERT INTO rules (run_id, sid, gid, rev, enabled, raw_text, created_at)
VALUES
	(7, 222, 1, 1, 1, 'first', 'now'),
	(7, 222, 1, 2, 0, 'second', 'now'),
	(8, 222, 1, 2, 1, 'third', 'now');
`)); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	if hasColumn(t, cfg.DBPath, "rules", "id") {
		t.Fatalf("expected rules.id to be removed")
	}
	wantPK := map[string]int64{"run_id": 1, "gid": 2, "sid": 3}
	for column, want := range wantPK {
		if got := columnPK(t, cfg.DBPath, "rules", column); got != want {
			t.Fatalf("expected rules.%s pk ordinal %d, got %d", column, want, got)
		}
	}
	rows, err := db.QueryJSON(cfg.DBPath, "SELECT run_id, gid, sid, rev FROM rules ORDER BY run_id;")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected duplicate run/gid/sid rows to be deduplicated, got %d", len(rows))
	}
}

func hasColumn(t *testing.T, dbPath, table, column string) bool {
	t.Helper()
	rows, err := db.QueryJSON(dbPath, "PRAGMA table_info("+table+");")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["name"] == column {
			return true
		}
	}
	return false
}

func columnPK(t *testing.T, dbPath, table, column string) int64 {
	t.Helper()
	rows, err := db.QueryJSON(dbPath, "PRAGMA table_info("+table+");")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["name"] == column {
			return asInt(row["pk"])
		}
	}
	return 0
}
