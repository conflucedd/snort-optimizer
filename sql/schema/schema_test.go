package schema

import (
	"path/filepath"
	"testing"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
)

func TestEnsureCreatesCurrentTables(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "snort.sqlite")}
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"profiler_metrics", "rule_profiler_metrics", "module_profile_metrics", "system_profiles"} {
		if !hasColumn(t, cfg.DBPath, table, "run_id") {
			t.Fatalf("expected %s to have run_id", table)
		}
	}
	if !hasColumn(t, cfg.DBPath, "system_profiles", "fp") {
		t.Fatalf("expected system_profiles to have fp")
	}
	if !hasColumn(t, cfg.DBPath, "system_profiles", "fn") {
		t.Fatalf("expected system_profiles to have fn")
	}
}

func TestEnsureRulesUsesRunGIDSIDPrimaryKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "snort.sqlite")}
	if err := EnsureRules(cfg); err != nil {
		t.Fatal(err)
	}
	if hasColumn(t, cfg.DBPath, "rules", "id") {
		t.Fatalf("expected rules.id not to exist")
	}
	wantPK := map[string]int64{"run_id": 1, "gid": 2, "sid": 3}
	for column, want := range wantPK {
		if got := columnPK(t, cfg.DBPath, "rules", column); got != want {
			t.Fatalf("expected rules.%s pk ordinal %d, got %d", column, want, got)
		}
	}
}

func TestEnsureRulesOnlyCreatesRulesTable(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "snort.sqlite")}
	if err := EnsureRules(cfg); err != nil {
		t.Fatal(err)
	}
	if !tableExistsForTest(t, cfg.DBPath, "rules") {
		t.Fatalf("expected rules table to exist")
	}
	for _, table := range []string{"alerts", "profiler_metrics", "rule_profiler_metrics", "module_profile_metrics", "system_profiles"} {
		if tableExistsForTest(t, cfg.DBPath, table) {
			t.Fatalf("expected %s table not to be created by EnsureRules", table)
		}
	}
}

func TestEnsureDropsIncompatibleOldTables(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{DBPath: filepath.Join(dir, "snort.sqlite")}
	if err := db.RunScript(cfg.DBPath, []byte(`
CREATE TABLE alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	raw_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);
INSERT INTO alerts (raw_json, created_at) VALUES ('{}', 'old');
CREATE TABLE system_profiles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	avg_cpu REAL NOT NULL,
	avg_mem_mb REAL NOT NULL,
	samples INTEGER NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id INTEGER NOT NULL DEFAULT 0,
	sid INTEGER NOT NULL,
	gid INTEGER NOT NULL DEFAULT 1,
	raw_text TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`)); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	if !hasColumn(t, cfg.DBPath, "alerts", "run_id") {
		t.Fatalf("expected alerts to be recreated with run_id")
	}
	if !hasColumn(t, cfg.DBPath, "system_profiles", "fp") || !hasColumn(t, cfg.DBPath, "system_profiles", "fn") {
		t.Fatalf("expected system_profiles to be recreated with fp/fn")
	}
	if hasColumn(t, cfg.DBPath, "rules", "id") {
		t.Fatalf("expected incompatible rules table to be recreated without id")
	}
	rows, err := db.QueryJSON(cfg.DBPath, "SELECT count(*) AS count FROM alerts;")
	if err != nil {
		t.Fatal(err)
	}
	if asInt(rows[0]["count"]) != 0 {
		t.Fatalf("expected incompatible old alerts data to be discarded")
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

func tableExistsForTest(t *testing.T, dbPath, table string) bool {
	t.Helper()
	rows, err := db.QueryJSON(dbPath, "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '"+table+"';")
	if err != nil {
		t.Fatal(err)
	}
	return len(rows) > 0
}
