package sql

import (
	dbsql "database/sql"
	"path/filepath"
	"testing"
)

func TestUpdateSystemProfileFPFNUpdatesRunRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snort.sqlite")
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE system_profiles (
id INTEGER PRIMARY KEY AUTOINCREMENT,
run_id INTEGER NOT NULL,
avg_cpu REAL NOT NULL,
avg_mem_mb REAL NOT NULL,
fp REAL NOT NULL DEFAULT 0,
fn REAL NOT NULL DEFAULT 0,
samples INTEGER NOT NULL,
created_at TEXT NOT NULL
);
INSERT INTO system_profiles (run_id, avg_cpu, avg_mem_mb, fp, fn, samples, created_at) VALUES
(4, 1, 2, 0, 0, 3, 'now'),
(5, 1, 2, 0, 0, 3, 'now');`)
	if err != nil {
		t.Fatal(err)
	}

	if err := UpdateSystemProfileFPFN(dbPath, 4, 12, 7); err != nil {
		t.Fatal(err)
	}

	var fp, fn float64
	if err := conn.QueryRow("SELECT fp, fn FROM system_profiles WHERE run_id = 4;").Scan(&fp, &fn); err != nil {
		t.Fatal(err)
	}
	if fp != 12 || fn != 7 {
		t.Fatalf("run 4 fp/fn = %g/%g, want 12/7", fp, fn)
	}
	if err := conn.QueryRow("SELECT fp, fn FROM system_profiles WHERE run_id = 5;").Scan(&fp, &fn); err != nil {
		t.Fatal(err)
	}
	if fp != 0 || fn != 0 {
		t.Fatalf("run 5 fp/fn = %g/%g, want 0/0", fp, fn)
	}
}

func TestRefreshSystemProfileFPFNUsesFlowEvaluation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snort.sqlite")
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE system_profiles (
id INTEGER PRIMARY KEY AUTOINCREMENT,
run_id INTEGER NOT NULL,
avg_cpu REAL NOT NULL,
avg_mem_mb REAL NOT NULL,
fp REAL NOT NULL DEFAULT 0,
fn REAL NOT NULL DEFAULT 0,
samples INTEGER NOT NULL,
created_at TEXT NOT NULL
);
CREATE TABLE alerts (
id INTEGER PRIMARY KEY AUTOINCREMENT,
run_id INTEGER NOT NULL,
timestamp TEXT,
proto TEXT,
src_ap TEXT,
dst_ap TEXT,
gid INTEGER,
sid INTEGER,
rev INTEGER
);
INSERT INTO system_profiles (run_id, avg_cpu, avg_mem_mb, fp, fn, samples, created_at) VALUES
(7, 1, 2, 0, 0, 3, 'now');
INSERT INTO alerts (run_id, timestamp, proto, src_ap, dst_ap, gid, sid, rev) VALUES
(7, '07/04-10:00:10.000000', 'TCP', '10.0.0.1:12345', '10.0.0.2:80', 1, 1001, 1);`)
	if err != nil {
		t.Fatal(err)
	}

	if err := RefreshSystemProfileFPFN(dbPath, 7, testFlowSet()); err != nil {
		t.Fatal(err)
	}

	var fp, fn float64
	if err := conn.QueryRow("SELECT fp, fn FROM system_profiles WHERE run_id = 7;").Scan(&fp, &fn); err != nil {
		t.Fatal(err)
	}
	if fp != 1 || fn != 1 {
		t.Fatalf("run 7 fp/fn = %g/%g, want 1/1", fp, fn)
	}
}
