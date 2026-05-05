package api

import (
	"path/filepath"
	"testing"
)

func TestCopyRulesBetweenDBsUsesAbsoluteAttachPath(t *testing.T) {
	dir := t.TempDir()
	sourceDB := filepath.Join(dir, "source.sqlite")
	targetDB := filepath.Join(dir, "nested", "target.sqlite")
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	sourceRel, err := filepath.Rel(cwd, sourceDB)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := sqlOpen(sourceDB)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(`
CREATE TABLE rules (
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
INSERT INTO rules (run_id, sid, gid, rev, action, proto, msg, classtype, enabled, source_file, raw_text, created_at)
VALUES (0, 1001, 1, 1, 'alert', 'tcp', 'test rule', 'attempted-admin', 1, 'test.rules', 'alert tcp any any -> any any (sid:1001;)', datetime('now'));
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if err := copyRulesBetweenDBs(sourceRel, targetDB, 0, 42); err != nil {
		t.Fatal(err)
	}

	target, err := sqlOpen(targetDB)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	var count int64
	if err := target.QueryRow("SELECT count(*) FROM rules WHERE run_id = 42;").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("copied %d rules, want 1", count)
	}
}
