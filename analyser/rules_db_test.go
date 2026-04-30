package analyser

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestListRulesFromDBFiltersRunIDZero(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "raw.sqlite")
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Exec(`CREATE TABLE rules (
run_id INTEGER NOT NULL,
sid INTEGER NOT NULL,
gid INTEGER NOT NULL,
rev INTEGER,
enabled INTEGER NOT NULL,
source_file TEXT,
raw_text TEXT NOT NULL
);
INSERT INTO rules (run_id, sid, gid, rev, enabled, source_file, raw_text)
VALUES
(0, 1001, 1, 1, 1, 'snort3-file-test.rules', 'alert tcp any any -> any any (sid:1001;)'),
(1, 1002, 1, 1, 1, 'snort3-browser-test.rules', 'alert tcp any any -> any any (sid:1002;)');`)
	if err != nil {
		t.Fatal(err)
	}

	rules, err := listRulesFromDB(dbPath, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
	if rules[0].SID != 1001 {
		t.Fatalf("SID = %d, want 1001", rules[0].SID)
	}
}
