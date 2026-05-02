package safe

import (
	"context"
	dbsql "database/sql"
	"path/filepath"
	"testing"

	"snort-optimizer/analyser/types"

	_ "modernc.org/sqlite"
)

func TestOrphanFlowbitsTrimsRulesWithoutProviders(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "snort.sqlite")
	conn, err := dbsql.Open("sqlite", dbPath)
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
msg TEXT,
raw_text TEXT NOT NULL
);
INSERT INTO rules (run_id, sid, gid, rev, enabled, source_file, msg, raw_text) VALUES
(0, 1001, 1, 1, 1, 'a.rules', 'provider', 'alert tcp any any -> any any (flowbits:set,seen.foo; flowbits:noalert; sid:1001;)'),
(0, 1002, 1, 1, 1, 'a.rules', 'satisfied', 'alert tcp any any -> any any (flowbits:isset,seen.foo; sid:1002;)'),
(0, 1003, 1, 1, 1, 'a.rules', 'orphan', 'alert tcp any any -> any any (flowbits:isset,missing.foo; sid:1003;)'),
(0, 1004, 1, 1, 1, 'a.rules', 'negative only', 'alert tcp any any -> any any (flowbits:isnotset,missing.bar; sid:1004;)');`)
	if err != nil {
		t.Fatal(err)
	}

	got, err := OrphanFlowbitsFunc(context.Background(), types.FunctionInput{
		ExpDBPath:   dbPath,
		SourceRunID: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1", len(got))
	}
	if got[0].SID != 1003 {
		t.Fatalf("SID = %d, want 1003", got[0].SID)
	}
}
