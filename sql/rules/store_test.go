package rules

import (
	"path/filepath"
	"testing"

	"snort-optimizer/sql/config"
	"snort-optimizer/types"
)

func TestListUsesConfigRunIDByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath: filepath.Join(dir, "snort.sqlite"),
		RunID:  7,
	}
	record := types.Rule{
		SID:     222,
		GID:     1,
		Rev:     1,
		Action:  "alert",
		Proto:   "tcp",
		Enabled: true,
		RawText: `alert tcp any any -> any any (msg:"test"; sid:222; rev:1;)`,
	}
	if err := InsertBatch(cfg, []types.Rule{record}); err != nil {
		t.Fatal(err)
	}
	got, err := List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one rule for config run id, got %d", len(got))
	}
	if got[0].RunID != 7 {
		t.Fatalf("expected run id 7, got %d", got[0].RunID)
	}
}

func TestSetEnabledFiltersByConfigRunID(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath: filepath.Join(dir, "snort.sqlite"),
		RunID:  7,
	}
	record := types.Rule{
		SID:     222,
		GID:     1,
		Rev:     1,
		Action:  "alert",
		Proto:   "tcp",
		Enabled: true,
		RawText: `alert tcp any any -> any any (msg:"test"; sid:222; rev:1;)`,
	}
	if err := InsertBatch(cfg, []types.Rule{record}); err != nil {
		t.Fatal(err)
	}
	got, err := List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one rule, got %d", len(got))
	}
	wrongRun := cfg
	wrongRun.RunID = 8
	if err := SetEnabled(wrongRun, 1, 222, false); err != nil {
		t.Fatal(err)
	}
	got, err = List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Enabled {
		t.Fatalf("expected run-id 8 update not to affect run-id 7 rule")
	}

	if err := SetEnabled(cfg, 1, 222, false); err != nil {
		t.Fatal(err)
	}
	got, err = List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Enabled {
		t.Fatalf("expected run-id 7 update to disable run-id 7 rule")
	}
}

func TestInsertBatchUsesRunGIDSIDPrimaryKey(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath: filepath.Join(dir, "snort.sqlite"),
		RunID:  7,
	}
	first := types.Rule{
		SID:     222,
		GID:     1,
		Rev:     1,
		Action:  "alert",
		Proto:   "tcp",
		Enabled: true,
		RawText: `alert tcp any any -> any any (msg:"first"; sid:222; rev:1;)`,
	}
	second := first
	second.Rev = 2
	second.RawText = `alert tcp any any -> any any (msg:"second"; sid:222; rev:2;)`
	if err := InsertBatch(cfg, []types.Rule{first, second}); err != nil {
		t.Fatal(err)
	}
	got, err := List(cfg, Query{GID: 1, SID: 222, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one rule for run/gid/sid primary key, got %d", len(got))
	}
	if got[0].Rev != 1 {
		t.Fatalf("expected first rev to be kept, got %d", got[0].Rev)
	}

	nextRun := cfg
	nextRun.RunID = 8
	if err := InsertBatch(nextRun, []types.Rule{second}); err != nil {
		t.Fatal(err)
	}
	got, err = List(nextRun, Query{GID: 1, SID: 222, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Rev != 2 {
		t.Fatalf("expected same gid/sid to be allowed in another run, got %#v", got)
	}
}
