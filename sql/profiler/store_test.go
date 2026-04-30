package profiler

import (
	"path/filepath"
	"testing"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
	"snort-optimizer/types"
)

func TestProfilerUsesConfigRunIDByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath: filepath.Join(dir, "snort.sqlite"),
		RunID:  7,
	}
	if err := InsertBatch(cfg, []types.ProfilerMetric{
		{Section: "Packet Statistics", Metric: "packets", Value: 10, RawLine: "packets: 10"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRuleBatch(cfg, []types.RuleProfilerMetric{
		{GID: 1, SID: 222, Rev: 1, RawLine: "rule", RuleTimePct: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertModuleBatch(cfg, []types.ModuleProfileMetric{
		{Rank: 1, Module: "detection", Layer: "main", RawLine: "module"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertSystemProfile(cfg, types.SystemProfile{AvgCPU: 1, AvgMemMB: 2, FP: 4, FN: 5, Samples: 3}); err != nil {
		t.Fatal(err)
	}

	got, err := List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one generic profiler metric for config run id, got %d", len(got))
	}
	if got[0].RunID != 7 {
		t.Fatalf("expected generic profiler run id 7, got %d", got[0].RunID)
	}

	for _, table := range []string{"rule_profiler_metrics", "module_profile_metrics", "system_profiles"} {
		rows, err := db.QueryJSON(cfg.DBPath, "SELECT run_id FROM "+table+";")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected one row in %s, got %d", table, len(rows))
		}
		if asInt(rows[0]["run_id"]) != 7 {
			t.Fatalf("expected %s run id 7, got %d", table, asInt(rows[0]["run_id"]))
		}
	}
	rows, err := db.QueryJSON(cfg.DBPath, "SELECT fp, fn FROM system_profiles;")
	if err != nil {
		t.Fatal(err)
	}
	if asFloat(rows[0]["fp"]) != 4 || asFloat(rows[0]["fn"]) != 5 {
		t.Fatalf("expected system profile fp/fn 4/5, got %#v", rows[0])
	}
}
