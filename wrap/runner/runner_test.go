package runner

import (
	"os"
	"path/filepath"
	"testing"

	wraptypes "snort-optimizer/wrap/types"
)

func TestSnortArgsNeedProfilerOverridesProfiler(t *testing.T) {
	r := &Runner{
		cfg: wraptypes.Config{
			Mode:            wraptypes.ModePCAP,
			SnortConfigPath: "/tmp/snort.lua",
			SnortWorkingDir: "/tmp",
			PcapFile:        "/tmp/input.pcap",
			NeedProfiler:    true,
		},
	}

	args := r.snortArgs("/tmp/daq")
	if !hasLuaOverride(args, "profiler = {}") {
		t.Fatalf("expected profiler lua override in args: %#v", args)
	}
}

func TestSnortArgsNeedAlertOverridesAlertJSON(t *testing.T) {
	r := &Runner{
		cfg: wraptypes.Config{
			Mode:            wraptypes.ModePCAP,
			SnortConfigPath: "/tmp/snort.lua",
			SnortWorkingDir: "/tmp",
			PcapFile:        "/tmp/input.pcap",
			NeedAlert:       true,
		},
	}

	args := r.snortArgs("/tmp/daq")
	if !hasLuaOverride(args, "alert_json = { file = true }") {
		t.Fatalf("expected alert_json lua override in args: %#v", args)
	}
}

func hasLuaOverride(args []string, override string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--lua" && args[i+1] == override {
			return true
		}
	}
	return false
}

func TestResolveSnortEnvUsesProcessEnvironment(t *testing.T) {
	t.Setenv("SNORT_DIR", "")
	t.Setenv("DAQ_DIR", "")
	dir := t.TempDir()
	snortDir := filepath.Join(dir, "snort-bin")
	daqDir := filepath.Join(dir, "daq")
	if err := os.MkdirAll(snortDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(daqDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snortDir, "snort"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SNORT_DIR", snortDir)
	t.Setenv("DAQ_DIR", daqDir)

	gotSnort, gotDAQ, err := resolveSnortEnv()
	if err != nil {
		t.Fatal(err)
	}
	if gotSnort != filepath.Join(snortDir, "snort") {
		t.Fatalf("snort path = %q, want %q", gotSnort, filepath.Join(snortDir, "snort"))
	}
	if gotDAQ != daqDir {
		t.Fatalf("daq path = %q, want %q", gotDAQ, daqDir)
	}
}

func TestResolveSnortEnvReadsDotEnvFile(t *testing.T) {
	t.Setenv("SNORT_DIR", "")
	t.Setenv("DAQ_DIR", "")
	dir := t.TempDir()
	snortDir := filepath.Join(dir, "custom", "snort-bin")
	daqDir := filepath.Join(dir, "custom", "daq")
	if err := os.MkdirAll(snortDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(daqDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snortDir, "snort"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SNORT_DIR=custom/snort-bin\nDAQ_DIR=custom/daq\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	gotSnort, gotDAQ, err := resolveSnortEnv()
	if err != nil {
		t.Fatal(err)
	}
	if gotSnort != filepath.Join(snortDir, "snort") {
		t.Fatalf("snort path = %q, want %q", gotSnort, filepath.Join(snortDir, "snort"))
	}
	if gotDAQ != daqDir {
		t.Fatalf("daq path = %q, want %q", gotDAQ, daqDir)
	}
}
