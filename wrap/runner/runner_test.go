package runner

import (
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
