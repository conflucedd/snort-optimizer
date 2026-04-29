# wrap

`wrap` is a smaller Snort runner module. It starts and stops Snort, manages rules through the shared `sql` package, writes `all.rules`, optionally captures Snort output, and optionally tails `alert_json.txt` into `snort.sqlite` while Snort runs.

## Package Layout

- `wrap`: public entry package with `NewRunner` and type aliases.
- `wrap/cmd`: CLI entrypoint. It starts Snort, waits for `SIGINT`/`SIGTERM`, then stops Snort.
- `wrap/runner`: process lifecycle, environment validation, Snort argument construction, and `sql` package integration.
- `sql`: shared SQLite schema, rule import/query/update, alert import/tail, and profiler import/query.
- `wrap/types`: wrap-specific types such as `Config`, `RunInfo`, and `Status`.
- `types`: shared domain types for rules, alerts, and profiler records.

## Shared Types vs wrap Types

The root `types` package is intentionally generic. It contains rule, alert, rule profiler, module profiler, and system profile records that other modules can reuse.

`wrap/types` contains objects that belong to the runner boundary, including runtime configuration and process status.

## Config

`wrap.Config` fields:

- `Mode`: `interface` or `pcap`.
- `SnortWorkingDir`: defaults to the current directory. Holds `snort.sqlite`, `all.rules`, optional `snort_output.txt`, and optional `alert_json.txt`.
- `SnortConfigPath`: Snort Lua config path. Relative paths are converted to absolute paths before Snort is started.
- `SnortDBPath`: SQLite database path. Defaults to `SnortWorkingDir/snort.sqlite`.
- `RawRulePath`: `.rules` file or directory used to initialize the rule table when the database does not exist. Defaults to `SnortWorkingDir/rules`.
- `Interface`: required when `Mode=interface`.
- `PcapFile`: required when `Mode=pcap`.
- `LuaOverrides`: additional `--lua` values. Each entry is passed as its own argument pair.
- `RunID`: run id written to alert, rule, profiler, and system profile records. Defaults to `0`.
- `NeedOutput`: when true, stdout/stderr are written to `snort_output.txt`.
- `NeedAlert`: when true, `alert_json = { file = true }` is injected and new alert lines are inserted into `snort.sqlite`.
- `NeedProfiler`: when true, stdout/stderr are written to `snort_output.txt`; after Snort exits, rule/module profiler data is imported and average CPU/RSS is inserted into `system_profiles`.
- `NoClean`: when true, keeps `alert_json.txt` after Snort exits. By default, `alert_json.txt` is removed after Snort exits and alert tailing has drained the final line.
All required runtime values must be supplied on each run. `wrap` does not load or save `wrap.db`.

`wrap` does not remove `alert_json.txt` at startup. When alert ingestion is enabled, an existing file is tailed from its current end before Snort starts; if the file does not exist yet, ingestion waits for Snort to create it and then reads from the beginning.

## Runner Interface

`Runner` supports:

- `Start()`: validates environment, initializes `snort.sqlite` if missing, imports rules from `RawRulePath` only when the database does not exist, regenerates `all.rules`, starts Snort in a separate process group, and records PID/PGID.
- `Stop()`: terminates the Snort process group and stops the alert tail goroutine.
- `Restart()`: `Stop()` then `Start()`.
- `Reset()`: deletes `snort.sqlite` and its WAL/SHM files; the next `Start()` rebuilds it from `RawRulePath`.
- `EnableRule(ruleID int64)` and `DisableRule(ruleID int64)`: update `rules.enabled` by database primary key `id`.
- `Status()`: returns `RunInfo` with `PID`, `PGID`, `Running`, and `StartTime`, plus the effective config.

## Module Example

```go
package main

import "snort-optimizer/wrap"

func main() {
	r, err := wrap.NewRunner(wrap.Config{
		Mode:            wrap.ModePCAP,
		SnortWorkingDir: "/tmp/snort-work",
		SnortConfigPath: "/home/c/snort-optimizer/wrap/config/snort.lua",
		RawRulePath:     "/tmp/snort-work/rules",
		RunID:           1,
		PcapFile:        "/tmp/sample.pcap",
		NeedOutput:      true,
		NeedAlert:       true,
		NeedProfiler:    true,
	})
	if err != nil {
		panic(err)
	}
	if err := r.Start(); err != nil {
		panic(err)
	}
	defer r.Stop()
	_ = r.Status()
}
```

## CLI Example

```sh
SNORT_DIR=/home/c/snort-optimizer/wrap/snort/build/src \
DAQ_DIR=/home/c/snort-optimizer/wrap/snort/libdaq/build/lib/daq \
go run ./wrap/cmd \
  --swd /tmp/snort-work \
  --pcap /tmp/sample.pcap \
  --config /home/c/snort-optimizer/wrap/config/snort.lua \
  --raw-rule-path /tmp/snort-work/rules \
  --run-id 1 \
  --need-output \
  --need-alert \
  --need-profiler \
  --lua 'search_engine = { search_method = "hyperscan" }'
```

The CLI only accepts long options such as `--pcap`; single-dash forms are rejected.

## Limits and Assumptions

- Linux only.
- `SNORT_DIR` must point to a directory containing an executable `snort` file.
- `DAQ_DIR` must point to an existing DAQ directory.
- The shared `sql` package uses the Go SQLite driver; the wrapper no longer depends on the old `wrap/sqliteutil` path for runtime storage.
- Rule parsing is intentionally shallow. It extracts common header fields and `msg`, `classtype`, `sid`, `gid`, and `rev`; the original rule is preserved in `raw_text`.
- Empty and commented rule lines are ignored. A bad rule line is logged and skipped.
- Alert ingestion tails `alert_json.txt` from the end when it already exists, or from the beginning when Snort creates it after startup. On shutdown, the tailer drains remaining alert lines before default cleanup removes `alert_json.txt`.
