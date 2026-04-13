# wrap2

`wrap2` is a smaller Snort runner module. It starts and stops Snort, manages `rules.db` and `all.rules`, optionally captures Snort output, and optionally tails `alert_json.txt` into `alerts.db` while Snort runs.

## Package Layout

- `wrap2`: public entry package with `NewRunner` and type aliases.
- `wrap2/cmd`: CLI entrypoint. It starts Snort, waits for `SIGINT`/`SIGTERM`, then stops Snort.
- `wrap2/runner`: process lifecycle, environment validation, Snort argument construction.
- `wrap2/rules`: rule file parsing, `rules.db` initialization, rule enable/disable, `all.rules` generation.
- `wrap2/alerts`: `alerts.db` schema, alert JSON parsing, and simple file tail logic.
- `wrap2/types`: wrap2-specific types such as `Config`, `RunInfo`, and `Status`.
- `types`: shared domain types for rules and alerts only.
- `wrap2/sqliteutil`: small SQLite CLI helper that executes direct SQL through `sqlite3`.

## Shared Types vs wrap2 Types

The root `types` package is intentionally generic. It currently contains only rule and alert records that other modules can reuse.

`wrap2/types` contains objects that belong to the runner boundary, including runtime configuration and process status.

## Config

`wrap2.Config` fields:

- `Mode`: `interface` or `pcap`.
- `SnortWorkingDir`: required. Holds `rules.db`, `all.rules`, optional `snort_output.txt`, optional `alert_json.txt`, and optional `alerts.db`.
- `SnortConfigPath`: Snort Lua config path. Relative paths are converted to absolute paths before Snort is started.
- `Interface`: required when `Mode=interface`.
- `PcapFile`: required when `Mode=pcap`.
- `LuaOverrides`: additional `--lua` values. Each entry is passed as its own argument pair.
- `NeedOutput`: when true, stdout/stderr are written to `snort_output.txt`.
- `NeedAlert`: when true, `alert_json = { file = true }` is injected, `alert_json.txt` is removed before start, and new alert lines are inserted into `alerts.db`.
All required runtime values must be supplied on each run. `wrap2` does not load or save `wrap.db`.

## Runner Interface

`Runner` supports:

- `Start()`: validates environment, initializes `rules.db` if needed, regenerates `all.rules`, starts Snort in a separate process group, and records PID/PGID.
- `Stop()`: terminates the Snort process group and stops the alert tail goroutine.
- `Restart()`: `Stop()` then `Start()`.
- `Reset()`: deletes `rules.db`; the next `Start()` rebuilds it from `SnortWorkingDir/rules/*.rules`.
- `EnableRule(ruleID int64)` and `DisableRule(ruleID int64)`: update `rules.enabled` by database primary key `id`.
- `Status()`: returns `RunInfo` with `PID`, `PGID`, `Running`, and `StartTime`, plus the effective config.

## Module Example

```go
package main

import "snort-optimizer/wrap2"

func main() {
	r, err := wrap2.NewRunner(wrap2.Config{
		Mode:            wrap2.ModePCAP,
		SnortWorkingDir: "/tmp/snort-work",
		SnortConfigPath: "/home/c/snort-optimizer/wrap/config/snort.lua",
		PcapFile:        "/tmp/sample.pcap",
		NeedOutput:      true,
		NeedAlert:       true,
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
go run ./wrap2/cmd \
  --swd /tmp/snort-work \
  --mode pcap \
  --pcap /tmp/sample.pcap \
  --config /home/c/snort-optimizer/wrap/config/snort.lua \
  --need-output \
  --need-alert \
  --lua 'search_engine = { search_method = "hyperscan" }'
```

## Limits and Assumptions

- Linux only.
- `SNORT_DIR` must point to a directory containing an executable `snort` file.
- `DAQ_DIR` must point to an existing DAQ directory.
- `sqlite3` CLI must be available.
- Rule parsing is intentionally shallow. It extracts common header fields and `msg`, `classtype`, `sid`, `gid`, and `rev`; the original rule is preserved in `raw_text`.
- Empty and commented rule lines are ignored. A bad rule line is logged and skipped.
- Alert ingestion tails the `alert_json.txt` file created for the current run. `alert_json.txt` is removed before each start; crash/restart file-reopen continuity is intentionally not handled.
