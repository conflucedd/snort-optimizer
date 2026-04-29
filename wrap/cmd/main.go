package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"snort-optimizer/wrap"
	"syscall"
	"time"
)

type luaFlags []string

func (f *luaFlags) String() string {
	return fmt.Sprint([]string(*f))
}

func (f *luaFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	var lua luaFlags
	var cfg wrap.Config
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage of %s:\n", os.Args[0])
		fs.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(fs.Output(), "  --%s\n\t%s", f.Name, f.Usage)
			if f.DefValue != "" && f.DefValue != "false" {
				fmt.Fprintf(fs.Output(), " (default %q)", f.DefValue)
			}
			fmt.Fprintln(fs.Output())
		})
	}
	fs.StringVar(&cfg.SnortWorkingDir, "swd", ".", "Snort working directory")
	fs.StringVar(&cfg.Interface, "iface", "", "Network interface for interface mode")
	fs.StringVar(&cfg.PcapFile, "pcap", "", "Pcap file for pcap mode")
	fs.StringVar(&cfg.SnortConfigPath, "config", "", "Snort Lua config path")
	fs.StringVar(&cfg.RawRulePath, "raw-rule-path", "", "Raw rule file or directory used to initialize the rule table")
	fs.StringVar(&cfg.SnortDBPath, "snort-db-path", "", "Snort SQLite database path")
	fs.Var(&lua, "lua", "Additional Snort --lua override; may be repeated")
	fs.Int64Var(&cfg.RunID, "run-id", 0, "Run id written to alerts, rules, profiler, and system profile records")
	fs.BoolVar(&cfg.NeedOutput, "need-output", false, "Write Snort stdout/stderr to snort_output.txt")
	fs.BoolVar(&cfg.NeedAlert, "need-alert", false, "Enable alert_json file output and ingest snort.sqlite")
	fs.BoolVar(&cfg.NeedProfiler, "need-profiler", false, "Write Snort output and import rule/module/system profiler data")
	fs.BoolVar(&cfg.NoClean, "noclean", false, "Keep alert_json.txt after Snort exits")
	if err := rejectSingleDashArgs(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(2)
	}
	fs.Parse(os.Args[1:])
	cfg.LuaOverrides = lua

	r, err := wrap.NewRunner(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create runner: %v\n", err)
		os.Exit(1)
	}
	if err := r.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start snort: %v\n", err)
		os.Exit(1)
	}
	status := r.Status()
	printStartupStats(os.Stderr, status, r.StartupStats())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sigCh:
			if err := r.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "stop snort: %v\n", err)
				os.Exit(1)
			}
			return
		case <-ticker.C:
			if !r.Status().RunInfo.Running {
				return
			}
		}
	}
}

func printStartupStats(out *os.File, status wrap.Status, stats wrap.StartupStats) {
	fmt.Fprintf(out, "snort started pid=%d pgid=%d\n", status.RunInfo.PID, status.RunInfo.PGID)
	fmt.Fprintf(out, "run id: %d\n", stats.RunID)
	fmt.Fprintf(out, "mode: %s\n", stats.Mode)
	if status.Config.PcapFile != "" {
		fmt.Fprintf(out, "pcap: %s\n", status.Config.PcapFile)
	}
	if status.Config.Interface != "" {
		fmt.Fprintf(out, "iface: %s\n", status.Config.Interface)
	}
	fmt.Fprintf(out, "swd: %s\n", stats.SnortWorkingDir)
	fmt.Fprintf(out, "config: %s\n", stats.SnortConfigPath)
	fmt.Fprintf(out, "database: %s\n", stats.SnortDBPath)
	fmt.Fprintf(out, "raw rules: %s\n", stats.RawRulePath)
	fmt.Fprintf(out, "all.rules: %s (%d enabled rules loaded)\n", stats.AllRulesPath, stats.LoadedRuleCount)
	fmt.Fprintf(out, "features: need-output=%t need-alert=%t need-profiler=%t\n", stats.NeedOutput, stats.NeedAlert, stats.NeedProfiler)
	fmt.Fprintln(out, "database counts: table total/run")
	for _, table := range []string{"rules", "alerts", "profiler_metrics", "rule_profiler_metrics", "module_profile_metrics", "system_profiles"} {
		count := stats.TableCounts[table]
		fmt.Fprintf(out, "  %s %d/%d\n", table, count.Total, count.Run)
	}
}

func rejectSingleDashArgs(args []string) error {
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' && (len(arg) == 2 || arg[1] != '-') {
			return fmt.Errorf("single-dash argument %q is not supported; use --%s", arg, arg[1:])
		}
	}
	return nil
}
