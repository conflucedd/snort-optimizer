package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"snort-optimizer/analyser"
	atypes "snort-optimizer/analyser/types"
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
	var cfg atypes.Config
	var lua luaFlags
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage of %s:\n", os.Args[0])
		fs.VisitAll(func(f *flag.Flag) {
			fmt.Fprintf(fs.Output(), "  --%s\n\t%s", f.Name, f.Usage)
			if f.DefValue != "" {
				fmt.Fprintf(fs.Output(), " (default %q)", f.DefValue)
			}
			fmt.Fprintln(fs.Output())
		})
	}
	fs.StringVar(&cfg.Pcap1, "pcap1", "", "Experiment pcap used for flow-level false positive and miss-rate evaluation")
	fs.StringVar(&cfg.DB1, "db1", "", "Flow label sqlite db for --pcap1")
	fs.StringVar(&cfg.Pcap2, "pcap2", "", "Real business pcap used for performance profiling")
	fs.StringVar(&cfg.AnalyserWorkingDir, "workdir", "analyser-work", "Analyser working directory")
	fs.StringVar(&cfg.SnortConfig, "config", "", "Snort Lua config path")
	fs.StringVar(&cfg.RawSnortSQLite, "raw-snort-sqlite", "", "Original snort.sqlite; only rules with run_id=0 are copied")
	fs.StringVar(&cfg.RawRulePath, "raw-rule-path", "", "Raw rule file or directory fallback when --raw-snort-sqlite is not provided")
	fs.StringVar(&cfg.EmptyPcap, "empty-pcap", "", "Optional empty pcap path for load-time baseline")
	fs.Var(&lua, "lua", "Additional Snort --lua override; may be repeated")
	fs.IntVar(&cfg.MaxRound, "max-round", atypes.DefaultMaxRound, "Maximum iterative trim rounds")
	fs.Float64Var(&cfg.InitialFactor, "factor", atypes.DefaultInitialFactor, "Initial trim factor in [0,1]")
	fs.Float64Var(&cfg.MaxMissRateIncrease, "max-miss-increase", 0.01, "Maximum absolute miss-rate increase allowed for ITER commit")
	fs.Float64Var(&cfg.MaxFPRateIncrease, "max-fp-increase", 0.02, "Maximum absolute false-positive-rate increase allowed for ITER commit")
	fs.BoolVar(&cfg.PreserveWorkDBs, "preserve-work-dbs", false, "Skip startup deletion of the analyser working directory")
	if err := rejectSingleDashArgs(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(2)
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cfg.LuaOverrides = lua

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result, err := analyser.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyser: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
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
