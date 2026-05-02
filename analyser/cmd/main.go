package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"snort-optimizer/analyser"
	"snort-optimizer/analyser/iter"
	"snort-optimizer/analyser/safe"
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

type stringFlags []string

func (f *stringFlags) String() string {
	return fmt.Sprint([]string(*f))
}

func (f *stringFlags) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

type strategySpec struct {
	Name string
	Fn   atypes.RegisteredFunction
}

func main() {
	var cfg atypes.Config
	var lua luaFlags
	var enabledStrategies stringFlags
	var disabledStrategies stringFlags
	var listStrategies bool
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
	fs.Var(&enabledStrategies, "strategy", "Enable built-in strategy by name; repeat or comma-separate; default all; use none for baseline only")
	fs.Var(&disabledStrategies, "disable-strategy", "Disable built-in strategy by name; repeat or comma-separate")
	fs.BoolVar(&listStrategies, "list-strategies", false, "List built-in strategy names and exit")
	if err := rejectSingleDashArgs(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(2)
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if listStrategies {
		for _, name := range builtinStrategyNames() {
			fmt.Fprintln(os.Stdout, name)
		}
		return
	}
	cfg.LuaOverrides = lua

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	a, err := analyser.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyser: %v\n", err)
		os.Exit(1)
	}
	strategies, err := selectStrategies(enabledStrategies, disabledStrategies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "analyser: %v\n", err)
		os.Exit(2)
	}
	a.RegisterAll(strategies...)
	result, err := a.Run(ctx)
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

func builtinStrategies() []strategySpec {
	return []strategySpec{
		{Name: "safe_source_file_browser", Fn: safe.SourceFileBrowser()},
		{Name: "safe_source_file_protocols", Fn: safe.SourceFileProtocols()},
		{Name: "safe_inactive_systemd_services", Fn: safe.InactiveSystemdServices()},
		{Name: "safe_orphan_flowbits", Fn: safe.OrphanFlowbits()},
		{Name: "iter_protocol_alert_overlap", Fn: iter.ProtocolAlertOverlap()},
		{Name: "iter_high_fp_low_utilization", Fn: iter.HighFPLowUtilization()},
		{Name: "iter_low_yield_hot_rules", Fn: iter.LowYieldHotRules()},
		{Name: "iter_high_cost_rules", Fn: iter.HighCostRules()},
	}
}

func builtinStrategyNames() []string {
	specs := builtinStrategies()
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Name)
	}
	sort.Strings(names)
	return names
}

func selectStrategies(enabled, disabled []string) ([]atypes.RegisteredFunction, error) {
	specs := builtinStrategies()
	byName := make(map[string]atypes.RegisteredFunction, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec.Fn
	}
	selected := map[string]bool{}
	if len(enabled) == 0 {
		for _, spec := range specs {
			selected[spec.Name] = true
		}
	} else {
		for _, name := range enabled {
			switch name {
			case "all":
				for _, spec := range specs {
					selected[spec.Name] = true
				}
			case "none":
				for key := range selected {
					delete(selected, key)
				}
			default:
				if _, ok := byName[name]; !ok {
					return nil, fmt.Errorf("unknown strategy %q", name)
				}
				selected[name] = true
			}
		}
	}
	for _, name := range disabled {
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("unknown strategy %q", name)
		}
		delete(selected, name)
	}
	out := make([]atypes.RegisteredFunction, 0, len(selected))
	for _, spec := range specs {
		if selected[spec.Name] {
			out = append(out, spec.Fn)
		}
	}
	return out, nil
}

func rejectSingleDashArgs(args []string) error {
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' && (len(arg) == 2 || arg[1] != '-') {
			return fmt.Errorf("single-dash argument %q is not supported; use --%s", arg, arg[1:])
		}
	}
	return nil
}
