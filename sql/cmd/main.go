package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	sqlpkg "snort-optimizer/sql"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	logger := log.New(os.Stderr, "sql: ", log.LstdFlags)
	cmd := os.Args[1]
	switch cmd {
	case "init":
		cfg := parseBaseFlags(os.Args[2:])
		must(sqlpkg.Ensure(cfg))
	case "import-alerts":
		cfg := parseBaseFlags(os.Args[2:])
		n, err := sqlpkg.ImportAlerts(cfg, logger)
		must(err)
		fmt.Printf("imported alerts: %d\n", n)
	case "tail-alerts":
		cfg := parseBaseFlags(os.Args[2:])
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		must(sqlpkg.TailAlerts(ctx, cfg, logger))
	case "import-profiler":
		fs, cfg := newBaseFlagSet("import-profiler", os.Args[2:])
		runID := fs.String("run-id", "", "Profiler run id")
		must(fs.Parse(os.Args[2:]))
		n, err := sqlpkg.ImportProfiler(*cfg, *runID, logger)
		must(err)
		fmt.Printf("imported profiler metrics: %d\n", n)
	case "import-rules":
		cfg := parseBaseFlags(os.Args[2:])
		n, err := sqlpkg.ImportRules(cfg, logger)
		must(err)
		fmt.Printf("imported rules: %d\n", n)
	case "query-alerts":
		fs, cfg := newBaseFlagSet("query-alerts", os.Args[2:])
		q := sqlpkg.AlertQuery{}
		fs.IntVar(&q.Limit, "limit", 100, "Result limit")
		fs.Int64Var(&q.SID, "sid", 0, "Rule SID")
		fs.StringVar(&q.Proto, "proto", "", "Protocol")
		fs.StringVar(&q.Action, "action", "", "Alert action")
		fs.StringVar(&q.SrcAP, "src", "", "Source address contains")
		fs.StringVar(&q.DstAP, "dst", "", "Destination address contains")
		must(fs.Parse(os.Args[2:]))
		rows, err := sqlpkg.ListAlerts(*cfg, q)
		must(err)
		printJSON(rows)
	case "query-profiler":
		fs, cfg := newBaseFlagSet("query-profiler", os.Args[2:])
		q := sqlpkg.ProfilerQuery{}
		fs.IntVar(&q.Limit, "limit", 100, "Result limit")
		fs.StringVar(&q.RunID, "run-id", "", "Run id")
		fs.StringVar(&q.Section, "section", "", "Section contains")
		fs.StringVar(&q.Module, "module", "", "Module contains")
		fs.StringVar(&q.Metric, "metric", "", "Metric contains")
		must(fs.Parse(os.Args[2:]))
		rows, err := sqlpkg.ListProfiler(*cfg, q)
		must(err)
		printJSON(rows)
	case "query-rules":
		fs, cfg := newBaseFlagSet("query-rules", os.Args[2:])
		q := sqlpkg.RuleQuery{}
		var enabled string
		fs.IntVar(&q.Limit, "limit", 100, "Result limit")
		fs.Int64Var(&q.SID, "sid", 0, "Rule SID")
		fs.Int64Var(&q.GID, "gid", 0, "Rule GID")
		fs.StringVar(&q.Msg, "msg", "", "Message contains")
		fs.StringVar(&q.Classtype, "classtype", "", "Classtype")
		fs.StringVar(&enabled, "enabled", "", "true or false")
		must(fs.Parse(os.Args[2:]))
		if enabled == "true" || enabled == "false" {
			value := enabled == "true"
			q.Enabled = &value
		}
		rows, err := sqlpkg.ListRules(*cfg, q)
		must(err)
		printJSON(rows)
	case "enable-rule", "disable-rule":
		fs, cfg := newBaseFlagSet(cmd, os.Args[2:])
		id := fs.Int64("id", 0, "Rule row id")
		must(fs.Parse(os.Args[2:]))
		if *id <= 0 {
			fatalf("--id is required")
		}
		must(sqlpkg.SetRuleEnabled(*cfg, *id, cmd == "enable-rule"))
	default:
		usage()
		os.Exit(2)
	}
}

func parseBaseFlags(args []string) sqlpkg.Config {
	fs, cfg := newBaseFlagSet("sql", args)
	must(fs.Parse(args))
	return *cfg
}

func newBaseFlagSet(name string, args []string) (*flag.FlagSet, *sqlpkg.Config) {
	rejectSingleDashFlags(args)
	cfg := &sqlpkg.Config{}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&cfg.DBPath, "db", "snort.sqlite", "SQLite database path")
	fs.StringVar(&cfg.AlertPath, "alerts", "tmp/alert_json.txt", "Snort alert_json file")
	fs.StringVar(&cfg.ProfilerPath, "profiler", "tmp/snort_output.txt", "Snort stdout/profiler file")
	fs.StringVar(&cfg.RulesDir, "rules", "tmp/config/rules", "Snort rules directory")
	return fs, cfg
}

func rejectSingleDashFlags(args []string) {
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' && (len(arg) == 2 || arg[1] != '-') {
			fatalf("options must use --name form, got %q", arg)
		}
	}
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	must(enc.Encode(v))
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: go run ./sql/cmd <command> [flags]

commands:
  init
  import-alerts
  tail-alerts
  import-profiler [--run-id id]
  import-rules
  query-alerts [--sid n] [--limit n]
  query-profiler [--run-id id] [--module name] [--metric name]
  query-rules [--sid n] [--msg text] [--enabled true|false]
  enable-rule --id n
  disable-rule --id n

common flags:
  --db path          SQLite database path
  --alerts path      alert_json.txt path
  --profiler path    snort_output.txt path
  --rules path       rules directory`)
}
