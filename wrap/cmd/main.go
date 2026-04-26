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
	fs.StringVar(&cfg.SnortWorkingDir, "swd", "", "Snort working directory")
	fs.StringVar(&cfg.Mode, "mode", "", "Run mode: interface or pcap")
	fs.StringVar(&cfg.Interface, "iface", "", "Network interface for interface mode")
	fs.StringVar(&cfg.PcapFile, "pcap", "", "Pcap file for pcap mode")
	fs.StringVar(&cfg.SnortConfigPath, "config", "", "Snort Lua config path")
	fs.Var(&lua, "lua", "Additional Snort --lua override; may be repeated")
	fs.BoolVar(&cfg.NeedOutput, "need-output", false, "Write Snort stdout/stderr to snort_output.txt")
	fs.BoolVar(&cfg.NeedAlert, "need-alert", false, "Enable alert_json file output and ingest snort.sqlite")
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
	fmt.Fprintf(os.Stderr, "snort started pid=%d pgid=%d\n", status.RunInfo.PID, status.RunInfo.PGID)

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

func rejectSingleDashArgs(args []string) error {
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' && (len(arg) == 2 || arg[1] != '-') {
			return fmt.Errorf("single-dash argument %q is not supported; use --%s", arg, arg[1:])
		}
	}
	return nil
}
