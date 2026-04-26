package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"snort-optimizer/wrap2"
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
	var cfg wrap2.Config
	flag.StringVar(&cfg.SnortWorkingDir, "swd", "", "Snort working directory")
	flag.StringVar(&cfg.Mode, "mode", "", "Run mode: interface or pcap")
	flag.StringVar(&cfg.Interface, "iface", "", "Network interface for interface mode")
	flag.StringVar(&cfg.PcapFile, "pcap", "", "Pcap file for pcap mode")
	flag.StringVar(&cfg.SnortConfigPath, "config", "", "Snort Lua config path")
	flag.Var(&lua, "lua", "Additional Snort --lua override; may be repeated")
	flag.BoolVar(&cfg.NeedOutput, "need-output", false, "Write Snort stdout/stderr to snort_output.txt")
	flag.BoolVar(&cfg.NeedAlert, "need-alert", false, "Enable alert_json file output and ingest alerts.db")
	flag.Parse()
	cfg.LuaOverrides = lua

	r, err := wrap2.NewRunner(cfg)
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
