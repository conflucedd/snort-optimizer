package config

import (
	"flag"
	"time"
)

type Config struct {
	SnortPath            string
	CSVPath              string
	DBPath               string
	FPThreshold          float64
	OverlapThreshold     float64
	EnableServicePrune   bool
	EnableAppIDPrune     bool
	EnableOverlapPrune   bool
	EnableProfilerPrune  bool
	AutoTimeOffset       bool
	TimeOffsetMinutes    int
	ProfilerCheckMin     int64
	ProfilerTimeMinUS    float64
	ProfilerMaxMatches   int64
	ProfilerAvgNoMatchUS float64
}

func ParseFlags() Config {
	cfg := Config{}
	flag.StringVar(&cfg.SnortPath, "snort", "snort_output.txt", "path to Snort output text")
	flag.StringVar(&cfg.CSVPath, "csv", "Friday-WorkingHours.csv", "path to CIC flow CSV")
	flag.StringVar(&cfg.DBPath, "db", "analyser.db", "path to SQLite database")
	flag.Float64Var(&cfg.FPThreshold, "fp-threshold", 0.8, "candidate prune threshold for per-rule false positive rate")
	flag.Float64Var(&cfg.OverlapThreshold, "overlap-threshold", 0.9, "candidate prune threshold for rule overlap ratio")
	flag.BoolVar(&cfg.EnableServicePrune, "enable-service-prune", false, "enable optional service-based pruning hints")
	flag.BoolVar(&cfg.EnableAppIDPrune, "enable-appid-prune", false, "mark AppID-related rules as prune candidates when enabled")
	flag.BoolVar(&cfg.EnableOverlapPrune, "enable-overlap-prune", true, "enable overlap-based pruning")
	flag.BoolVar(&cfg.EnableProfilerPrune, "enable-profiler-prune", true, "enable profiler-based low-value high-cost pruning")
	flag.BoolVar(&cfg.AutoTimeOffset, "auto-time-offset", true, "infer Snort/CSV timestamp offset from matching 5-tuples")
	flag.IntVar(&cfg.TimeOffsetMinutes, "time-offset-minutes", 0, "apply a fixed time offset to Snort alerts before CSV matching")
	flag.Int64Var(&cfg.ProfilerCheckMin, "profiler-check-threshold", 10000, "minimum profiler checks for low-value high-cost pruning")
	flag.Float64Var(&cfg.ProfilerTimeMinUS, "profiler-time-threshold-us", 5000, "minimum profiler total time(us) for low-value high-cost pruning")
	flag.Int64Var(&cfg.ProfilerMaxMatches, "profiler-max-match-count", 1, "maximum profiler matches for low-value high-cost pruning")
	flag.Float64Var(&cfg.ProfilerAvgNoMatchUS, "profiler-avg-no-match-threshold-us", 1, "minimum avg non-match time(us) for low-value high-cost pruning")
	flag.Parse()
	return cfg
}

func (c Config) FixedTimeOffset() time.Duration {
	return time.Duration(c.TimeOffsetMinutes) * time.Minute
}
