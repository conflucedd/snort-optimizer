package main

import (
	"encoding/json"
	"fmt"
	"os"

	"analyser/internal/analyzer"
	"analyser/internal/config"
	"analyser/internal/parse"
	"analyser/internal/store"
)

func main() {
	cfg := config.ParseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config.Config) error {
	csvYear, err := parse.DetectCSVYear(cfg.CSVPath)
	if err != nil {
		return err
	}

	alerts, profilers, warnings, err := parse.ParseSnortOutput(cfg.SnortPath, csvYear)
	if err != nil {
		return err
	}

	if cfg.TimeOffsetMinutes != 0 {
		analyzer.ShiftAlerts(alerts, cfg.FixedTimeOffset())
		warnings = append(warnings, fmt.Sprintf("applied fixed snort time offset: %d minutes", cfg.TimeOffsetMinutes))
	} else if cfg.AutoTimeOffset {
		offset, count, inferErr := parse.InferTimeOffset(cfg.CSVPath, alerts)
		if inferErr != nil {
			warnings = append(warnings, "auto time offset inference failed: "+inferErr.Error())
		} else if count > 0 && offset != 0 {
			analyzer.ShiftAlerts(alerts, offset)
			warnings = append(warnings, fmt.Sprintf("inferred snort time offset %s from %d tuple matches", offset, count))
		}
	}

	alerts, totalMaliciousCSVFlows, missedByLabel, csvWarnings, err := parse.ApplyCSVLabels(cfg.CSVPath, alerts)
	if err != nil {
		return err
	}
	warnings = append(warnings, csvWarnings...)

	if err := store.BuildSQLite(cfg.DBPath, alerts, profilers); err != nil {
		return err
	}

	stats, perRule := analyzer.ComputeMetrics(alerts, profilers, totalMaliciousCSVFlows, missedByLabel)
	candidates := analyzer.BuildCandidates(cfg, alerts, perRule)

	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
	fmt.Fprintf(os.Stderr, "stats: alerted_flows=%d false_positive_flows=%d false_positive_rate=%.4f malicious_csv_flows=%d missed_flows=%d missed_rate=%.4f\n",
		stats.TotalAlertFlows, stats.FalsePositiveAlertFlows, stats.OverallFalsePositiveRate,
		stats.TotalMaliciousCSVFlows, stats.MissedMaliciousCSVFlows, stats.OverallMissedDetectionRate)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(candidates)
}
