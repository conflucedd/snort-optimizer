package sql

import (
	"context"
	"log"
	"os"

	"snort-optimizer/sql/alerts"
	"snort-optimizer/sql/config"
	"snort-optimizer/sql/profiler"
	"snort-optimizer/sql/rules"
	"snort-optimizer/sql/schema"
	"snort-optimizer/types"
)

type Config = config.Config
type AlertQuery = alerts.Query
type AlertTailer = alerts.Tailer
type ProfilerQuery = profiler.Query
type RuleQuery = rules.Query

func Ensure(cfg Config) error {
	return schema.Ensure(cfg)
}

func ImportAlerts(cfg Config, logger *log.Logger) (int, error) {
	return alerts.ImportFile(cfg, fallbackLogger(logger))
}

func TailAlerts(ctx context.Context, cfg Config, logger *log.Logger) error {
	return alerts.TailFile(ctx, cfg, fallbackLogger(logger))
}

func NewAlertTailer(cfg Config, logger *log.Logger, startExistingAtEnd bool) (*AlertTailer, error) {
	return alerts.NewTailer(cfg, fallbackLogger(logger), startExistingAtEnd)
}

func ListAlerts(cfg Config, q AlertQuery) ([]types.Alert, error) {
	return alerts.List(cfg, q)
}

func ImportProfiler(cfg Config, runID int64, logger *log.Logger) (int, error) {
	return profiler.ImportFile(cfg, runID, fallbackLogger(logger))
}

func ListProfiler(cfg Config, q ProfilerQuery) ([]types.ProfilerMetric, error) {
	return profiler.List(cfg, q)
}

func ImportRules(cfg Config, logger *log.Logger) (int, error) {
	return rules.ImportDir(cfg, fallbackLogger(logger))
}

func ListRules(cfg Config, q RuleQuery) ([]types.Rule, error) {
	return rules.List(cfg, q)
}

func SetRuleEnabled(cfg Config, id int64, enabled bool) error {
	return rules.SetEnabled(cfg, id, enabled)
}

func ResetRules(cfg Config) error {
	return rules.Reset(cfg)
}

func Reset(cfg Config) error {
	return schema.Reset(cfg)
}

func InsertSystemProfile(cfg Config, profile types.SystemProfile) error {
	return profiler.InsertSystemProfile(cfg, profile)
}

func fallbackLogger(logger *log.Logger) *log.Logger {
	if logger != nil {
		return logger
	}
	return log.New(os.Stderr, "sql: ", log.LstdFlags)
}
