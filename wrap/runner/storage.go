package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sqlstore "snort-optimizer/sql"
)

const maxRuleList = 1_000_000

func (r *Runner) sqlConfig() sqlstore.Config {
	dbPath := r.cfg.SnortDBPath
	if dbPath == "" {
		dbPath = filepath.Join(r.cfg.SnortWorkingDir, "snort.sqlite")
	}
	rawRulePath := r.cfg.RawRulePath
	if rawRulePath == "" {
		rawRulePath = filepath.Join(r.cfg.SnortWorkingDir, "rules")
	}
	return sqlstore.Config{
		DBPath:       dbPath,
		AlertPath:    alertJSONPath(r.cfg.SnortWorkingDir),
		ProfilerPath: filepath.Join(r.cfg.SnortWorkingDir, "snort_output.txt"),
		RulesDir:     filepath.Join(r.cfg.SnortWorkingDir, "rules"),
		RawRulePath:  rawRulePath,
		RunID:        r.cfg.RunID,
	}
}

func (r *Runner) ensureSQLStore() error {
	if err := os.MkdirAll(r.cfg.SnortWorkingDir, 0755); err != nil {
		return fmt.Errorf("create snort working dir: %w", err)
	}
	return sqlstore.Ensure(r.sqlConfig())
}

func (r *Runner) ensureRuleStore() error {
	cfg := r.sqlConfig()
	dbMissing := false
	if _, err := os.Stat(cfg.DBPath); os.IsNotExist(err) {
		dbMissing = true
	} else if err != nil {
		return fmt.Errorf("stat sql db: %w", err)
	}
	if err := r.ensureSQLStore(); err != nil {
		return err
	}
	if dbMissing {
		if _, err := sqlstore.ImportRules(cfg, r.logger); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) generateAllRules() error {
	enabled := true
	rules, err := sqlstore.ListRules(r.sqlConfig(), sqlstore.RuleQuery{Enabled: &enabled, Limit: maxRuleList})
	if err != nil {
		return fmt.Errorf("query enabled rules: %w", err)
	}
	lines := make([]string, 0, len(rules))
	for _, rule := range rules {
		if raw := strings.TrimSpace(rule.RawText); raw != "" {
			lines = append(lines, raw)
		}
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(allRulesPath(r.cfg.SnortWorkingDir), []byte(content), 0644); err != nil {
		return fmt.Errorf("write all.rules: %w", err)
	}
	return nil
}

func (r *Runner) tailAlerts(ctx context.Context) error {
	return sqlstore.TailAlerts(ctx, r.sqlConfig(), r.logger)
}

func (r *Runner) setRuleEnabled(ruleID int64, enabled bool) error {
	if err := r.ensureSQLStore(); err != nil {
		return err
	}
	return sqlstore.SetRuleEnabled(r.sqlConfig(), ruleID, enabled)
}

func (r *Runner) resetSQLStore() error {
	return sqlstore.Reset(r.sqlConfig())
}

func alertJSONPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "alert_json.txt")
}

func allRulesPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "all.rules")
}
