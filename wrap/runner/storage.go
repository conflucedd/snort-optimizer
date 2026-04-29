package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sqlstore "snort-optimizer/sql"
	wraptypes "snort-optimizer/wrap/types"
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
	if r.cfg.RunID != 0 {
		if dbMissing {
			return fmt.Errorf("snort db %s does not exist for run-id %d", cfg.DBPath, r.cfg.RunID)
		}
		if err := r.ensureSQLStore(); err != nil {
			return err
		}
		rules, err := sqlstore.ListRules(cfg, sqlstore.RuleQuery{RunID: r.cfg.RunID, Limit: 1})
		if err != nil {
			return fmt.Errorf("query rules for run-id %d: %w", r.cfg.RunID, err)
		}
		if len(rules) == 0 {
			return fmt.Errorf("snort db %s has no rules for run-id %d", cfg.DBPath, r.cfg.RunID)
		}
		return nil
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

func (r *Runner) generateAllRules() (int64, error) {
	enabled := true
	rules, err := sqlstore.ListRules(r.sqlConfig(), sqlstore.RuleQuery{RunID: r.cfg.RunID, Enabled: &enabled, Limit: maxRuleList})
	if err != nil {
		return 0, fmt.Errorf("query enabled rules: %w", err)
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
		return 0, fmt.Errorf("write all.rules: %w", err)
	}
	return int64(len(lines)), nil
}

func (r *Runner) resetSQLStore() error {
	return sqlstore.Reset(r.sqlConfig())
}

func (r *Runner) buildStartupStats(loadedRules int64) (wraptypes.StartupStats, error) {
	cfg := r.sqlConfig()
	counts, err := sqlstore.CountTables(cfg)
	if err != nil {
		return wraptypes.StartupStats{}, fmt.Errorf("count sql tables: %w", err)
	}
	tableCounts := make(map[string]wraptypes.DBTableCount, len(counts))
	for table, count := range counts {
		tableCounts[table] = wraptypes.DBTableCount{Total: count.Total, Run: count.Run}
	}
	return wraptypes.StartupStats{
		RunID:           r.cfg.RunID,
		Mode:            r.cfg.Mode,
		SnortWorkingDir: r.cfg.SnortWorkingDir,
		SnortConfigPath: r.cfg.SnortConfigPath,
		SnortDBPath:     cfg.DBPath,
		RawRulePath:     cfg.RawRulePath,
		AllRulesPath:    allRulesPath(r.cfg.SnortWorkingDir),
		LoadedRuleCount: loadedRules,
		TableCounts:     tableCounts,
		NeedAlert:       r.cfg.NeedAlert,
		NeedProfiler:    r.cfg.NeedProfiler,
		NeedOutput:      r.cfg.NeedOutput,
	}, nil
}

func alertJSONPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "alert_json.txt")
}

func allRulesPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "all.rules")
}
