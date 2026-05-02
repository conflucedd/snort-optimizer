package scheduler

import (
	"context"
	"fmt"
	"sort"

	anasql "snort-optimizer/analyser/sql"
	"snort-optimizer/analyser/types"
)

func (s Scheduler) prepareRuleDatabases(set instanceSet) error {
	if !s.cfg.PreserveWorkDBs {
		if err := anasql.ResetAnalyserWorkingDir(s.cfg.AnalyserWorkingDir); err != nil {
			return err
		}
	}
	if err := ensureInstanceDirs(set); err != nil {
		return err
	}
	if err := ensureEmptyPCAP(s.cfg.EmptyPcap); err != nil {
		return err
	}
	for _, inst := range set.ordered() {
		if err := anasql.InitRuleDB(s.cfg, inst.DBPath); err != nil {
			return fmt.Errorf("%s init rules: %w", inst.Name, err)
		}
	}
	return nil
}

func (s Scheduler) evaluateRun(set instanceSet, runID int64, runs []instanceRun, flows anasql.FlowSet) (types.Evaluation, error) {
	stats := anasql.RuntimeStats{}
	for _, run := range runs {
		switch run.Name {
		case instanceBase:
			stats.BaseLoadMS = run.Duration.Milliseconds()
		case instanceExp:
			stats.ExpRuntimeMS = run.Duration.Milliseconds()
		case instanceReal:
			stats.RealRuntimeMS = run.Duration.Milliseconds()
		}
	}
	return anasql.EvaluateRun(set.Exp.DBPath, set.Real.DBPath, runID, flows, stats)
}

func (s Scheduler) execute(ctx context.Context, typ types.FunctionType, input types.FunctionInput) ([]types.TrimDecision, error) {
	var out []types.TrimDecision
	for _, fn := range s.functions {
		if fn.Type != typ {
			continue
		}
		decisions, err := fn.Fn(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Name, err)
		}
		for _, d := range decisions {
			d.Function = fn.Name
			d.Type = fn.Type
			out = append(out, d)
		}
	}
	return out, nil
}

func (s Scheduler) executeFunction(ctx context.Context, fn types.RegisteredFunction, input types.FunctionInput) ([]types.TrimDecision, error) {
	decisions, err := fn.Fn(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name, err)
	}
	for i := range decisions {
		decisions[i].Function = fn.Name
		decisions[i].Type = fn.Type
	}
	return decisions, nil
}

func (s Scheduler) functionsByType(typ types.FunctionType) []types.RegisteredFunction {
	var out []types.RegisteredFunction
	for _, fn := range s.functions {
		if fn.Type == typ {
			out = append(out, fn)
		}
	}
	return out
}

func (s Scheduler) evaluateCandidate(accepted, candidate types.Evaluation) (bool, string) {
	missDelta := candidate.MissRate - accepted.MissRate
	fpDelta := candidate.FalsePositiveRate - accepted.FalsePositiveRate
	if candidate.MaliciousFlows > 0 && missDelta > s.cfg.MaxMissRateIncrease {
		return false, fmt.Sprintf("rollback: miss_rate_delta %.6f exceeds %.6f", missDelta, s.cfg.MaxMissRateIncrease)
	}
	if candidate.TotalFlows > 0 && fpDelta > s.cfg.MaxFPRateIncrease {
		return false, fmt.Sprintf("rollback: false_positive_rate_delta %.6f exceeds %.6f", fpDelta, s.cfg.MaxFPRateIncrease)
	}
	return true, fmt.Sprintf("commit: miss_rate_delta %.6f false_positive_rate_delta %.6f", missDelta, fpDelta)
}

func setTrimRunID(values []types.TrimmedRule, runID int64) {
	for i := range values {
		values[i].RunID = runID
	}
}

func sortTrimmedRules(values []types.TrimmedRule) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].RunID != values[j].RunID {
			return values[i].RunID < values[j].RunID
		}
		if values[i].GID != values[j].GID {
			return values[i].GID < values[j].GID
		}
		return values[i].SID < values[j].SID
	})
}
