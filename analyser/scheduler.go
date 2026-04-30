package analyser

import (
	"context"
	"fmt"
	"sort"
)

type scheduler struct {
	cfg       Config
	functions []RegisteredFunction
}

func (s scheduler) run(ctx context.Context) (*Result, error) {
	set := newInstanceSet(s.cfg)
	if err := prepareRuleDatabases(s.cfg, set); err != nil {
		return nil, err
	}
	storePath := analyserDBPath(s.cfg)
	if err := ensureAnalyserStore(storePath); err != nil {
		return nil, err
	}
	flows, err := loadFlowSet(s.cfg.DB1)
	if err != nil {
		return nil, err
	}

	result := &Result{
		AnalyserDBPath: storePath,
		TrimmedRules:   []TrimmedRule{},
		Runs:           []RunResult{},
	}
	factor := s.cfg.InitialFactor

	baseRuns, err := set.runAll(ctx, s.cfg, 0)
	if err != nil {
		return nil, err
	}
	baseEval, err := evaluateRun(s.cfg, set, 0, baseRuns, flows)
	if err != nil {
		return nil, err
	}
	acceptedEval := baseEval
	acceptedRunID := int64(0)
	nextRunID := int64(1)
	baseResult := RunResult{
		RunID:      0,
		Committed:  true,
		Factor:     factor,
		Reason:     "baseline run",
		Evaluation: baseEval,
	}
	if err := insertRunResult(storePath, baseResult); err != nil {
		return nil, err
	}
	result.Runs = append(result.Runs, baseResult)

	safeDecisions, err := s.execute(ctx, SAFE, FunctionInput{
		ExpDBPath:   set.Exp.DBPath,
		RealDBPath:  set.Real.DBPath,
		BaseDBPath:  set.Base.DBPath,
		Round:       0,
		SourceRunID: acceptedRunID,
		Factor:      1,
	})
	if err != nil {
		return nil, err
	}
	safeTrimmed, err := aggregateAndEnrich(set.Exp.DBPath, acceptedRunID, SAFE, safeDecisions)
	if err != nil {
		return nil, err
	}
	if len(safeTrimmed) > 0 {
		setTrimRunID(safeTrimmed, nextRunID)
		if err := cloneRulesForRun(set, acceptedRunID, nextRunID, safeTrimmed); err != nil {
			return nil, err
		}
		runs, err := set.runAll(ctx, s.cfg, nextRunID)
		if err != nil {
			return nil, err
		}
		eval, err := evaluateRun(s.cfg, set, nextRunID, runs, flows)
		if err != nil {
			return nil, err
		}
		runResult := RunResult{
			RunID:      nextRunID,
			Committed:  true,
			Factor:     1,
			Reason:     "SAFE functions are committed directly",
			Evaluation: eval,
		}
		if err := insertTrimDecisions(storePath, nextRunID, safeTrimmed, true); err != nil {
			return nil, err
		}
		if err := insertRunResult(storePath, runResult); err != nil {
			return nil, err
		}
		result.TrimmedRules = append(result.TrimmedRules, safeTrimmed...)
		result.Runs = append(result.Runs, runResult)
		acceptedRunID = nextRunID
		acceptedEval = eval
		nextRunID++
	}

	for round := 1; round <= s.cfg.MaxRound; round++ {
		iterDecisions, err := s.execute(ctx, ITER, FunctionInput{
			ExpDBPath:   set.Exp.DBPath,
			RealDBPath:  set.Real.DBPath,
			BaseDBPath:  set.Base.DBPath,
			Round:       round,
			SourceRunID: acceptedRunID,
			Factor:      factor,
		})
		if err != nil {
			return nil, err
		}
		iterTrimmed, err := aggregateAndEnrich(set.Exp.DBPath, acceptedRunID, ITER, iterDecisions)
		if err != nil {
			return nil, err
		}
		if len(iterTrimmed) == 0 {
			break
		}
		setTrimRunID(iterTrimmed, nextRunID)
		if err := cloneRulesForRun(set, acceptedRunID, nextRunID, iterTrimmed); err != nil {
			return nil, err
		}
		runs, err := set.runAll(ctx, s.cfg, nextRunID)
		if err != nil {
			return nil, err
		}
		eval, err := evaluateRun(s.cfg, set, nextRunID, runs, flows)
		if err != nil {
			return nil, err
		}
		committed, reason := s.evaluateCandidate(acceptedEval, eval)
		runResult := RunResult{
			RunID:      nextRunID,
			Committed:  committed,
			RolledBack: !committed,
			Factor:     factor,
			Reason:     reason,
			Evaluation: eval,
		}
		if err := insertTrimDecisions(storePath, nextRunID, iterTrimmed, committed); err != nil {
			return nil, err
		}
		if err := insertRunResult(storePath, runResult); err != nil {
			return nil, err
		}
		result.Runs = append(result.Runs, runResult)
		if committed {
			result.TrimmedRules = append(result.TrimmedRules, iterTrimmed...)
			acceptedRunID = nextRunID
			acceptedEval = eval
		} else {
			factor = factor / 2
			if factor <= 0.001 {
				break
			}
		}
		nextRunID++
	}

	result.FinalRunID = acceptedRunID
	sortTrimmedRules(result.TrimmedRules)
	return result, nil
}

func (s scheduler) execute(ctx context.Context, typ FunctionType, input FunctionInput) ([]TrimDecision, error) {
	var out []TrimDecision
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

func (s scheduler) evaluateCandidate(accepted, candidate Evaluation) (bool, string) {
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

func setTrimRunID(values []TrimmedRule, runID int64) {
	for i := range values {
		values[i].RunID = runID
	}
}

func sortTrimmedRules(values []TrimmedRule) {
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
