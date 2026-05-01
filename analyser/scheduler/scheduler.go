package scheduler

import (
	"context"

	anasql "snort-optimizer/analyser/sql"
	"snort-optimizer/analyser/types"
)

type Scheduler struct {
	cfg       types.Config
	functions []types.RegisteredFunction
}

func New(cfg types.Config, functions []types.RegisteredFunction) Scheduler {
	copied := make([]types.RegisteredFunction, len(functions))
	copy(copied, functions)
	return Scheduler{cfg: cfg, functions: copied}
}

func (s Scheduler) Run(ctx context.Context) (*types.Result, error) {
	set := newInstanceSet(s.cfg)
	if err := s.prepareRuleDatabases(set); err != nil {
		return nil, err
	}
	storePath := anasql.AnalyserDBPath(s.cfg)
	if err := anasql.EnsureAnalyserStore(storePath); err != nil {
		return nil, err
	}
	flows, err := anasql.LoadFlowSet(s.cfg.DB1)
	if err != nil {
		return nil, err
	}

	result := &types.Result{
		AnalyserDBPath: storePath,
		TrimmedRules:   []types.TrimmedRule{},
		Runs:           []types.RunResult{},
	}
	factor := s.cfg.InitialFactor

	baseRuns, err := set.runAll(ctx, s.cfg, 0, func() error {
		return anasql.RefreshRuleFP(set.Exp.DBPath, 0, flows)
	})
	if err != nil {
		return nil, err
	}
	baseEval, err := s.evaluateRun(set, 0, baseRuns, flows)
	if err != nil {
		return nil, err
	}
	acceptedEval := baseEval
	acceptedRunID := int64(0)
	nextRunID := int64(1)
	baseResult := types.RunResult{
		RunID:      0,
		Committed:  true,
		Factor:     factor,
		Reason:     "baseline run",
		Evaluation: baseEval,
	}
	if err := anasql.InsertRunResult(storePath, baseResult); err != nil {
		return nil, err
	}
	result.Runs = append(result.Runs, baseResult)

	safeDecisions, err := s.execute(ctx, types.SAFE, types.FunctionInput{
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
	safeTrimmed, err := anasql.AggregateAndEnrich(set.Exp.DBPath, acceptedRunID, types.SAFE, safeDecisions)
	if err != nil {
		return nil, err
	}
	if len(safeTrimmed) > 0 {
		setTrimRunID(safeTrimmed, nextRunID)
		if err := anasql.CloneRulesForRun(set.dbPaths(), acceptedRunID, nextRunID, safeTrimmed); err != nil {
			return nil, err
		}
		runs, err := set.runAll(ctx, s.cfg, nextRunID, func() error {
			return anasql.RefreshRuleFP(set.Exp.DBPath, nextRunID, flows)
		})
		if err != nil {
			return nil, err
		}
		eval, err := s.evaluateRun(set, nextRunID, runs, flows)
		if err != nil {
			return nil, err
		}
		runResult := types.RunResult{
			RunID:      nextRunID,
			Committed:  true,
			Factor:     1,
			Reason:     "SAFE functions are committed directly",
			Evaluation: eval,
		}
		if err := anasql.InsertTrimDecisions(storePath, nextRunID, safeTrimmed, true); err != nil {
			return nil, err
		}
		if err := anasql.InsertRunResult(storePath, runResult); err != nil {
			return nil, err
		}
		result.TrimmedRules = append(result.TrimmedRules, safeTrimmed...)
		result.Runs = append(result.Runs, runResult)
		acceptedRunID = nextRunID
		acceptedEval = eval
		nextRunID++
	}

	for round := 1; round <= s.cfg.MaxRound; round++ {
		iterDecisions, err := s.execute(ctx, types.ITER, types.FunctionInput{
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
		iterTrimmed, err := anasql.AggregateAndEnrich(set.Exp.DBPath, acceptedRunID, types.ITER, iterDecisions)
		if err != nil {
			return nil, err
		}
		if len(iterTrimmed) == 0 {
			break
		}
		setTrimRunID(iterTrimmed, nextRunID)
		if err := anasql.CloneRulesForRun(set.dbPaths(), acceptedRunID, nextRunID, iterTrimmed); err != nil {
			return nil, err
		}
		runs, err := set.runAll(ctx, s.cfg, nextRunID, func() error {
			return anasql.RefreshRuleFP(set.Exp.DBPath, nextRunID, flows)
		})
		if err != nil {
			return nil, err
		}
		eval, err := s.evaluateRun(set, nextRunID, runs, flows)
		if err != nil {
			return nil, err
		}
		committed, reason := s.evaluateCandidate(acceptedEval, eval)
		runResult := types.RunResult{
			RunID:      nextRunID,
			Committed:  committed,
			RolledBack: !committed,
			Factor:     factor,
			Reason:     reason,
			Evaluation: eval,
		}
		if err := anasql.InsertTrimDecisions(storePath, nextRunID, iterTrimmed, committed); err != nil {
			return nil, err
		}
		if err := anasql.InsertRunResult(storePath, runResult); err != nil {
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
