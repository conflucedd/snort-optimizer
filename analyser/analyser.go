package analyser

import (
	"context"
	"strings"

	"snort-optimizer/analyser/iter"
	"snort-optimizer/analyser/safe"
	"snort-optimizer/analyser/scheduler"
	"snort-optimizer/analyser/types"
)

type Analyzer struct {
	cfg       types.Config
	functions []types.RegisteredFunction
}

func New(cfg types.Config) (*Analyzer, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	a := &Analyzer{cfg: normalized}
	a.Register(safe.SourceFileBrowser())
	a.Register(iter.HighCostRules())
	return a, nil
}

func Run(ctx context.Context, cfg types.Config) (*types.Result, error) {
	a, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return a.Run(ctx)
}

func (a *Analyzer) Config() types.Config {
	return a.cfg
}

func (a *Analyzer) Functions() []types.RegisteredFunction {
	out := make([]types.RegisteredFunction, len(a.functions))
	copy(out, a.functions)
	return out
}

func (a *Analyzer) ClearFunctions() {
	a.functions = nil
}

func (a *Analyzer) Register(fn types.RegisteredFunction) {
	if strings.TrimSpace(fn.Name) == "" || fn.Fn == nil {
		return
	}
	if fn.Type != types.SAFE && fn.Type != types.ITER {
		return
	}
	a.functions = append(a.functions, fn)
}

func (a *Analyzer) Run(ctx context.Context) (*types.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	s := scheduler.New(a.cfg, a.functions)
	return s.Run(ctx)
}
