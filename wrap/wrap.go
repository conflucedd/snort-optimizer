package wrap

import (
	"snort-optimizer/wrap/runner"
	wraptypes "snort-optimizer/wrap/types"
)

type Config = wraptypes.Config
type RunInfo = wraptypes.RunInfo
type Status = wraptypes.Status
type Runner = runner.Runner

const (
	ModeInterface = wraptypes.ModeInterface
	ModePCAP      = wraptypes.ModePCAP
)

func NewRunner(cfg Config) (*Runner, error) {
	return runner.New(cfg)
}
