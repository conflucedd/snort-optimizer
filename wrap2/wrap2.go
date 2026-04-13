package wrap2

import (
	"snort-optimizer/wrap2/runner"
	wraptypes "snort-optimizer/wrap2/types"
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
