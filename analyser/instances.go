package analyser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"snort-optimizer/wrap"
)

const (
	instanceExp  = "exp"
	instanceReal = "real"
	instanceBase = "base"
)

type snortInstance struct {
	Name      string
	PcapPath  string
	WorkDir   string
	DBPath    string
	NeedAlert bool
}

type instanceSet struct {
	Exp  snortInstance
	Real snortInstance
	Base snortInstance
}

type instanceRun struct {
	Name            string
	RunID           int64
	Duration        time.Duration
	LoadedRuleCount int64
}

func newInstanceSet(cfg Config) instanceSet {
	expDir := filepath.Join(cfg.AnalyserWorkingDir, instanceExp)
	realDir := filepath.Join(cfg.AnalyserWorkingDir, instanceReal)
	baseDir := filepath.Join(cfg.AnalyserWorkingDir, instanceBase)
	return instanceSet{
		Exp: snortInstance{
			Name:      instanceExp,
			PcapPath:  cfg.Pcap1,
			WorkDir:   expDir,
			DBPath:    filepath.Join(expDir, "snort.sqlite"),
			NeedAlert: true,
		},
		Real: snortInstance{
			Name:     instanceReal,
			PcapPath: cfg.Pcap2,
			WorkDir:  realDir,
			DBPath:   filepath.Join(realDir, "snort.sqlite"),
		},
		Base: snortInstance{
			Name:     instanceBase,
			PcapPath: cfg.EmptyPcap,
			WorkDir:  baseDir,
			DBPath:   filepath.Join(baseDir, "snort.sqlite"),
		},
	}
}

func (set instanceSet) ordered() []snortInstance {
	return []snortInstance{set.Exp, set.Real, set.Base}
}

func (set instanceSet) runAll(ctx context.Context, cfg Config, runID int64) ([]instanceRun, error) {
	out := make([]instanceRun, 0, 3)
	for _, inst := range set.ordered() {
		run, err := inst.run(ctx, cfg, runID)
		if err != nil {
			return out, err
		}
		out = append(out, run)
	}
	return out, nil
}

func (inst snortInstance) run(ctx context.Context, cfg Config, runID int64) (instanceRun, error) {
	r, err := wrap.NewRunner(wrap.Config{
		Mode:            wrap.ModePCAP,
		SnortWorkingDir: inst.WorkDir,
		SnortConfigPath: cfg.SnortConfig,
		SnortDBPath:     inst.DBPath,
		RawRulePath:     cfg.RawRulePath,
		PcapFile:        inst.PcapPath,
		LuaOverrides:    cfg.LuaOverrides,
		RunID:           runID,
		NeedOutput:      false,
		NeedAlert:       inst.NeedAlert,
		NeedProfiler:    true,
	})
	if err != nil {
		return instanceRun{}, fmt.Errorf("%s runner: %w", inst.Name, err)
	}
	start := time.Now()
	if err := r.Start(); err != nil {
		return instanceRun{}, fmt.Errorf("%s start: %w", inst.Name, err)
	}
	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	for {
		if !r.Status().RunInfo.Running {
			stats := r.StartupStats()
			return instanceRun{
				Name:            inst.Name,
				RunID:           runID,
				Duration:        time.Since(start),
				LoadedRuleCount: stats.LoadedRuleCount,
			}, nil
		}
		select {
		case <-ctx.Done():
			_ = r.Stop()
			return instanceRun{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func ensureInstanceDirs(set instanceSet) error {
	for _, inst := range set.ordered() {
		if err := os.MkdirAll(inst.WorkDir, 0755); err != nil {
			return fmt.Errorf("create %s work dir: %w", inst.Name, err)
		}
	}
	return nil
}

func ensureEmptyPCAP(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat empty pcap: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	header := []byte{
		0xd4, 0xc3, 0xb2, 0xa1,
		0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
	}
	return os.WriteFile(path, header, 0644)
}
