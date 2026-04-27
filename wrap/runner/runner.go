package runner

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	sqlstore "snort-optimizer/sql"
	wraptypes "snort-optimizer/wrap/types"
)

type Runner struct {
	cfg    wraptypes.Config
	logger *log.Logger

	mu         sync.Mutex
	cmd        *exec.Cmd
	waitDone   chan struct{}
	runInfo    wraptypes.RunInfo
	outputFile *os.File
	alertStop  context.CancelFunc
	alertDone  chan struct{}
}

func New(cfg wraptypes.Config) (*Runner, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Runner{
		cfg:    normalized,
		logger: log.New(os.Stderr, "wrap: ", log.LstdFlags),
	}, nil
}

func (r *Runner) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.runInfo.Running {
		return fmt.Errorf("snort is already running with pid %d", r.runInfo.PID)
	}
	if err := r.ensureRuleStore(); err != nil {
		return err
	}
	if err := r.generateAllRules(); err != nil {
		return err
	}
	snortBin, daqDir, err := resolveSnortEnv()
	if err != nil {
		return err
	}
	if r.cfg.NeedAlert {
		if err := r.ensureSQLStore(); err != nil {
			return err
		}
	}
	var alertTailer *sqlstore.AlertTailer
	if r.cfg.NeedAlert {
		alertTailer, err = sqlstore.NewAlertTailer(r.sqlConfig(), r.logger, true)
		if err != nil {
			return err
		}
	}

	cmd := exec.Command(snortBin, r.snortArgs(daqDir)...)
	cmd.Dir = r.cfg.SnortWorkingDir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := r.attachOutput(cmd); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		if alertTailer != nil {
			_ = alertTailer.Close()
		}
		if r.outputFile != nil {
			r.outputFile.Close()
			r.outputFile = nil
		}
		return fmt.Errorf("start snort: %w", err)
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		pgid = cmd.Process.Pid
	}
	r.cmd = cmd
	r.waitDone = make(chan struct{})
	r.runInfo = wraptypes.RunInfo{
		PID:       cmd.Process.Pid,
		PGID:      pgid,
		Running:   true,
		StartTime: time.Now(),
	}
	if r.cfg.NeedAlert {
		ctx, cancel := context.WithCancel(context.Background())
		r.alertStop = cancel
		r.alertDone = make(chan struct{})
		go func(done chan struct{}) {
			defer close(done)
			if err := alertTailer.Tail(ctx); err != nil {
				r.logger.Printf("alert tail stopped: %v", err)
			}
		}(r.alertDone)
	}

	go r.waitForExit(cmd, r.waitDone)
	return nil
}

func (r *Runner) Stop() error {
	r.mu.Lock()
	cmd := r.cmd
	info := r.runInfo
	waitDone := r.waitDone
	r.mu.Unlock()

	if cmd == nil || !info.Running {
		r.clearStopped()
		return nil
	}

	pgid := info.PGID
	if pgid <= 0 {
		pgid = info.PID
	}
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		return fmt.Errorf("stop snort process group %d: %w", pgid, err)
	}
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-waitDone
	}
	r.clearStopped()
	return nil
}

func (r *Runner) Restart() error {
	if err := r.Stop(); err != nil {
		return err
	}
	return r.Start()
}

func (r *Runner) Reset() error {
	return r.resetSQLStore()
}

func (r *Runner) EnableRule(ruleID int64) error {
	return r.setRuleEnabled(ruleID, true)
}

func (r *Runner) DisableRule(ruleID int64) error {
	return r.setRuleEnabled(ruleID, false)
}

func (r *Runner) Status() wraptypes.Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return wraptypes.Status{RunInfo: r.runInfo, Config: r.cfg}
}

func (r *Runner) Config() wraptypes.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

func (r *Runner) snortArgs(daqDir string) []string {
	args := []string{
		"--daq-dir", daqDir,
		"-c", r.cfg.SnortConfigPath,
	}
	switch r.cfg.Mode {
	case wraptypes.ModeInterface:
		args = append(args, "-i", r.cfg.Interface)
	case wraptypes.ModePCAP:
		args = append(args, "-r", r.cfg.PcapFile)
	}
	args = append(args, "--lua", "ips.rules = [[\ninclude "+allRulesPath(r.cfg.SnortWorkingDir)+"\n]]")
	if r.cfg.NeedAlert {
		args = append(args, "--lua", "alert_json = { file = true }")
	}
	for _, override := range r.cfg.LuaOverrides {
		args = append(args, "--lua", override)
	}
	return args
}

func (r *Runner) attachOutput(cmd *exec.Cmd) error {
	if !r.cfg.NeedOutput {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return nil
	}
	outputPath := filepath.Join(r.cfg.SnortWorkingDir, "snort_output.txt")
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create snort output file: %w", err)
	}
	cmd.Stdout = file
	cmd.Stderr = file
	r.outputFile = file
	return nil
}

func cleanupAlertFile(snortWorkingDir string) error {
	path := alertJSONPath(snortWorkingDir)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	return nil
}

func (r *Runner) waitForExit(cmd *exec.Cmd, done chan struct{}) {
	err := cmd.Wait()
	if err != nil {
		r.logger.Printf("snort exited: %v", err)
	}
	r.mu.Lock()
	if r.cmd == cmd {
		if r.outputFile != nil {
			r.outputFile.Close()
			r.outputFile = nil
		}
		alertStop := r.alertStop
		alertDone := r.alertDone
		r.alertStop = nil
		r.alertDone = nil
		r.cmd = nil
		r.waitDone = nil
		r.runInfo.Running = false
		r.mu.Unlock()
		if alertStop != nil {
			alertStop()
		}
		if alertDone != nil {
			<-alertDone
		}
		if !r.cfg.NoClean {
			if err := cleanupAlertFile(r.cfg.SnortWorkingDir); err != nil {
				r.logger.Printf("cleanup alert json failed: %v", err)
			}
		}
		close(done)
		return
	}
	r.mu.Unlock()
	close(done)
}

func (r *Runner) clearStopped() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cmd = nil
	r.waitDone = nil
	r.alertStop = nil
	r.alertDone = nil
	if r.outputFile != nil {
		r.outputFile.Close()
		r.outputFile = nil
	}
	r.runInfo.Running = false
}

func resolveSnortEnv() (string, string, error) {
	snortDir := os.Getenv("SNORT_DIR")
	if snortDir == "" {
		return "", "", fmt.Errorf("SNORT_DIR is required")
	}
	daqDir := os.Getenv("DAQ_DIR")
	if daqDir == "" {
		return "", "", fmt.Errorf("DAQ_DIR is required")
	}
	snortBin := filepath.Join(snortDir, "snort")
	stat, err := os.Stat(snortBin)
	if err != nil {
		return "", "", fmt.Errorf("snort executable %s is not available: %w", snortBin, err)
	}
	if stat.IsDir() || stat.Mode()&0111 == 0 {
		return "", "", fmt.Errorf("snort executable %s is not executable", snortBin)
	}
	stat, err = os.Stat(daqDir)
	if err != nil {
		return "", "", fmt.Errorf("DAQ_DIR %s is not available: %w", daqDir, err)
	}
	if !stat.IsDir() {
		return "", "", fmt.Errorf("DAQ_DIR %s is not a directory", daqDir)
	}
	return snortBin, daqDir, nil
}
