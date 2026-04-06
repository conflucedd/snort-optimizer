package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type SnortRunner struct {
	cfg        RuntimeConfig
	alertStore *AlertStore
	broker     *AlertBroker
	logger     *log.Logger

	mu      sync.RWMutex
	pid     int
	process *os.Process
}

func NewSnortRunner(cfg RuntimeConfig, alertStore *AlertStore, broker *AlertBroker, logger *log.Logger) *SnortRunner {
	return &SnortRunner{
		cfg:        cfg,
		alertStore: alertStore,
		broker:     broker,
		logger:     logger,
	}
}

func (r *SnortRunner) PID() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pid
}

func (r *SnortRunner) setPID(pid int) {
	r.mu.Lock()
	r.pid = pid
	r.mu.Unlock()
}

func (r *SnortRunner) setProcess(process *os.Process) {
	r.mu.Lock()
	r.process = process
	r.mu.Unlock()
}

func (r *SnortRunner) clearProcess() {
	r.mu.Lock()
	r.pid = 0
	r.process = nil
	r.mu.Unlock()
}

func (r *SnortRunner) Stop(sig os.Signal) error {
	r.mu.RLock()
	process := r.process
	pid := r.pid
	r.mu.RUnlock()
	if process == nil || pid <= 0 {
		return nil
	}

	sysSig, ok := sig.(syscall.Signal)
	if !ok {
		sysSig = syscall.SIGTERM
	}
	return syscall.Kill(-pid, sysSig)
}

func (r *SnortRunner) Run(ctx context.Context) error {
	args := []string{
		"--daq-dir", r.cfg.DAQDir,
		"-c", r.cfg.Paths.ConfigFile,
	}
	if r.cfg.Interface != "" {
		args = append(args, "-i", r.cfg.Interface)
	} else {
		args = append(args, "-r", r.cfg.PCAPPath)
	}
	args = append(args, r.cfg.ExtraArgs...)

	cmd := exec.Command(r.cfg.SnortBin, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	outputFile, err := os.Create(r.cfg.Paths.OutputPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outputFile.Close()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start snort: %w", err)
	}
	r.setPID(cmd.Process.Pid)
	r.setProcess(cmd.Process)
	defer r.clearProcess()
	r.logger.Printf("snort started with pid=%d", cmd.Process.Pid)

	var outputMu sync.Mutex
	writeLine := func(line string) {
		outputMu.Lock()
		defer outputMu.Unlock()
		fmt.Fprintln(os.Stdout, line)
		fmt.Fprintln(outputFile, line)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r.consumeOutput(stdout, writeLine)
	}()
	go func() {
		defer wg.Done()
		r.consumeOutput(stderr, writeLine)
	}()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		select {
		case err := <-waitCh:
			wg.Wait()
			if ctx.Err() != nil && err != nil {
				return ctx.Err()
			}
		case <-time.After(10 * time.Second):
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				select {
				case <-waitCh:
					wg.Wait()
				case <-time.After(5 * time.Second):
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					<-waitCh
					wg.Wait()
				}
			}
		}
		return ctx.Err()
	case err := <-waitCh:
		wg.Wait()
		if err != nil {
			return err
		}
		return nil
	}
}

func (r *SnortRunner) consumeOutput(reader io.Reader, writeLine func(string)) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		writeLine(line)
		if !looksLikeAlertJSON(line) {
			continue
		}

		alert, err := ParseAlertJSON(line)
		if err != nil {
			r.logger.Printf("ignore invalid alert json: %v", err)
			continue
		}
		r.alertStore.Insert(alert)
		r.broker.Publish(alert)
	}
	if err := scanner.Err(); err != nil {
		r.logger.Printf("scan snort output failed: %v", err)
	}
}

func looksLikeAlertJSON(line string) bool {
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "{") && strings.Contains(line, `"timestamp"`) && json.Valid([]byte(line))
}

type ProcessStats struct {
	PID        int       `json:"pid"`
	CPUSeconds float64   `json:"cpu_seconds"`
	MemoryRSS  int64     `json:"memory_rss_bytes"`
	Timestamp  time.Time `json:"timestamp"`
}

func (r *SnortRunner) Stats() (ProcessStats, error) {
	pid := r.PID()
	if pid <= 0 {
		return ProcessStats{}, fmt.Errorf("snort is not running")
	}

	cpuSeconds, err := readCPUSeconds(pid, r.cfg.ClockTicks)
	if err != nil {
		return ProcessStats{}, err
	}
	memoryRSS, err := readMemoryRSS(pid)
	if err != nil {
		return ProcessStats{}, err
	}
	return ProcessStats{
		PID:        pid,
		CPUSeconds: cpuSeconds,
		MemoryRSS:  memoryRSS,
		Timestamp:  time.Now(),
	}, nil
}
