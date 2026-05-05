package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"snort-optimizer/analyser"
	"snort-optimizer/analyser/iter"
	"snort-optimizer/analyser/safe"
	atypes "snort-optimizer/analyser/types"
	"snort-optimizer/server/configoptimize"
	"snort-optimizer/server/store"
	"snort-optimizer/wrap"
)

type strategySpec struct {
	Name string
	Fn   atypes.RegisteredFunction
}

func (s *Server) analysisStatus(decisionLimit, decisionOffset int) (AnalysisStatusResponse, error) {
	settings, err := s.currentSettings()
	if err != nil {
		return AnalysisStatusResponse{}, err
	}
	job, ok, err := s.store.LatestJob("analysis")
	if err != nil {
		return AnalysisStatusResponse{}, err
	}
	s.mu.Lock()
	running := s.analysisCancel != nil
	s.mu.Unlock()
	result, _ := loadAnalysisResult(settings.AWD, decisionLimit, decisionOffset, 100)
	expected := expectedAnalysisRuns(job.ConfigJSON)
	progress := 0.0
	if result != nil && expected > 0 {
		progress = float64(len(result.Runs)) / float64(expected)
		if progress > 1 {
			progress = 1
		}
	}
	if result != nil && (!running || (ok && job.Status == "completed")) {
		progress = 1
	}
	var jobPtr *store.JobRecord
	if ok {
		jobCopy := job
		jobPtr = &jobCopy
	}
	return AnalysisStatusResponse{
		Job:          jobPtr,
		Running:      running,
		Restored:     false,
		Progress:     progress,
		ExpectedRuns: expected,
		Result:       result,
		WorkDir:      settings.AWD,
	}, nil
}

func (s *Server) startAnalysis(req AnalysisStartRequest) (AnalysisStatusResponse, error) {
	settings, err := s.currentSettings()
	if err != nil {
		return AnalysisStatusResponse{}, err
	}
	if req.WorkDir == "" {
		req.WorkDir = settings.AWD
	} else {
		req.WorkDir = store.NormalizePath(s.root, req.WorkDir)
	}
	s.mu.Lock()
	if s.analysisCancel != nil {
		s.mu.Unlock()
		return AnalysisStatusResponse{}, fmt.Errorf("analysis job is already running")
	}
	s.mu.Unlock()

	cfg := atypes.Config{
		Pcap1:               choosePath(s.root, req.Pcap1, filepath.Join(s.root, "data", "Tuesday.pcap")),
		DB1:                 choosePath(s.root, req.DB1, filepath.Join(s.root, "data", "Tuesday.db")),
		Pcap2:               choosePath(s.root, req.Pcap2, filepath.Join(s.root, "data", "Monday.pcap")),
		AnalyserWorkingDir:  req.WorkDir,
		SnortConfig:         choosePath(s.root, req.SnortConfig, settings.SnortConfigPath),
		RawSnortSQLite:      choosePath(s.root, req.RawSnortSQLite, settings.RawSnortSQLite),
		RawRulePath:         choosePath(s.root, req.RawRulePath, settings.RawRulePath),
		MaxRound:            req.MaxRound,
		InitialFactor:       req.Factor,
		MaxMissRateIncrease: req.MaxMissRateIncrease,
		MaxFPRateIncrease:   req.MaxFPRateIncrease,
		LuaOverrides:        configoptimize.EnabledLuaValues(settings.LuaOverrides),
	}
	if cfg.RawSnortSQLite == "" && cfg.RawRulePath == "" {
		cfg.RawRulePath = settings.RawRulePath
	}
	rawCfg, err := store.MarshalConfig(map[string]any{
		"request":  req,
		"config":   cfg,
		"lua":      cfg.LuaOverrides,
		"strategy": req.Strategies,
		"disabled": req.DisabledStrategies,
	})
	if err != nil {
		return AnalysisStatusResponse{}, err
	}
	jobID := uuid.NewString()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	job := store.JobRecord{
		ID: jobID, Kind: "analysis", Status: "running", WorkDir: req.WorkDir,
		ConfigJSON: rawCfg, StartedAt: now, UpdatedAt: now,
	}
	if err := s.store.UpsertJob(job); err != nil {
		return AnalysisStatusResponse{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.analysisCancel = cancel
	s.analysisJobID = jobID
	s.mu.Unlock()
	go s.runAnalysisJob(ctx, job, cfg, req.Strategies, req.DisabledStrategies)
	return s.analysisStatus(80, 0)
}

func (s *Server) runAnalysisJob(ctx context.Context, job store.JobRecord, cfg atypes.Config, strategies, disabled []string) {
	finish := func(status string, result *atypes.Result, err error) {
		job.Status = status
		if result != nil {
			raw, _ := json.Marshal(result)
			job.ResultJSON = string(raw)
		}
		if err != nil {
			job.Error = err.Error()
		}
		job.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		job.UpdatedAt = job.FinishedAt
		_ = s.store.UpsertJob(job)
		s.mu.Lock()
		if s.analysisJobID == job.ID {
			s.analysisCancel = nil
			s.analysisJobID = ""
		}
		s.mu.Unlock()
	}
	a, err := analyser.New(cfg)
	if err != nil {
		finish("failed", nil, err)
		return
	}
	selected, err := selectStrategies(strategies, disabled)
	if err != nil {
		finish("failed", nil, err)
		return
	}
	a.RegisterAll(selected...)
	result, err := a.Run(ctx)
	if err != nil {
		if ctx.Err() != nil {
			finish("canceled", nil, ctx.Err())
			return
		}
		finish("failed", nil, err)
		return
	}
	finish("completed", result, nil)
}

func (s *Server) startCapture(req CaptureStartRequest) (CaptureSummary, error) {
	settings, err := s.currentSettings()
	if err != nil {
		return CaptureSummary{}, err
	}
	if req.Interface == "" {
		req.Interface = settings.Interface
	}
	if strings.TrimSpace(req.Interface) == "" {
		return CaptureSummary{}, fmt.Errorf("interface is required")
	}
	if req.DurationS <= 0 {
		req.DurationS = 60
	}
	if req.DurationS > 3600 {
		req.DurationS = 3600
	}
	if err := store.EnsureRuntimeDirs(settings); err != nil {
		return CaptureSummary{}, err
	}
	jobID := uuid.NewString()
	filename := cleanCaptureFilename(req.Filename)
	if filename == "" {
		filename = time.Now().UTC().Format("20060102_150405") + ".pcap"
	}
	path := filepath.Join(settings.PcapDir, filename)
	rawCfg, _ := store.MarshalConfig(map[string]any{"request": req, "path": path})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	job := store.JobRecord{
		ID: jobID, Kind: "capture", Status: "running", WorkDir: settings.PcapDir,
		ConfigJSON: rawCfg, StartedAt: now, UpdatedAt: now,
	}
	s.mu.Lock()
	if s.captureCancel != nil {
		s.mu.Unlock()
		return CaptureSummary{}, fmt.Errorf("capture job is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.captureCancel = cancel
	s.captureJobID = jobID
	s.mu.Unlock()
	if err := s.store.UpsertJob(job); err != nil {
		s.mu.Lock()
		if s.captureJobID == jobID {
			s.captureCancel = nil
			s.captureJobID = ""
		}
		s.mu.Unlock()
		cancel()
		return CaptureSummary{}, err
	}
	go s.runCaptureJob(ctx, job, req.Interface, req.DurationS, path)
	return CaptureSummary{ID: jobID, Status: "running", StartedAt: now}, nil
}

func (s *Server) runCaptureJob(ctx context.Context, job store.JobRecord, iface string, durationS int, path string) {
	start := time.Now()
	finish := func(status string, result *CaptureResult, err error) {
		job.Status = status
		if result != nil {
			raw, _ := json.Marshal(result)
			job.ResultJSON = string(raw)
		}
		if err != nil {
			job.Error = err.Error()
		}
		job.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		job.UpdatedAt = job.FinishedAt
		_ = s.store.UpsertJob(job)
		s.mu.Lock()
		if s.captureJobID == job.ID {
			s.captureCancel = nil
			s.captureJobID = ""
		}
		s.mu.Unlock()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		finish("failed", nil, err)
		return
	}
	args := []string{"-i", iface, "-s", "0", "-U", "-w", path}
	cmd, displayCommand := captureCommand(args)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		finish("failed", nil, fmt.Errorf("start tcpdump: %w", err))
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(time.Duration(durationS) * time.Second)
	defer timer.Stop()
	stoppedByTimer := false
	select {
	case <-ctx.Done():
	case <-timer.C:
		stoppedByTimer = true
	case err := <-done:
		timer.Stop()
		if err != nil {
			finish("failed", nil, fmt.Errorf("tcpdump exited: %w: %s", err, strings.TrimSpace(stderr.String())))
			return
		}
	}
	if stoppedByTimer || ctx.Err() != nil {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err != nil {
			pgid = cmd.Process.Pid
		}
		_ = syscall.Kill(-pgid, syscall.SIGINT)
		select {
		case err := <-done:
			if err != nil && !stoppedByTimer && ctx.Err() == nil {
				finish("failed", nil, fmt.Errorf("tcpdump stopped: %w: %s", err, strings.TrimSpace(stderr.String())))
				return
			}
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			<-done
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		finish("failed", nil, err)
		return
	}
	status := "completed"
	var finishErr error
	if ctx.Err() != nil && !stoppedByTimer {
		status = "canceled"
		finishErr = ctx.Err()
	}
	finish(status, &CaptureResult{
		Interface:  iface,
		DurationMS: time.Since(start).Milliseconds(),
		Path:       path,
		Size:       info.Size(),
		Command:    displayCommand,
		Output:     strings.TrimSpace(stderr.String()),
	}, finishErr)
}

func captureCommand(args []string) (*exec.Cmd, string) {
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		tcpdumpPath = "tcpdump"
	}
	if os.Geteuid() != 0 {
		if pkexecPath, err := exec.LookPath("pkexec"); err == nil {
			pkArgs := append([]string{tcpdumpPath}, args...)
			return exec.Command(pkexecPath, pkArgs...), strings.Join(append([]string{"pkexec", tcpdumpPath}, args...), " ")
		}
	}
	return exec.Command(tcpdumpPath, args...), strings.Join(append([]string{tcpdumpPath}, args...), " ")
}

func (s *Server) latestCaptureSummaries(limit int) []CaptureSummary {
	jobs, err := s.store.ListJobs("capture", limit)
	if err != nil {
		return nil
	}
	out := []CaptureSummary{}
	for _, job := range jobs {
		item := CaptureSummary{
			ID: job.ID, Status: job.Status, Error: job.Error, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
		}
		if job.ResultJSON != "" {
			var result CaptureResult
			if json.Unmarshal([]byte(job.ResultJSON), &result) == nil {
				item.Result = &result
			}
		}
		out = append(out, item)
	}
	return out
}

func (s *Server) startPerfTest(req PerfTestStartRequest) (PerfTestSummary, error) {
	settings, err := s.currentSettings()
	if err != nil {
		return PerfTestSummary{}, err
	}
	if req.Mode == "" {
		req.Mode = wrap.ModePCAP
	}
	runID := time.Now().Unix()
	jobID := uuid.NewString()
	workDir := filepath.Join(s.root, "SNORT_TEST_WD", "perf-"+jobID)
	dbPath := filepath.Join(workDir, "snort.sqlite")
	cfg := wrap.Config{
		Mode:            req.Mode,
		SnortWorkingDir: workDir,
		SnortConfigPath: settings.SnortConfigPath,
		SnortDBPath:     dbPath,
		RawRulePath:     settings.RawRulePath,
		RunID:           runID,
		NeedOutput:      true,
		NeedAlert:       true,
		NeedProfiler:    true,
		LuaOverrides:    configoptimize.EnabledLuaValues(settings.LuaOverrides),
	}
	if req.Mode == wrap.ModeInterface {
		cfg.Interface = chooseString(req.Interface, settings.Interface)
		if req.DurationS <= 0 {
			req.DurationS = 30
		}
	} else {
		cfg.PcapFile = choosePath(s.root, req.PcapFile, settings.PcapFile)
		if cfg.PcapFile == "" {
			return PerfTestSummary{}, fmt.Errorf("pcap_file is required for pcap performance test")
		}
	}
	if err := copyRulesBetweenDBs(settings.SnortDBPath, dbPath, settings.ActiveRunID, runID); err != nil {
		return PerfTestSummary{}, fmt.Errorf("copy production rules for performance test: %w", err)
	}
	rawCfg, _ := store.MarshalConfig(map[string]any{
		"request":       req,
		"wrap":          cfg,
		"source_db":     settings.SnortDBPath,
		"lua_overrides": settings.LuaOverrides,
	})
	now := time.Now().UTC().Format(time.RFC3339Nano)
	job := store.JobRecord{
		ID: jobID, Kind: "perf", Status: "running", WorkDir: workDir,
		ConfigJSON: rawCfg, StartedAt: now, UpdatedAt: now,
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	if len(s.perfCancels) > 0 {
		s.mu.Unlock()
		cancel()
		return PerfTestSummary{}, fmt.Errorf("performance test is already running")
	}
	s.perfCancels[jobID] = cancel
	s.mu.Unlock()
	if err := s.store.UpsertJob(job); err != nil {
		s.mu.Lock()
		delete(s.perfCancels, jobID)
		s.mu.Unlock()
		cancel()
		return PerfTestSummary{}, err
	}
	go s.runPerfJob(ctx, job, cfg, req.DurationS)
	return PerfTestSummary{ID: jobID, Status: "running", StartedAt: now}, nil
}

func (s *Server) runPerfJob(ctx context.Context, job store.JobRecord, cfg wrap.Config, durationS int) {
	start := time.Now()
	finish := func(status string, result *PerfTestResult, err error) {
		job.Status = status
		if result != nil {
			raw, _ := json.Marshal(result)
			job.ResultJSON = string(raw)
		}
		if err != nil {
			job.Error = err.Error()
		}
		job.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		job.UpdatedAt = job.FinishedAt
		_ = s.store.UpsertJob(job)
		s.mu.Lock()
		delete(s.perfCancels, job.ID)
		s.mu.Unlock()
	}
	runner, err := wrap.NewRunner(cfg)
	if err != nil {
		finish("failed", nil, err)
		return
	}
	if err := runner.Start(); err != nil {
		finish("failed", nil, err)
		return
	}
	stats := runner.StartupStats()
	if cfg.Mode == wrap.ModeInterface && durationS > 0 {
		timer := time.NewTimer(time.Duration(durationS) * time.Second)
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		timer.Stop()
		if err := runner.Stop(); err != nil {
			finish("failed", nil, err)
			return
		}
	} else {
		if err := runner.Wait(ctx); err != nil {
			if ctx.Err() == nil {
				_ = runner.Stop()
				finish("failed", nil, err)
				return
			}
			if stopErr := runner.Stop(); stopErr != nil {
				finish("failed", nil, stopErr)
				return
			}
		}
	}
	profiles, _ := querySystemProfiles(cfg.SnortDBPath, cfg.RunID, 20)
	throughputPPS, throughputMbps := queryPerfThroughput(cfg.SnortDBPath, cfg.RunID)
	ruleTime, _ := sumRuleTime(cfg.SnortDBPath, cfg.RunID)
	alerts, _ := countTableRun(cfg.SnortDBPath, "alerts", cfg.RunID)
	rules, _ := countTableRun(cfg.SnortDBPath, "rules", cfg.RunID)
	finish("completed", &PerfTestResult{
		RunID:           cfg.RunID,
		Mode:            cfg.Mode,
		DurationMS:      time.Since(start).Milliseconds(),
		WorkDir:         cfg.SnortWorkingDir,
		DBPath:          cfg.SnortDBPath,
		Profiles:        profiles,
		ThroughputPPS:   throughputPPS,
		ThroughputMbps:  throughputMbps,
		RuleTimeUS:      ruleTime,
		AlertCount:      alerts,
		RuleCount:       rules,
		LoadedRuleCount: stats.LoadedRuleCount,
	}, nil)
}

func (s *Server) latestPerfSummaries(limit int) []PerfTestSummary {
	jobs, err := s.store.ListJobs("perf", limit)
	if err != nil {
		return nil
	}
	out := []PerfTestSummary{}
	for _, job := range jobs {
		item := PerfTestSummary{
			ID: job.ID, Status: job.Status, Error: job.Error, StartedAt: job.StartedAt, FinishedAt: job.FinishedAt,
		}
		var rawConfig struct {
			LuaOverrides []store.LuaOverride `json:"lua_overrides"`
		}
		if job.ConfigJSON != "" && json.Unmarshal([]byte(job.ConfigJSON), &rawConfig) == nil {
			item.Config = rawConfig.LuaOverrides
		}
		if job.ResultJSON != "" {
			var result PerfTestResult
			if json.Unmarshal([]byte(job.ResultJSON), &result) == nil {
				item.Result = &result
			}
		}
		out = append(out, item)
	}
	return out
}

func builtinStrategies() []strategySpec {
	return []strategySpec{
		{Name: "safe_source_file_browser", Fn: safe.SourceFileBrowser()},
		{Name: "safe_source_file_protocols", Fn: safe.SourceFileProtocols()},
		{Name: "safe_inactive_systemd_services", Fn: safe.InactiveSystemdServices()},
		{Name: "safe_orphan_flowbits", Fn: safe.OrphanFlowbits()},
		{Name: "iter_protocol_alert_overlap", Fn: iter.ProtocolAlertOverlap()},
		{Name: "iter_high_fp_low_utilization", Fn: iter.HighFPLowUtilization()},
		{Name: "iter_low_yield_hot_rules", Fn: iter.LowYieldHotRules()},
		{Name: "iter_high_cost_rules", Fn: iter.HighCostRules()},
	}
}

func selectStrategies(enabled, disabled []string) ([]atypes.RegisteredFunction, error) {
	specs := builtinStrategies()
	byName := make(map[string]atypes.RegisteredFunction, len(specs))
	for _, spec := range specs {
		byName[spec.Name] = spec.Fn
	}
	selected := map[string]bool{}
	if len(enabled) == 0 {
		for _, spec := range specs {
			selected[spec.Name] = true
		}
	} else {
		for _, name := range enabled {
			switch name {
			case "all":
				for _, spec := range specs {
					selected[spec.Name] = true
				}
			case "none":
				for key := range selected {
					delete(selected, key)
				}
			default:
				if _, ok := byName[name]; !ok {
					return nil, fmt.Errorf("unknown strategy %q", name)
				}
				selected[name] = true
			}
		}
	}
	for _, name := range disabled {
		if _, ok := byName[name]; !ok {
			return nil, fmt.Errorf("unknown strategy %q", name)
		}
		delete(selected, name)
	}
	out := make([]atypes.RegisteredFunction, 0, len(selected))
	for _, spec := range specs {
		if selected[spec.Name] {
			out = append(out, spec.Fn)
		}
	}
	return out, nil
}

func expectedAnalysisRuns(configJSON string) int {
	var raw struct {
		Request AnalysisStartRequest `json:"request"`
	}
	if configJSON != "" && json.Unmarshal([]byte(configJSON), &raw) == nil {
		return expectedAnalysisRunsFromRequest(raw.Request)
	}
	return 18
}

func expectedAnalysisRunsFromRequest(req AnalysisStartRequest) int {
	maxRound := req.MaxRound
	if maxRound <= 0 {
		maxRound = atypes.DefaultMaxRound
	}
	selected, err := selectedStrategyNames(req.Strategies, req.DisabledStrategies)
	if err != nil {
		return 18
	}
	safeEnabled := false
	iterCount := 0
	for _, name := range selected {
		if strings.HasPrefix(name, "safe_") {
			safeEnabled = true
		}
		if strings.HasPrefix(name, "iter_") {
			iterCount++
		}
	}
	expected := 1 + iterCount*maxRound
	if safeEnabled {
		expected++
	}
	return expected
}

func selectedStrategyNames(enabled, disabled []string) ([]string, error) {
	specs := builtinStrategies()
	known := map[string]bool{}
	selected := map[string]bool{}
	for _, spec := range specs {
		known[spec.Name] = true
	}
	if len(enabled) == 0 {
		for _, spec := range specs {
			selected[spec.Name] = true
		}
	} else {
		for _, name := range enabled {
			switch name {
			case "all":
				for _, spec := range specs {
					selected[spec.Name] = true
				}
			case "none":
				for key := range selected {
					delete(selected, key)
				}
			default:
				if !known[name] {
					return nil, fmt.Errorf("unknown strategy %q", name)
				}
				selected[name] = true
			}
		}
	}
	for _, name := range disabled {
		if !known[name] {
			return nil, fmt.Errorf("unknown strategy %q", name)
		}
		delete(selected, name)
	}
	out := []string{}
	for _, spec := range specs {
		if selected[spec.Name] {
			out = append(out, spec.Name)
		}
	}
	return out, nil
}

func choosePath(root, value, fallback string) string {
	if value == "" {
		return fallback
	}
	return store.NormalizePath(root, value)
}

func chooseString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func cleanCaptureFilename(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	name := filepath.Base(value)
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".pcap" && ext != ".pcapng" {
		name += ".pcap"
	}
	return sanitizeFilenamePart(name)
}

func sanitizeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "capture"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	cleaned := strings.Trim(b.String(), "._-")
	if cleaned == "" {
		return "capture"
	}
	return cleaned
}

func sumRuleTime(dbPath string, runID int64) (int64, error) {
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var value int64
	err = conn.QueryRow("SELECT COALESCE(sum(time_us), 0) FROM rule_profiler_metrics WHERE run_id = ?;", runID).Scan(&value)
	return value, err
}

func countTableRun(dbPath, table string, runID int64) (int64, error) {
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var value int64
	err = conn.QueryRow("SELECT count(*) FROM "+table+" WHERE run_id = ?;", runID).Scan(&value)
	return value, err
}

func queryPerfThroughput(dbPath string, runID int64) (float64, float64) {
	conn, err := sqlOpen(dbPath)
	if err != nil {
		return 0, 0
	}
	defer conn.Close()
	return queryProfilerMetricValue(conn, runID, []string{"pkts/sec", "packets/sec"}),
		queryProfilerMetricValue(conn, runID, []string{"Mbits/sec", "mbits/sec"})
}

func queryProfilerMetricValue(conn *sql.DB, runID int64, metrics []string) float64 {
	for _, metric := range metrics {
		var value sql.NullFloat64
		err := conn.QueryRow(`SELECT value FROM profiler_metrics
WHERE run_id = ? AND lower(metric) = lower(?)
ORDER BY id DESC LIMIT 1;`, runID, metric).Scan(&value)
		if err == nil && value.Valid {
			return value.Float64
		}
	}
	return 0
}

func sortedStrategyNames() []string {
	names := []string{}
	for _, spec := range builtinStrategies() {
		names = append(names, spec.Name)
	}
	sort.Strings(names)
	return names
}
