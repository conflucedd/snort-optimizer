package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"snort-optimizer/server/configoptimize"
	"snort-optimizer/server/store"
	"snort-optimizer/server/systemoptimize"
	sqlstore "snort-optimizer/sql"
	sqldb "snort-optimizer/sql/db"
	"snort-optimizer/wrap"

	_ "modernc.org/sqlite"
)

type Server struct {
	root   string
	store  *store.Store
	logger *log.Logger

	mu             sync.Mutex
	runner         *wrap.Runner
	analysisCancel context.CancelFunc
	analysisJobID  string
	captureCancel  context.CancelFunc
	captureJobID   string
	perfCancels    map[string]context.CancelFunc
	sampler        processSampler
}

func New(root string, st *store.Store, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(os.Stderr, "server: ", log.LstdFlags)
	}
	return &Server{
		root:        root,
		store:       st,
		logger:      logger,
		perfCancels: map[string]context.CancelFunc{},
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/files/pcaps", s.handlePcapFiles)
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/snort/start", s.handleSnortStart)
	mux.HandleFunc("/api/snort/stop", s.handleSnortStop)
	mux.HandleFunc("/api/snort/restart", s.handleSnortRestart)
	mux.HandleFunc("/api/snort/reset", s.handleSnortReset)
	mux.HandleFunc("/api/perf-tests", s.handlePerfTests)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/analysis/status", s.handleAnalysisStatus)
	mux.HandleFunc("/api/analysis/strategies", s.handleAnalysisStrategies)
	mux.HandleFunc("/api/analysis/start", s.handleAnalysisStart)
	mux.HandleFunc("/api/analysis/cancel", s.handleAnalysisCancel)
	mux.HandleFunc("/api/analysis/apply", s.handleAnalysisApply)
	mux.HandleFunc("/api/capture/start", s.handleCaptureStart)
	mux.HandleFunc("/api/capture/status", s.handleCaptureStatus)
	mux.HandleFunc("/api/config/lua-presets", s.handleLuaPresets)
	mux.HandleFunc("/api/config/rules", s.handleRules)
	mux.HandleFunc("/api/config/rules/toggle", s.handleRuleToggle)
	mux.HandleFunc("/api/config/recommendations", s.handleRecommendations)
	mux.HandleFunc("/api/system/status", s.handleSystemStatus)
	mux.HandleFunc("/api/system/offload", s.handleSystemOffload)
	mux.HandleFunc("/api/system/affinity", s.handleSystemAffinity)
	return withCORS(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC().Format(time.RFC3339Nano)})
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		settings, err := s.currentSettings()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.writeSettings(w, settings)
	case http.MethodPut:
		var incoming store.AppSettings
		if err := decodeJSON(r, &incoming); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		current, err := s.currentSettings()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		merged := mergeIncomingSettings(s.root, current, incoming)
		merged.LuaOverrides = configoptimize.MergePresetMetadata(merged.LuaOverrides)
		if err := store.EnsureRuntimeDirs(merged); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.SaveSettings(merged); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.writeSettings(w, merged)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handlePcapFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	files := listFilesFromDirs(s.root, []string{"data", "real_pcap", settings.PcapDir}, []string{".pcap", ".pcapng"})
	writeJSON(w, http.StatusOK, FileListResponse{Files: files})
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	status := s.runnerStatus()
	hash := configHash(settings)
	dbStats := s.dbStats(settings)
	perfTests := s.latestPerfSummaries(5)
	response := OverviewResponse{
		Status:       status,
		Running:      status.RunInfo.Running,
		NeedsRestart: status.RunInfo.Running && hash != settings.LastAppliedHash,
		ConfigHash:   hash,
		Telemetry:    s.telemetry(status.RunInfo.PID),
		DBStats:      dbStats,
		PerfTests:    perfTests,
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleSnortStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := s.startRunner(false); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settings, _ := s.currentSettings()
	writeJSON(w, http.StatusOK, map[string]any{"status": s.runnerStatus(), "settings": settings})
}

func (s *Server) handleSnortStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	runner := s.runner
	s.mu.Unlock()
	if runner != nil {
		if err := runner.Stop(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": s.runnerStatus()})
}

func (s *Server) handleSnortRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := s.startRunner(true); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": s.runnerStatus()})
}

func (s *Server) handleSnortReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	runner := s.runner
	s.mu.Unlock()
	if runner != nil {
		if err := runner.Stop(); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if err := sqlstore.Reset(sqlstore.Config{DBPath: settings.SnortDBPath, RunID: settings.ActiveRunID}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePerfTests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"items": s.latestPerfSummaries(20)})
	case http.MethodPost:
		var req PerfTestStartRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		job, err := s.startPerfTest(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	q := r.URL.Query()
	limit := clampInt(queryInt(q.Get("limit"), 100), 1, 1000)
	offset := clampInt(queryInt(q.Get("offset"), 0), 0, 1_000_000_000)
	runID := queryInt64Default(q.Get("run_id"), settings.ActiveRunID)
	response, err := queryAlerts(settings.SnortDBPath, alertQuery{
		RunID:  runID,
		Limit:  limit,
		Offset: offset,
		SID:    queryInt64(q.Get("sid")),
		GID:    queryInt64(q.Get("gid")),
		Proto:  q.Get("proto"),
		Action: q.Get("action"),
		Search: q.Get("q"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAnalysisStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	response, err := s.analysisStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleAnalysisStrategies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	items := []AnalysisStrategy{}
	for _, spec := range builtinStrategies() {
		items = append(items, AnalysisStrategy{Name: spec.Name, Type: string(spec.Fn.Type)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAnalysisStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req AnalysisStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	response, err := s.startAnalysis(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, response)
}

func (s *Server) handleAnalysisCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.mu.Lock()
	cancel := s.analysisCancel
	jobID := s.analysisJobID
	s.analysisCancel = nil
	s.analysisJobID = ""
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if jobID != "" {
		if job, ok, err := s.store.GetJob(jobID); err == nil && ok {
			job.Status = "canceled"
			job.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
			job.UpdatedAt = job.FinishedAt
			_ = s.store.UpsertJob(job)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAnalysisApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		RunID int64 `json:"run_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if req.RunID < 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("run_id must be >= 0"))
		return
	}
	if req.RunID == 0 {
		result, err := loadAnalysisResult(settings.AWD, 200, 100)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		req.RunID = result.FinalRunID
	}
	sourceDB := filepath.Join(settings.AWD, "exp", "snort.sqlite")
	if err := copyRulesBetweenDBs(sourceDB, settings.SnortDBPath, req.RunID, settings.ActiveRunID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if _, err := s.store.MarkAppliedFinalRun(s.root, req.RunID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "applied_run_id": req.RunID, "target_run_id": settings.ActiveRunID})
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req CaptureStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	job, err := s.startCapture(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": s.latestCaptureSummaries(10)})
}

func (s *Server) handleLuaPresets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": configoptimize.Presets()})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	q := r.URL.Query()
	limit := clampInt(queryInt(q.Get("limit"), 100), 1, 1000)
	offset := clampInt(queryInt(q.Get("offset"), 0), 0, 1_000_000_000)
	runID := queryInt64Default(q.Get("run_id"), settings.ActiveRunID)
	response, err := queryRules(settings.SnortDBPath, ruleQuery{
		RunID:     runID,
		Limit:     limit,
		Offset:    offset,
		SID:       queryInt64(q.Get("sid")),
		GID:       queryInt64(q.Get("gid")),
		Search:    q.Get("q"),
		Classtype: q.Get("classtype"),
		Enabled:   optionalBool(q.Get("enabled")),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req RuleToggleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if req.RunID == 0 {
		req.RunID = settings.ActiveRunID
	}
	if req.GID <= 0 || req.SID <= 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("gid and sid are required"))
		return
	}
	cfg := sqlstore.Config{DBPath: settings.SnortDBPath, RunID: req.RunID}
	if err := sqlstore.SetRuleEnabled(cfg, req.GID, req.SID, req.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.store.SaveRuleOverride(store.RuleOverride{
		RunID: req.RunID, GID: req.GID, SID: req.SID, Enabled: req.Enabled, Reason: req.Reason,
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRecommendations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	settings, err := s.currentSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	limit := clampInt(queryInt(r.URL.Query().Get("limit"), 80), 1, 300)
	items, err := queryRecommendations(settings.AWD, settings.SnortDBPath, settings.ActiveRunID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, RecommendationResponse{Items: items})
}

func (s *Server) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	interfaces, _ := systemoptimize.ListInterfaces()
	status := s.runnerStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"interfaces": interfaces,
		"cpu":        systemoptimize.Status(status.RunInfo.PID),
	})
}

func (s *Server) handleSystemOffload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		Interface string `json:"interface"`
		Feature   string `json:"feature"`
		Enabled   bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Interface == "" || req.Feature == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("interface and feature are required"))
		return
	}
	writeJSON(w, http.StatusOK, systemoptimize.SetOffload(req.Interface, req.Feature, req.Enabled))
}

func (s *Server) handleSystemAffinity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var req struct {
		CPUs string `json:"cpus"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	status := s.runnerStatus()
	writeJSON(w, http.StatusOK, systemoptimize.SetAffinity(status.RunInfo.PID, req.CPUs))
}

func (s *Server) currentSettings() (store.AppSettings, error) {
	settings, err := s.store.GetSettings(s.root)
	if err != nil {
		return settings, err
	}
	settings.LuaOverrides = configoptimize.MergePresetMetadata(settings.LuaOverrides)
	return settings, nil
}

func (s *Server) writeSettings(w http.ResponseWriter, settings store.AppSettings) {
	hash := configHash(settings)
	status := s.runnerStatus()
	writeJSON(w, http.StatusOK, SettingsResponse{
		Settings:     settings,
		EffectiveLua: configoptimize.EnabledLuaValues(settings.LuaOverrides),
		ConfigHash:   hash,
		NeedsRestart: status.RunInfo.Running && hash != settings.LastAppliedHash,
	})
}

func (s *Server) startRunner(forceRestart bool) error {
	settings, err := s.currentSettings()
	if err != nil {
		return err
	}
	if err := store.EnsureRuntimeDirs(settings); err != nil {
		return err
	}
	cfg := buildWrapConfig(settings)
	runner, err := wrap.NewRunner(cfg)
	if err != nil {
		return err
	}

	s.mu.Lock()
	current := s.runner
	if current != nil && current.Status().RunInfo.Running && !forceRestart {
		s.mu.Unlock()
		return fmt.Errorf("snort is already running")
	}
	s.runner = runner
	s.mu.Unlock()

	if current != nil {
		if err := current.Stop(); err != nil {
			return err
		}
	}
	if err := runner.Start(); err != nil {
		s.mu.Lock()
		if s.runner == runner {
			s.runner = current
		}
		s.mu.Unlock()
		return err
	}
	_, err = s.store.MarkSettingsApplied(s.root, configHash(settings))
	return err
}

func (s *Server) runnerStatus() wrap.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runner == nil {
		settings, _ := s.currentSettingsNoDecorate()
		return wrap.Status{Config: buildWrapConfig(settings)}
	}
	return s.runner.Status()
}

func (s *Server) currentSettingsNoDecorate() (store.AppSettings, error) {
	return s.store.GetSettings(s.root)
}

func buildWrapConfig(settings store.AppSettings) wrap.Config {
	return wrap.Config{
		Mode:            settings.Mode,
		SnortWorkingDir: settings.SWD,
		SnortConfigPath: settings.SnortConfigPath,
		SnortDBPath:     settings.SnortDBPath,
		RawRulePath:     settings.RawRulePath,
		Interface:       settings.Interface,
		PcapFile:        settings.PcapFile,
		RunID:           0,
		NeedOutput:      settings.NeedOutput,
		NeedAlert:       true,
		NeedProfiler:    settings.NeedProfiler,
		LuaOverrides:    configoptimize.EnabledLuaValues(settings.LuaOverrides),
	}
}

func configHash(settings store.AppSettings) string {
	effective := struct {
		SWD             string   `json:"swd"`
		SnortConfigPath string   `json:"snort_config_path"`
		SnortDBPath     string   `json:"snort_db_path"`
		RawRulePath     string   `json:"raw_rule_path"`
		Mode            string   `json:"mode"`
		Interface       string   `json:"interface"`
		PcapFile        string   `json:"pcap_file"`
		NeedOutput      bool     `json:"need_output"`
		NeedAlert       bool     `json:"need_alert"`
		NeedProfiler    bool     `json:"need_profiler"`
		Lua             []string `json:"lua"`
	}{
		SWD:             settings.SWD,
		SnortConfigPath: settings.SnortConfigPath,
		SnortDBPath:     settings.SnortDBPath,
		RawRulePath:     settings.RawRulePath,
		Mode:            settings.Mode,
		Interface:       settings.Interface,
		PcapFile:        settings.PcapFile,
		NeedOutput:      settings.NeedOutput,
		NeedAlert:       true,
		NeedProfiler:    settings.NeedProfiler,
		Lua:             configoptimize.EnabledLuaValues(settings.LuaOverrides),
	}
	raw, _ := json.Marshal(effective)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func mergeIncomingSettings(root string, current, incoming store.AppSettings) store.AppSettings {
	out := current
	if incoming.SWD != "" {
		out.SWD = cleanSettingPath(incoming.SWD)
	}
	if incoming.AWD != "" {
		out.AWD = cleanSettingPath(incoming.AWD)
	}
	if incoming.PcapDir != "" {
		out.PcapDir = cleanSettingPath(incoming.PcapDir)
	}
	if incoming.SnortConfigPath != "" {
		out.SnortConfigPath = cleanSettingPath(incoming.SnortConfigPath)
	}
	if incoming.SnortDBPath != "" {
		out.SnortDBPath = cleanSettingPath(incoming.SnortDBPath)
	} else if incoming.SWD != "" {
		out.SnortDBPath = filepath.Join(out.SWD, "snort.sqlite")
	}
	if incoming.RawRulePath != "" {
		out.RawRulePath = cleanSettingPath(incoming.RawRulePath)
	}
	if incoming.RawSnortSQLite != "" {
		out.RawSnortSQLite = cleanSettingPath(incoming.RawSnortSQLite)
	}
	if incoming.Interface != "" || current.Interface != "" {
		out.Interface = incoming.Interface
	}
	if incoming.Mode != "" {
		out.Mode = incoming.Mode
	}
	if incoming.PcapFile != "" || current.PcapFile != "" {
		out.PcapFile = cleanSettingPath(incoming.PcapFile)
	}
	out.ActiveRunID = 0
	out.NeedOutput = incoming.NeedOutput
	out.NeedAlert = true
	out.NeedProfiler = incoming.NeedProfiler
	if incoming.LuaOverrides != nil {
		out.LuaOverrides = incoming.LuaOverrides
	}
	if incoming.AnalysisDisabledStrategies != nil {
		out.AnalysisDisabledStrategies = cleanStrategyNames(incoming.AnalysisDisabledStrategies)
	}
	return out
}

func cleanStrategyNames(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func cleanSettingPath(value string) string {
	if value == "" {
		return ""
	}
	return filepath.Clean(value)
}

func (s *Server) dbStats(settings store.AppSettings) map[string]any {
	stats := map[string]any{}
	cfg := sqlstore.Config{DBPath: settings.SnortDBPath, RunID: settings.ActiveRunID}
	counts, err := sqlstore.CountTables(cfg)
	if err == nil {
		stats["tables"] = counts
	}
	stats["path"] = settings.SnortDBPath
	stats["exists"] = fileExists(settings.SnortDBPath)
	if alertSummary, err := queryAlertSummary(settings.SnortDBPath, settings.ActiveRunID); err == nil {
		stats["alerts"] = alertSummary
	}
	return stats
}

func (s *Server) telemetry(pid int) TelemetrySample {
	sample := TelemetrySample{Time: time.Now().UTC().Format(time.RFC3339Nano), PID: pid}
	if pid > 0 {
		proc := s.sampler.Sample(pid)
		sample.CPUPercent = proc.CPUPercent
		sample.MemMB = proc.MemMB
	}
	conns := readConnectionCounts()
	sample.SystemConnections = conns.Total
	sample.EstablishedTCP = conns.EstablishedTCP
	sample.UDPConnections = conns.UDP
	return sample
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, APIError{Error: err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func queryInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func queryInt64(value string) int64 {
	n, _ := strconv.ParseInt(value, 10, 64)
	return n
}

func queryInt64Default(value string, fallback int64) int64 {
	if value == "" {
		return fallback
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func optionalBool(value string) *bool {
	if value == "" {
		return nil
	}
	v := value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes")
	return &v
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func listFiles(dir string, exts []string) []FileItem {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, ext := range exts {
		allowed[strings.ToLower(ext)] = true
	}
	out := []FileItem{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if len(allowed) > 0 && !allowed[strings.ToLower(filepath.Ext(path))] {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		out = append(out, FileItem{
			Path:    path,
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339Nano),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime > out[j].ModTime })
	return out
}

func listFilesFromDirs(root string, dirs []string, exts []string) []FileItem {
	seenDirs := map[string]bool{}
	seenFiles := map[string]bool{}
	out := []FileItem{}
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		scanDir := dir
		if !filepath.IsAbs(scanDir) {
			scanDir = filepath.Join(root, scanDir)
		}
		scanDir = filepath.Clean(scanDir)
		if seenDirs[scanDir] {
			continue
		}
		seenDirs[scanDir] = true
		for _, file := range listFiles(scanDir, exts) {
			absPath := file.Path
			if !filepath.IsAbs(absPath) {
				absPath = filepath.Join(scanDir, file.Name)
			}
			absPath = filepath.Clean(absPath)
			if seenFiles[absPath] {
				continue
			}
			seenFiles[absPath] = true
			if rel, err := filepath.Rel(root, absPath); err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".." {
				file.Path = filepath.Clean(rel)
			} else {
				file.Path = absPath
			}
			out = append(out, file)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ModTime == out[j].ModTime {
			return out[i].Path < out[j].Path
		}
		return out[i].ModTime > out[j].ModTime
	})
	return out
}

func sqlOpen(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is empty")
	}
	return sql.Open("sqlite", path)
}

func quote(value string) string {
	return sqldb.Quote(value)
}
