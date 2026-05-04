package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type LuaOverride struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Value       string `json:"value"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

type AppSettings struct {
	RootDir             string        `json:"root_dir"`
	SWD                 string        `json:"swd"`
	AWD                 string        `json:"awd"`
	PcapDir             string        `json:"pcap_dir"`
	SnortConfigPath     string        `json:"snort_config_path"`
	SnortDBPath         string        `json:"snort_db_path"`
	RawRulePath         string        `json:"raw_rule_path"`
	RawSnortSQLite      string        `json:"raw_snort_sqlite"`
	Interface           string        `json:"interface"`
	Mode                string        `json:"mode"`
	PcapFile            string        `json:"pcap_file"`
	ActiveRunID         int64         `json:"active_run_id"`
	NeedOutput          bool          `json:"need_output"`
	NeedAlert           bool          `json:"need_alert"`
	NeedProfiler        bool          `json:"need_profiler"`
	LuaOverrides        []LuaOverride `json:"lua_overrides"`
	LastAppliedHash     string        `json:"last_applied_hash"`
	LastAppliedAt       string        `json:"last_applied_at,omitempty"`
	LastAppliedFinalRun int64         `json:"last_applied_final_run,omitempty"`
	UpdatedAt           string        `json:"updated_at"`
}

type JobRecord struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	WorkDir    string `json:"work_dir"`
	ConfigJSON string `json:"config_json"`
	ResultJSON string `json:"result_json,omitempty"`
	Error      string `json:"error,omitempty"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

type RuleOverride struct {
	RunID     int64  `json:"run_id"`
	GID       int64  `json:"gid"`
	SID       int64  `json:"sid"`
	Enabled   bool   `json:"enabled"`
	Reason    string `json:"reason,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.Ensure(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) Ensure() error {
	_, err := s.db.Exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS app_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	json TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
	id TEXT PRIMARY KEY,
	kind TEXT NOT NULL,
	status TEXT NOT NULL,
	work_dir TEXT NOT NULL,
	config_json TEXT NOT NULL,
	result_json TEXT,
	error TEXT,
	started_at TEXT NOT NULL,
	finished_at TEXT,
	updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_kind_updated ON jobs (kind, updated_at);
CREATE TABLE IF NOT EXISTS rule_overrides (
	run_id INTEGER NOT NULL,
	gid INTEGER NOT NULL,
	sid INTEGER NOT NULL,
	enabled INTEGER NOT NULL,
	reason TEXT,
	updated_at TEXT NOT NULL,
	PRIMARY KEY (run_id, gid, sid)
);
`)
	return err
}

func DefaultSettings(root string) AppSettings {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	serverRoot := filepath.Join(root, "server")
	swd := filepath.Join(serverRoot, "SWD")
	awd := filepath.Join(serverRoot, "AWD")
	pcapDir := filepath.Join(serverRoot, "pcap")
	return AppSettings{
		RootDir:         root,
		SWD:             swd,
		AWD:             awd,
		PcapDir:         pcapDir,
		SnortConfigPath: filepath.Join(root, "config", "snort.lua"),
		SnortDBPath:     filepath.Join(swd, "snort.sqlite"),
		RawRulePath:     filepath.Join(root, "config", "rules"),
		Interface:       "",
		Mode:            "interface",
		ActiveRunID:     0,
		NeedOutput:      true,
		NeedAlert:       true,
		NeedProfiler:    true,
		LuaOverrides:    []LuaOverride{},
		UpdatedAt:       now,
	}
}

func (s *Store) GetSettings(root string) (AppSettings, error) {
	var raw string
	err := s.db.QueryRow("SELECT json FROM app_settings WHERE id = 1;").Scan(&raw)
	if err == sql.ErrNoRows {
		settings := DefaultSettings(root)
		if err := s.SaveSettings(settings); err != nil {
			return settings, err
		}
		return settings, nil
	}
	if err != nil {
		return AppSettings{}, err
	}
	var settings AppSettings
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return AppSettings{}, err
	}
	settings = mergeSettingDefaults(settings, root)
	return settings, nil
}

func (s *Store) SaveSettings(settings AppSettings) error {
	settings.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO app_settings (id, json, updated_at)
VALUES (1, ?, ?)
ON CONFLICT(id) DO UPDATE SET json = excluded.json, updated_at = excluded.updated_at;`, string(raw), settings.UpdatedAt)
	return err
}

func (s *Store) MarkSettingsApplied(root, hash string) (AppSettings, error) {
	settings, err := s.GetSettings(root)
	if err != nil {
		return settings, err
	}
	settings.LastAppliedHash = hash
	settings.LastAppliedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return settings, s.SaveSettings(settings)
}

func (s *Store) MarkAppliedFinalRun(root string, runID int64) (AppSettings, error) {
	settings, err := s.GetSettings(root)
	if err != nil {
		return settings, err
	}
	settings.LastAppliedFinalRun = runID
	return settings, s.SaveSettings(settings)
}

func (s *Store) UpsertJob(job JobRecord) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if job.UpdatedAt == "" {
		job.UpdatedAt = now
	}
	if job.StartedAt == "" {
		job.StartedAt = now
	}
	_, err := s.db.Exec(`INSERT INTO jobs
(id, kind, status, work_dir, config_json, result_json, error, started_at, finished_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
	status = excluded.status,
	work_dir = excluded.work_dir,
	config_json = excluded.config_json,
	result_json = excluded.result_json,
	error = excluded.error,
	finished_at = excluded.finished_at,
	updated_at = excluded.updated_at;`,
		job.ID, job.Kind, job.Status, job.WorkDir, job.ConfigJSON, job.ResultJSON,
		job.Error, job.StartedAt, job.FinishedAt, job.UpdatedAt)
	return err
}

func (s *Store) LatestJob(kind string) (JobRecord, bool, error) {
	row := s.db.QueryRow(`SELECT id, kind, status, work_dir, config_json, COALESCE(result_json, ''),
COALESCE(error, ''), started_at, COALESCE(finished_at, ''), updated_at
FROM jobs WHERE kind = ? ORDER BY updated_at DESC LIMIT 1;`, kind)
	var job JobRecord
	err := row.Scan(&job.ID, &job.Kind, &job.Status, &job.WorkDir, &job.ConfigJSON,
		&job.ResultJSON, &job.Error, &job.StartedAt, &job.FinishedAt, &job.UpdatedAt)
	if err == sql.ErrNoRows {
		return JobRecord{}, false, nil
	}
	if err != nil {
		return JobRecord{}, false, err
	}
	return job, true, nil
}

func (s *Store) ListJobs(kind string, limit int) ([]JobRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT id, kind, status, work_dir, config_json, COALESCE(result_json, ''),
COALESCE(error, ''), started_at, COALESCE(finished_at, ''), updated_at
FROM jobs WHERE kind = ? ORDER BY updated_at DESC LIMIT ?;`, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JobRecord{}
	for rows.Next() {
		var job JobRecord
		if err := rows.Scan(&job.ID, &job.Kind, &job.Status, &job.WorkDir, &job.ConfigJSON,
			&job.ResultJSON, &job.Error, &job.StartedAt, &job.FinishedAt, &job.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

func (s *Store) GetJob(id string) (JobRecord, bool, error) {
	row := s.db.QueryRow(`SELECT id, kind, status, work_dir, config_json, COALESCE(result_json, ''),
COALESCE(error, ''), started_at, COALESCE(finished_at, ''), updated_at
FROM jobs WHERE id = ?;`, id)
	var job JobRecord
	err := row.Scan(&job.ID, &job.Kind, &job.Status, &job.WorkDir, &job.ConfigJSON,
		&job.ResultJSON, &job.Error, &job.StartedAt, &job.FinishedAt, &job.UpdatedAt)
	if err == sql.ErrNoRows {
		return JobRecord{}, false, nil
	}
	if err != nil {
		return JobRecord{}, false, err
	}
	return job, true, nil
}

func (s *Store) SaveRuleOverride(value RuleOverride) error {
	value.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	enabled := 0
	if value.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`INSERT INTO rule_overrides (run_id, gid, sid, enabled, reason, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(run_id, gid, sid) DO UPDATE SET
	enabled = excluded.enabled,
	reason = excluded.reason,
	updated_at = excluded.updated_at;`,
		value.RunID, value.GID, value.SID, enabled, value.Reason, value.UpdatedAt)
	return err
}

func (s *Store) ListRuleOverrides(runID int64, limit int) ([]RuleOverride, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT run_id, gid, sid, enabled, COALESCE(reason, ''), updated_at
FROM rule_overrides WHERE run_id = ? ORDER BY updated_at DESC LIMIT ?;`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RuleOverride
	for rows.Next() {
		var item RuleOverride
		var enabled int
		if err := rows.Scan(&item.RunID, &item.GID, &item.SID, &enabled, &item.Reason, &item.UpdatedAt); err != nil {
			return nil, err
		}
		item.Enabled = enabled != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

func MarshalConfig(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func mergeSettingDefaults(settings AppSettings, root string) AppSettings {
	defaults := DefaultSettings(root)
	if settings.RootDir == "" {
		settings.RootDir = defaults.RootDir
	}
	if settings.SWD == "" {
		settings.SWD = defaults.SWD
	}
	if settings.AWD == "" {
		settings.AWD = defaults.AWD
	}
	if settings.PcapDir == "" {
		settings.PcapDir = defaults.PcapDir
	}
	if settings.SnortConfigPath == "" {
		settings.SnortConfigPath = defaults.SnortConfigPath
	}
	if settings.SnortDBPath == "" {
		settings.SnortDBPath = filepath.Join(settings.SWD, "snort.sqlite")
	}
	if settings.RawRulePath == "" {
		settings.RawRulePath = defaults.RawRulePath
	}
	if settings.Mode == "" {
		settings.Mode = defaults.Mode
	}
	if !settings.NeedAlert && !settings.NeedOutput && !settings.NeedProfiler {
		settings.NeedAlert = defaults.NeedAlert
		settings.NeedOutput = defaults.NeedOutput
		settings.NeedProfiler = defaults.NeedProfiler
	}
	return settings
}

func NormalizePath(root, value string) string {
	if value == "" {
		return ""
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(root, value))
}

func EnsureRuntimeDirs(settings AppSettings) error {
	for _, path := range []string{settings.SWD, settings.AWD, settings.PcapDir} {
		if path == "" {
			return fmt.Errorf("runtime directory is empty")
		}
		if err := os.MkdirAll(path, 0755); err != nil {
			return err
		}
	}
	return nil
}
