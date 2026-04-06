package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type AppPaths struct {
	ConfigDir    string
	ConfigFile   string
	RulesDBPath  string
	AllRulesPath string
	AlertDBPath  string
	OutputPath   string
	SiteDir      string
}

type RuntimeConfig struct {
	SnortBin   string
	DAQDir     string
	PCAPPath   string
	Interface  string
	ExtraArgs  []string
	HTTPAddr   string
	ClockTicks float64
	Paths      AppPaths
}

func LoadRuntimeConfig() (RuntimeConfig, error) {
	configDir := envOrDefault("SNORT_CONFIG_DIR", "config")
	configFile := envOrDefault("SNORT_CONFIG_FILE", filepath.Join(configDir, "snort.lua"))
	alertDBPath := envOrDefault("SNORT_ALERT_DB", filepath.Join("data", "alert.db"))
	outputPath := envOrDefault("SNORT_OUTPUT_FILE", "snort_output.txt")
	siteDir := envOrDefault("SNORT_SITE_DIR", detectSiteDir())

	cfg := RuntimeConfig{
		SnortBin:   envOrDefault("SNORT_BIN", filepath.Join("snort", "install", "bin", "snort")),
		DAQDir:     envOrDefault("SNORT_DAQ_DIR", filepath.Join("snort", "libdaq", "build", "lib", "daq")),
		PCAPPath:   os.Getenv("SNORT_PCAP"),
		Interface:  os.Getenv("SNORT_INTERFACE"),
		ExtraArgs:  strings.Fields(os.Getenv("SNORT_EXTRA_ARGS")),
		HTTPAddr:   envOrDefault("HTTP_ADDR", ":8080"),
		ClockTicks: 100,
		Paths: AppPaths{
			ConfigDir:    configDir,
			ConfigFile:   configFile,
			RulesDBPath:  filepath.Join(configDir, "rules.db"),
			AllRulesPath: filepath.Join(configDir, "all.rules"),
			AlertDBPath:  alertDBPath,
			OutputPath:   outputPath,
			SiteDir:      siteDir,
		},
	}

	if cfg.PCAPPath == "" && cfg.Interface == "" {
		cfg.PCAPPath = detectPCAPPath("data")
	}
	if cfg.PCAPPath == "" && cfg.Interface == "" {
		legacyPath := filepath.Join("data", "CIC-IDS-2017", "Friday-WorkingHours.pcap")
		if _, err := os.Stat(legacyPath); err == nil {
			cfg.PCAPPath = legacyPath
		}
	}
	if cfg.PCAPPath == "" && cfg.Interface == "" {
		return cfg, fmt.Errorf("no pcap found under data and SNORT_INTERFACE is empty")
	}
	return cfg, nil
}

func detectSiteDir() string {
	candidates := []string{"../web", "site"}
	for _, candidate := range candidates {
		if stat, err := os.Stat(candidate); err == nil && stat.IsDir() {
			return candidate
		}
	}
	return "../web"
}

func detectPCAPPath(root string) string {
	var candidates []string
	walkRoot := root
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		walkRoot = resolved
	}
	filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		lower := strings.ToLower(d.Name())
		if strings.HasSuffix(lower, ".pcap") || strings.HasSuffix(lower, ".pcapng") {
			candidates = append(candidates, path)
		}
		return nil
	})
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func PrepareAlertDBPath(cfg *RuntimeConfig, logger *log.Logger) error {
	if canCreateFile(cfg.Paths.AlertDBPath) {
		return nil
	}

	fallback := "alert.db"
	if cfg.Paths.AlertDBPath != fallback && canCreateFile(fallback) {
		logger.Printf("alert db path %s is not writable, falling back to %s", cfg.Paths.AlertDBPath, fallback)
		cfg.Paths.AlertDBPath = fallback
		return nil
	}
	return fmt.Errorf("alert db path is not writable: %s", cfg.Paths.AlertDBPath)
}

func canCreateFile(path string) bool {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return false
	}
	file.Close()
	return true
}
