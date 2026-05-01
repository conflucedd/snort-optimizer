package analyser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"snort-optimizer/analyser/types"
)

func normalizeConfig(cfg types.Config) (types.Config, error) {
	var err error
	if strings.TrimSpace(cfg.AnalyserWorkingDir) == "" {
		cfg.AnalyserWorkingDir = "analyser-work"
	}
	cfg.AnalyserWorkingDir, err = filepath.Abs(cfg.AnalyserWorkingDir)
	if err != nil {
		return cfg, fmt.Errorf("resolve AnalyserWorkingDir: %w", err)
	}

	if cfg.Pcap1 != "" {
		cfg.Pcap1, err = normalizePCAPInput("Pcap1", cfg.Pcap1)
		if err != nil {
			return cfg, err
		}
	}
	if cfg.Pcap2 != "" {
		cfg.Pcap2, err = normalizePCAPInput("Pcap2", cfg.Pcap2)
		if err != nil {
			return cfg, err
		}
	}

	for name, ptr := range map[string]*string{
		"Pcap1":          &cfg.Pcap1,
		"DB1":            &cfg.DB1,
		"Pcap2":          &cfg.Pcap2,
		"SnortConfig":    &cfg.SnortConfig,
		"RawSnortSQLite": &cfg.RawSnortSQLite,
		"RawRulePath":    &cfg.RawRulePath,
		"EmptyPcap":      &cfg.EmptyPcap,
	} {
		if strings.TrimSpace(*ptr) == "" {
			continue
		}
		*ptr, err = filepath.Abs(*ptr)
		if err != nil {
			return cfg, fmt.Errorf("resolve %s: %w", name, err)
		}
	}

	if cfg.EmptyPcap == "" {
		cfg.EmptyPcap = filepath.Join(cfg.AnalyserWorkingDir, "base", "empty.pcap")
	}
	if cfg.MaxRound <= 0 {
		cfg.MaxRound = types.DefaultMaxRound
	}
	if cfg.InitialFactor <= 0 {
		cfg.InitialFactor = types.DefaultInitialFactor
	}
	if cfg.InitialFactor > 1 {
		cfg.InitialFactor = 1
	}
	if cfg.MaxMissRateIncrease == 0 {
		cfg.MaxMissRateIncrease = types.DefaultMissIncrease
	}
	if cfg.MaxFPRateIncrease == 0 {
		cfg.MaxFPRateIncrease = types.DefaultFPIncrease
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = types.DefaultPollInterval
	}

	required := map[string]string{
		"Pcap1":       cfg.Pcap1,
		"DB1":         cfg.DB1,
		"Pcap2":       cfg.Pcap2,
		"SnortConfig": cfg.SnortConfig,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return cfg, fmt.Errorf("%s is required", name)
		}
	}
	if cfg.RawSnortSQLite == "" && cfg.RawRulePath == "" {
		return cfg, fmt.Errorf("RawSnortSQLite or RawRulePath is required")
	}
	for name, value := range required {
		if err := requireFile(name, value); err != nil {
			return cfg, err
		}
	}
	for name, value := range map[string]string{"Pcap1": cfg.Pcap1, "Pcap2": cfg.Pcap2} {
		if err := requirePCAP(name, value); err != nil {
			return cfg, err
		}
	}
	if cfg.RawSnortSQLite != "" {
		if err := requireFile("RawSnortSQLite", cfg.RawSnortSQLite); err != nil {
			return cfg, err
		}
	}
	if cfg.RawRulePath != "" {
		if _, err := os.Stat(cfg.RawRulePath); err != nil {
			return cfg, fmt.Errorf("stat RawRulePath: %w", err)
		}
	}
	return cfg, nil
}

func normalizePCAPInput(name, value string) (string, error) {
	if !strings.EqualFold(filepath.Ext(value), ".db") {
		return value, nil
	}
	candidate := strings.TrimSuffix(value, filepath.Ext(value)) + ".pcap"
	if _, err := os.Stat(candidate); err == nil {
		return candidate, nil
	} else if os.IsNotExist(err) {
		return "", fmt.Errorf("%s points to sqlite db %s; expected pcap, and sibling %s does not exist", name, value, candidate)
	} else {
		return "", fmt.Errorf("stat inferred %s pcap %s: %w", name, candidate, err)
	}
}

func requireFile(name, path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if stat.IsDir() {
		return fmt.Errorf("%s must be a file: %s", name, path)
	}
	return nil
}

func requirePCAP(name, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer file.Close()
	header := make([]byte, 4)
	if _, err := file.Read(header); err != nil {
		return fmt.Errorf("read %s header: %w", name, err)
	}
	if isPCAPMagic(header) {
		return nil
	}
	return fmt.Errorf("%s is not a pcap/pcapng file: %s", name, path)
}

func isPCAPMagic(header []byte) bool {
	if len(header) < 4 {
		return false
	}
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1", "\xa1\xb2\xc3\xd4", "\x4d\x3c\xb2\xa1", "\xa1\xb2\x3c\x4d", "\x0a\x0d\x0d\x0a":
		return true
	default:
		return false
	}
}
