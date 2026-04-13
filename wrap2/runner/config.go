package runner

import (
	"fmt"
	"path/filepath"
	"strings"

	wraptypes "snort-optimizer/wrap2/types"
)

func normalizeConfig(input wraptypes.Config) (wraptypes.Config, error) {
	if strings.TrimSpace(input.SnortWorkingDir) == "" {
		return input, fmt.Errorf("SnortWorkingDir is required")
	}
	swd, err := filepath.Abs(input.SnortWorkingDir)
	if err != nil {
		return input, fmt.Errorf("resolve SnortWorkingDir: %w", err)
	}
	input.SnortWorkingDir = swd

	if strings.TrimSpace(input.SnortConfigPath) != "" {
		absConfig, err := filepath.Abs(input.SnortConfigPath)
		if err != nil {
			return input, fmt.Errorf("resolve SnortConfigPath: %w", err)
		}
		input.SnortConfigPath = absConfig
	}
	if err := validateConfig(input); err != nil {
		return input, err
	}
	return input, nil
}

func validateConfig(cfg wraptypes.Config) error {
	if cfg.Mode != wraptypes.ModeInterface && cfg.Mode != wraptypes.ModePCAP {
		return fmt.Errorf("Mode must be %q or %q", wraptypes.ModeInterface, wraptypes.ModePCAP)
	}
	if cfg.Mode == wraptypes.ModeInterface && strings.TrimSpace(cfg.Interface) == "" {
		return fmt.Errorf("Interface is required when Mode=interface")
	}
	if cfg.Mode == wraptypes.ModePCAP && strings.TrimSpace(cfg.PcapFile) == "" {
		return fmt.Errorf("PcapFile is required when Mode=pcap")
	}
	if strings.TrimSpace(cfg.SnortConfigPath) == "" {
		return fmt.Errorf("SnortConfigPath is required")
	}
	return nil
}
