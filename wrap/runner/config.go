package runner

import (
	"fmt"
	"path/filepath"
	"strings"

	wraptypes "snort-optimizer/wrap/types"
)

func normalizeConfig(input wraptypes.Config) (wraptypes.Config, error) {
	if strings.TrimSpace(input.SnortWorkingDir) == "" {
		input.SnortWorkingDir = "."
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
	if strings.TrimSpace(input.SnortDBPath) != "" {
		absDB, err := filepath.Abs(input.SnortDBPath)
		if err != nil {
			return input, fmt.Errorf("resolve SnortDBPath: %w", err)
		}
		input.SnortDBPath = absDB
	}
	if strings.TrimSpace(input.RawRulePath) != "" {
		absRules, err := filepath.Abs(input.RawRulePath)
		if err != nil {
			return input, fmt.Errorf("resolve RawRulePath: %w", err)
		}
		input.RawRulePath = absRules
	}
	if input.Mode == "" {
		switch {
		case strings.TrimSpace(input.PcapFile) != "":
			input.Mode = wraptypes.ModePCAP
		case strings.TrimSpace(input.Interface) != "":
			input.Mode = wraptypes.ModeInterface
		}
	}
	if err := validateConfig(input); err != nil {
		return input, err
	}
	return input, nil
}

func validateConfig(cfg wraptypes.Config) error {
	if strings.TrimSpace(cfg.PcapFile) != "" && strings.TrimSpace(cfg.Interface) != "" {
		return fmt.Errorf("only one of PcapFile or Interface may be set")
	}
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
