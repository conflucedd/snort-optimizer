package sql

import (
	"fmt"
	"os"
	"path/filepath"
)

func ResetAnalyserWorkingDir(path string) error {
	clean := filepath.Clean(path)
	if err := validateRemoveAllTarget(clean); err != nil {
		return err
	}
	if err := os.RemoveAll(clean); err != nil {
		return fmt.Errorf("remove analyser working dir %s: %w", clean, err)
	}
	return nil
}

func validateRemoveAllTarget(path string) error {
	if path == "" || path == "." || path == string(os.PathSeparator) {
		return fmt.Errorf("refuse to remove unsafe analyser working dir %q", path)
	}
	cwd, err := os.Getwd()
	if err == nil && filepath.Clean(cwd) == path {
		return fmt.Errorf("refuse to remove current working directory %s", path)
	}
	home, err := os.UserHomeDir()
	if err == nil && filepath.Clean(home) == path {
		return fmt.Errorf("refuse to remove home directory %s", path)
	}
	tmp := filepath.Clean(os.TempDir())
	if tmp == path {
		return fmt.Errorf("refuse to remove temp root %s", path)
	}
	return nil
}
