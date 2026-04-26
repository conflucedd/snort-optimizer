package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

//go:embed target/CICFlowMeterV3-0.0.4-SNAPSHOT.jar
var cicFlowMeterJar []byte

//go:embed jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap.so
var libJNetPcap []byte

//go:embed jnetpcap/linux/jnetpcap-1.4.r1425/libjnetpcap-pcap100.so
var libJNetPcapPcap100 []byte

const usage = `Usage:
  cicflowmeter <input.pcap> <output.csv>

Environment:
  CICFLOWMETER_JAVA   Java executable to use. Defaults to JAVA_HOME/bin/java or java in PATH.
  JAVA_OPTS           Extra JVM options, split on whitespace.
`

func main() {
	if len(os.Args) != 3 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprint(os.Stderr, usage)
		if len(os.Args) == 3 {
			os.Exit(2)
		}
		return
	}

	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintf(os.Stderr, "cicflowmeter: %v\n", err)
		os.Exit(1)
	}
}

func run(inputPcap, outputCSV string) error {
	javaPath, err := findJava()
	if err != nil {
		return err
	}

	runtimeDir, err := os.MkdirTemp("", "cicflowmeter-runtime-*")
	if err != nil {
		return fmt.Errorf("create runtime temp dir: %w", err)
	}
	defer os.RemoveAll(runtimeDir)

	jarPath := filepath.Join(runtimeDir, "CICFlowMeter.jar")
	libDir := filepath.Join(runtimeDir, "native")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		return fmt.Errorf("create native library dir: %w", err)
	}

	files := []struct {
		path string
		data []byte
		mode fs.FileMode
	}{
		{jarPath, cicFlowMeterJar, 0644},
		{filepath.Join(libDir, "libjnetpcap.so"), libJNetPcap, 0755},
		{filepath.Join(libDir, "libjnetpcap-pcap100.so"), libJNetPcapPcap100, 0755},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, file.data, file.mode); err != nil {
			return fmt.Errorf("write embedded runtime file %s: %w", file.path, err)
		}
	}

	args := make([]string, 0, 8)
	if major, err := javaMajorVersion(javaPath); err == nil && major >= 22 {
		args = append(args, "--enable-native-access=ALL-UNNAMED")
	}
	if extra := strings.Fields(os.Getenv("JAVA_OPTS")); len(extra) > 0 {
		args = append(args, extra...)
	}
	args = append(args,
		"-Djava.library.path="+libDir,
		"-jar", jarPath,
		inputPcap,
		outputCSV,
	)

	cmd := exec.Command(javaPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("java exited with status %d", exitErr.ExitCode())
		}
		return fmt.Errorf("run java: %w", err)
	}
	return nil
}

func findJava() (string, error) {
	if javaPath := os.Getenv("CICFLOWMETER_JAVA"); javaPath != "" {
		return javaPath, nil
	}

	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		javaPath := filepath.Join(javaHome, "bin", "java")
		if _, err := os.Stat(javaPath); err == nil {
			return javaPath, nil
		}
	}

	javaPath, err := exec.LookPath("java")
	if err != nil {
		return "", errors.New("java executable not found; set CICFLOWMETER_JAVA or JAVA_HOME")
	}
	return javaPath, nil
}

func javaMajorVersion(javaPath string) (int, error) {
	cmd := exec.Command(javaPath, "-version")
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return 0, err
	}

	re := regexp.MustCompile(`version "([^"]+)"`)
	matches := re.FindStringSubmatch(output.String())
	if len(matches) != 2 {
		return 0, fmt.Errorf("can not parse java version: %s", strings.TrimSpace(output.String()))
	}

	parts := strings.Split(matches[1], ".")
	if len(parts) >= 2 && parts[0] == "1" {
		return strconv.Atoi(parts[1])
	}
	return strconv.Atoi(parts[0])
}
