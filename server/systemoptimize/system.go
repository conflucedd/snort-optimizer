package systemoptimize

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type InterfaceInfo struct {
	Name     string          `json:"name"`
	Up       bool            `json:"up"`
	MAC      string          `json:"mac,omitempty"`
	MTU      int             `json:"mtu,omitempty"`
	Speed    string          `json:"speed,omitempty"`
	Offloads []OffloadStatus `json:"offloads,omitempty"`
}

type OffloadStatus struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Fixed     bool   `json:"fixed"`
	Raw       string `json:"raw"`
	Supported bool   `json:"supported"`
}

type CommandResult struct {
	OK        bool   `json:"ok"`
	Command   string `json:"command"`
	Output    string `json:"output,omitempty"`
	Error     string `json:"error,omitempty"`
	NeedsRoot bool   `json:"needs_root,omitempty"`
}

type CPUStatus struct {
	CPUCount      int    `json:"cpu_count"`
	SnortPID      int    `json:"snort_pid,omitempty"`
	SnortAffinity string `json:"snort_affinity,omitempty"`
}

func ListInterfaces() ([]InterfaceInfo, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		base := filepath.Join("/sys/class/net", name)
		info := InterfaceInfo{Name: name}
		info.Up = strings.TrimSpace(readText(filepath.Join(base, "operstate"))) == "up"
		info.MAC = strings.TrimSpace(readText(filepath.Join(base, "address")))
		info.MTU, _ = strconv.Atoi(strings.TrimSpace(readText(filepath.Join(base, "mtu"))))
		speed := strings.TrimSpace(readText(filepath.Join(base, "speed")))
		if speed != "" {
			info.Speed = speed + " Mb/s"
		}
		info.Offloads = readOffloads(name)
		out = append(out, info)
	}
	return out, nil
}

func SetOffload(iface, feature string, enabled bool) CommandResult {
	state := "off"
	if enabled {
		state = "on"
	}
	return runCommand("ethtool", "-K", iface, feature, state)
}

func Status(pid int) CPUStatus {
	status := CPUStatus{CPUCount: runtime.NumCPU(), SnortPID: pid}
	if pid > 0 {
		status.SnortAffinity = readAffinity(pid)
	}
	return status
}

func SetAffinity(pid int, cpus string) CommandResult {
	if pid <= 0 {
		return CommandResult{OK: false, Error: "snort is not running"}
	}
	return runCommand("taskset", "-pc", cpus, strconv.Itoa(pid))
}

func readOffloads(iface string) []OffloadStatus {
	cmd := exec.Command("ethtool", "-k", iface)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	statuses := []OffloadStatus{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasSuffix(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		status := OffloadStatus{Name: name, Raw: value, Supported: true}
		if strings.HasPrefix(value, "on") {
			status.Enabled = true
		}
		if strings.Contains(value, "[fixed]") {
			status.Fixed = true
		}
		statuses = append(statuses, status)
	}
	return statuses
}

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func readAffinity(pid int) string {
	status := readText(fmt.Sprintf("/proc/%d/status", pid))
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Cpus_allowed_list:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Cpus_allowed_list:"))
		}
	}
	return ""
}

func runCommand(name string, args ...string) CommandResult {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	result := CommandResult{
		Command: strings.Join(append([]string{name}, args...), " "),
		Output:  strings.TrimSpace(string(out)),
		OK:      err == nil,
	}
	if err != nil {
		result.Error = err.Error()
		lower := strings.ToLower(result.Output + " " + result.Error)
		result.NeedsRoot = strings.Contains(lower, "operation not permitted") ||
			strings.Contains(lower, "permission denied") ||
			strings.Contains(lower, "not superuser")
	}
	return result
}
