package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readCPUSeconds(pid int, clockTicks float64) (float64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("read proc stat: %w", err)
	}

	text := string(data)
	end := strings.LastIndex(text, ")")
	if end < 0 || end+2 >= len(text) {
		return 0, fmt.Errorf("unexpected /proc stat format")
	}

	fields := strings.Fields(text[end+2:])
	if len(fields) < 22 {
		return 0, fmt.Errorf("not enough proc stat fields")
	}

	utime, err := strconv.ParseFloat(fields[11], 64)
	if err != nil {
		return 0, fmt.Errorf("parse utime: %w", err)
	}
	stime, err := strconv.ParseFloat(fields[12], 64)
	if err != nil {
		return 0, fmt.Errorf("parse stime: %w", err)
	}
	return (utime + stime) / clockTicks, nil
}

func readMemoryRSS(pid int) (int64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, fmt.Errorf("read proc status: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse VmRSS: %w", err)
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("VmRSS not found")
}
