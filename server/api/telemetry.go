package api

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type procTelemetry struct {
	CPUPercent float64
	MemMB      float64
}

type processSampler struct {
	mu       sync.Mutex
	lastPID  int
	lastCPU  float64
	lastTime time.Time
}

func (s *processSampler) Sample(pid int) procTelemetry {
	now := time.Now()
	cpuSeconds, memMB, err := readProcCPUAndMem(pid)
	if err != nil {
		return procTelemetry{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := procTelemetry{MemMB: memMB}
	if s.lastPID == pid && !s.lastTime.IsZero() {
		elapsed := now.Sub(s.lastTime).Seconds()
		if elapsed > 0 && cpuSeconds >= s.lastCPU {
			out.CPUPercent = (cpuSeconds - s.lastCPU) / elapsed * 100
		}
	}
	s.lastPID = pid
	s.lastCPU = cpuSeconds
	s.lastTime = now
	return out
}

func readProcCPUAndMem(pid int) (float64, float64, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 15 {
		return 0, 0, fmt.Errorf("invalid proc stat")
	}
	utime, _ := strconv.ParseFloat(fields[13], 64)
	stime, _ := strconv.ParseFloat(fields[14], 64)
	return (utime + stime) / 100, readProcRSSMB(pid), nil
}

func readProcRSSMB(pid int) float64 {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, _ := strconv.ParseFloat(fields[1], 64)
			return kb / 1024
		}
	}
	return 0
}

type connectionCounts struct {
	Total          int
	EstablishedTCP int
	UDP            int
}

func readConnectionCounts() connectionCounts {
	var c connectionCounts
	tcp, established := countTCP("/proc/net/tcp")
	tcp6, established6 := countTCP("/proc/net/tcp6")
	udp := countUDP("/proc/net/udp")
	udp6 := countUDP("/proc/net/udp6")
	c.EstablishedTCP = established + established6
	c.UDP = udp + udp6
	c.Total = tcp + tcp6 + udp + udp6
	return c
}

func countTCP(path string) (total, established int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		total++
		if fields[3] == "01" {
			established++
		}
	}
	return total, established
}

func countUDP(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	count := 0
	for _, line := range lines[1:] {
		if len(strings.Fields(line)) > 0 {
			count++
		}
	}
	return count
}
