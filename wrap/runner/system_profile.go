package runner

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"snort-optimizer/types"
)

type systemProfileResult struct {
	profile types.SystemProfile
	err     error
}

type procSample struct {
	cpuSeconds float64
	rssMB      float64
}

func monitorSystemProfile(ctx context.Context, pid int, runID int64, done chan<- systemProfileResult) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var prev procSample
	var prevTime time.Time
	var cpuSum, memSum float64
	var samples int64
	var lastErr error

	for {
		select {
		case <-ctx.Done():
			done <- systemProfileResult{
				profile: types.SystemProfile{
					RunID:    runID,
					AvgCPU:   average(cpuSum, samples),
					AvgMemMB: average(memSum, samples),
					Samples:  samples,
				},
				err: lastErr,
			}
			return
		case now := <-ticker.C:
			current, err := readProcSample(pid)
			if err != nil {
				lastErr = err
				continue
			}
			if !prevTime.IsZero() {
				elapsed := now.Sub(prevTime).Seconds()
				if elapsed > 0 && current.cpuSeconds >= prev.cpuSeconds {
					cpuPct := (current.cpuSeconds - prev.cpuSeconds) / elapsed * 100
					if cpuPct > 0 || current.rssMB > 0 {
						cpuSum += cpuPct
						memSum += current.rssMB
						samples++
					}
				}
			}
			prev = current
			prevTime = now
		}
	}
}

func readProcSample(pid int) (procSample, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procSample{}, err
	}
	fields := strings.Fields(string(stat))
	if len(fields) < 15 {
		return procSample{}, fmt.Errorf("invalid proc stat for pid %d", pid)
	}
	utime, err := strconv.ParseFloat(fields[13], 64)
	if err != nil {
		return procSample{}, err
	}
	stime, err := strconv.ParseFloat(fields[14], 64)
	if err != nil {
		return procSample{}, err
	}
	return procSample{
		cpuSeconds: (utime + stime) / float64(clockTicks()),
		rssMB:      readRSSMB(pid),
	}, nil
}

func readRSSMB(pid int) float64 {
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

func clockTicks() int {
	// Linux commonly uses 100 ticks/sec. CPU is reported as percent of one CPU,
	// so multi-threaded Snort can exceed 100%.
	return 100
}

func average(sum float64, count int64) float64 {
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}
