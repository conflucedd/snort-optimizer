package profiler

import (
	"bufio"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"snort-optimizer/types"
)

var metricLine = regexp.MustCompile(`^\s*([^:]+):\s*([-+]?\d+(?:\.\d+)?)\s*(?:\(\s*([-+]?\d+(?:\.\d+)?)%\s*\))?\s*([[:alpha:]]+)?\s*$`)

func Parse(reader io.Reader, runID, sourceFile string) ([]types.ProfilerMetric, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var metrics []types.ProfilerMetric
	var section, module, pendingTitle string
	source := filepath.Base(sourceFile)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if isSeparator(line) {
			if pendingTitle != "" {
				section = pendingTitle
				module = ""
				pendingTitle = ""
			}
			continue
		}
		if metric := parseMetricLine(raw, runID, source, section, module); metric != nil {
			metrics = append(metrics, *metric)
			pendingTitle = ""
			continue
		}
		if shouldIgnoreLine(line) {
			pendingTitle = ""
			continue
		}
		if section == "" || strings.HasPrefix(line, "Packet Statistics") || strings.HasPrefix(line, "Module Statistics") {
			pendingTitle = line
			continue
		}
		module = line
	}
	return metrics, scanner.Err()
}

func parseMetricLine(raw, runID, sourceFile, section, module string) *types.ProfilerMetric {
	match := metricLine.FindStringSubmatch(raw)
	if len(match) != 5 {
		return nil
	}
	value, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		return nil
	}
	var percent float64
	if match[3] != "" {
		percent, _ = strconv.ParseFloat(match[3], 64)
	}
	return &types.ProfilerMetric{
		RunID:      runID,
		Section:    strings.TrimSpace(section),
		Module:     strings.TrimSpace(module),
		Metric:     strings.TrimSpace(match[1]),
		Value:      value,
		Percent:    percent,
		Unit:       strings.TrimSpace(match[4]),
		RawLine:    strings.TrimSpace(raw),
		SourceFile: sourceFile,
	}
}

func isSeparator(line string) bool {
	return strings.Trim(line, "-") == ""
}

func shouldIgnoreLine(line string) bool {
	return strings.HasPrefix(line, "Loading ") ||
		strings.HasPrefix(line, "Finished ") ||
		strings.HasPrefix(line, "Commencing ") ||
		strings.HasPrefix(line, "++ ") ||
		strings.HasPrefix(line, "-- ") ||
		strings.HasPrefix(line, `o")~`) ||
		strings.HasPrefix(line, "Snort++")
}
