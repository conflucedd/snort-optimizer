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

func Parse(reader io.Reader, runID int64, sourceFile string) ([]types.ProfilerMetric, []types.RuleProfilerMetric, []types.ModuleProfileMetric, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var metrics []types.ProfilerMetric
	var rules []types.RuleProfilerMetric
	var modules []types.ModuleProfileMetric
	var section, module, pendingTitle string
	source := filepath.Base(sourceFile)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "module profile "):
			section = "module profile"
			module = ""
			pendingTitle = ""
			continue
		case strings.HasPrefix(line, "rule profile "):
			section = "rule profile"
			module = ""
			pendingTitle = ""
			continue
		}
		if section == "module profile" {
			if m := parseModuleProfileLine(raw, runID, source); m != nil {
				modules = append(modules, *m)
			}
			continue
		}
		if section == "rule profile" {
			if r := parseRuleProfileLine(raw, runID, source); r != nil {
				rules = append(rules, *r)
			}
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
	return metrics, rules, modules, scanner.Err()
}

func parseMetricLine(raw string, runID int64, sourceFile, section, module string) *types.ProfilerMetric {
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

func parseModuleProfileLine(raw string, runID int64, sourceFile string) *types.ModuleProfileMetric {
	fields := strings.Fields(raw)
	if len(fields) != 8 {
		return nil
	}
	rank, ok := parseInt(fields[0])
	if !ok {
		return nil
	}
	checks, ok := parseInt(fields[3])
	if !ok {
		return nil
	}
	timeUS, ok := parseInt(fields[4])
	if !ok {
		return nil
	}
	avgCheck, ok := parseFloat(fields[5])
	if !ok {
		return nil
	}
	callerPct, ok := parseFloat(fields[6])
	if !ok {
		return nil
	}
	totalPct, ok := parseFloat(fields[7])
	if !ok {
		return nil
	}
	return &types.ModuleProfileMetric{
		RunID:      runID,
		Rank:       rank,
		Module:     fields[1],
		Layer:      fields[2],
		Checks:     checks,
		TimeUS:     timeUS,
		AvgCheck:   avgCheck,
		CallerPct:  callerPct,
		TotalPct:   totalPct,
		RawLine:    strings.TrimSpace(raw),
		SourceFile: sourceFile,
	}
}

func parseRuleProfileLine(raw string, runID int64, sourceFile string) *types.RuleProfilerMetric {
	fields := strings.Fields(raw)
	if len(fields) != 14 {
		return nil
	}
	values := make([]int64, 0, 12)
	for i := 0; i <= 11; i++ {
		value, ok := parseInt(fields[i])
		if !ok {
			return nil
		}
		values = append(values, value)
	}
	ruleTimePct, ok := parseFloat(fields[13])
	if !ok {
		return nil
	}
	avgCheck, _ := parseFloat(fields[8])
	avgMatch, _ := parseFloat(fields[9])
	avgNonMatch, _ := parseFloat(fields[10])
	return &types.RuleProfilerMetric{
		RunID:       runID,
		GID:         values[1],
		SID:         values[2],
		Rev:         values[3],
		Checks:      values[4],
		Matches:     values[5],
		Alerts:      values[6],
		TimeUS:      values[7],
		AvgCheck:    avgCheck,
		AvgMatch:    avgMatch,
		AvgNonMatch: avgNonMatch,
		Timeouts:    values[11],
		Suspends:    mustInt(fields[12]),
		RuleTimePct: ruleTimePct,
		RawLine:     strings.TrimSpace(raw),
		SourceFile:  sourceFile,
	}
}

func parseInt(input string) (int64, bool) {
	value, err := strconv.ParseInt(input, 10, 64)
	return value, err == nil
}

func mustInt(input string) int64 {
	value, _ := strconv.ParseInt(input, 10, 64)
	return value
}

func parseFloat(input string) (float64, bool) {
	value, err := strconv.ParseFloat(input, 64)
	return value, err == nil
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
