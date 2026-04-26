package parse

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"analyser/internal/model"
)

type snortAlertJSON struct {
	Timestamp string `json:"timestamp"`
	Proto     string `json:"proto"`
	SrcAP     string `json:"src_ap"`
	DstAP     string `json:"dst_ap"`
	Rule      string `json:"rule"`
}

var ruleProfileLineRE = regexp.MustCompile(`^\s*\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)`)

func ParseSnortOutput(path string, year int) ([]*model.AlertRecord, []*model.RuleProfiler, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open snort output: %w", err)
	}
	defer f.Close()

	var alerts []*model.AlertRecord
	var profilers []*model.RuleProfiler
	var warnings []string
	mergeIndex := map[string][]*model.AlertRecord{}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "{") && strings.Contains(line, `"rule"`) {
			record, err := parseSnortAlertLine(line, year)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("line %d: alert parse failed: %v", lineNo, err))
				continue
			}
			key := model.AlertMergeKey(record)
			merged := false
			for _, existing := range mergeIndex[key] {
				// Snort emits packet alerts. We merge them into a flow-level alert
				// when rule identity, 5-tuple and timestamp stay within 2 minutes.
				if AbsDuration(record.FlowTimestamp.Sub(existing.FlowTimestamp)) < AlertMergeWindow {
					existing.AlertCount++
					if record.FirstAlertTimestamp.Before(existing.FirstAlertTimestamp) {
						existing.FirstAlertTimestamp = record.FirstAlertTimestamp
					}
					if record.FlowTimestamp.Before(existing.FlowTimestamp) {
						existing.FlowTimestamp = record.FlowTimestamp
					}
					merged = true
					break
				}
			}
			if !merged {
				record.ID = int64(len(alerts) + 1)
				alerts = append(alerts, record)
				mergeIndex[key] = append(mergeIndex[key], record)
			}
			continue
		}

		if profiler := parseRuleProfilerLine(line); profiler != nil {
			profiler.ID = int64(len(profilers) + 1)
			profilers = append(profilers, profiler)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, warnings, fmt.Errorf("scan snort output: %w", err)
	}
	return alerts, profilers, warnings, nil
}

func parseSnortAlertLine(line string, year int) (*model.AlertRecord, error) {
	var raw snortAlertJSON
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, err
	}
	ts, err := ParseSnortTimestamp(raw.Timestamp, year)
	if err != nil {
		return nil, err
	}
	srcIP, srcPort, err := parseAddrPort(raw.SrcAP)
	if err != nil {
		return nil, fmt.Errorf("parse src_ap: %w", err)
	}
	dstIP, dstPort, err := parseAddrPort(raw.DstAP)
	if err != nil {
		return nil, fmt.Errorf("parse dst_ap: %w", err)
	}
	gid, sid, rev, err := parseRuleIdentity(raw.Rule)
	if err != nil {
		return nil, err
	}
	return &model.AlertRecord{
		RuleGID:             Int64Ptr(gid),
		RuleSID:             Int64Ptr(sid),
		RuleREV:             Int64Ptr(rev),
		SrcIP:               srcIP,
		SrcPort:             srcPort,
		DstIP:               dstIP,
		DstPort:             dstPort,
		Protocol:            NormalizeProtocol(raw.Proto),
		FlowTimestamp:       ts,
		FirstAlertTimestamp: ts,
		AlertCount:          1,
		Source:              "snort",
	}, nil
}

func parseRuleProfilerLine(line string) *model.RuleProfiler {
	matches := ruleProfileLineRE.FindStringSubmatch(line)
	if matches == nil || len(matches) < 11 {
		return nil
	}

	vals := make([]int64, 0, 6)
	for _, raw := range matches[1:7] {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil
		}
		vals = append(vals, v)
	}

	floats := make([]float64, 0, 4)
	for _, raw := range matches[7:11] {
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return nil
		}
		floats = append(floats, v)
	}

	noMatches := vals[3] - vals[4]
	if noMatches < 0 {
		noMatches = 0
	}

	return &model.RuleProfiler{
		RuleGID:        Int64Ptr(vals[0]),
		RuleSID:        Int64Ptr(vals[1]),
		RuleREV:        Int64Ptr(vals[2]),
		Checks:         vals[3],
		Matches:        vals[4],
		Alerts:         vals[5],
		NoMatches:      noMatches,
		TotalTimeUS:    floats[0],
		AvgCheckTime:   floats[1],
		AvgMatchTime:   floats[2],
		AvgNoMatchTime: floats[3],
		RawLine:        line,
	}
}

func parseAddrPort(raw string) (string, int, error) {
	pos := strings.LastIndex(strings.TrimSpace(raw), ":")
	if pos <= 0 || pos == len(raw)-1 {
		return "", 0, fmt.Errorf("invalid addr:port %q", raw)
	}
	port, err := strconv.Atoi(raw[pos+1:])
	if err != nil {
		return "", 0, err
	}
	return raw[:pos], port, nil
}

func parseRuleIdentity(raw string) (int64, int64, int64, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid rule identity %q", raw)
	}
	gid, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	sid, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	rev, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	return gid, sid, rev, nil
}
