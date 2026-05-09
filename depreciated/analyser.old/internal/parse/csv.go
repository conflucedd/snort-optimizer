package parse

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"analyser/internal/model"
)

func DetectCSVYear(csvPath string) (int, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return 0, fmt.Errorf("open csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return 0, fmt.Errorf("read csv header: %w", err)
	}
	index := buildHeaderIndex(header)
	tsIdx, ok := index["Timestamp"]
	if !ok {
		return 0, errors.New("csv missing Timestamp column")
	}

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("read csv row: %w", err)
		}
		if tsIdx >= len(row) {
			continue
		}
		ts, err := ParseCSVTimestamp(strings.TrimSpace(row[tsIdx]))
		if err == nil {
			return ts.Year(), nil
		}
	}
	return 0, errors.New("unable to infer year from csv")
}

func InferTimeOffset(csvPath string, alerts []*model.AlertRecord) (time.Duration, int, error) {
	tupleMap := map[string][]*model.AlertRecord{}
	for _, alert := range alerts {
		key := model.TupleKey(alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort, alert.Protocol)
		tupleMap[key] = append(tupleMap[key], alert)
	}
	if len(tupleMap) == 0 {
		return 0, 0, nil
	}

	f, err := os.Open(csvPath)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return 0, 0, err
	}
	index := buildHeaderIndex(header)

	offsetCounts := map[int]int{}
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, 0, err
		}
		flow, ok := parseCSVFlowRow(row, index)
		if !ok {
			continue
		}
		for _, alert := range tupleMap[model.TupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)] {
			offsetMin := int(math.Round(alert.FlowTimestamp.Sub(flow.Start).Minutes()))
			offsetCounts[offsetMin]++
		}
	}

	bestOffset := 0
	bestCount := 0
	for offset, count := range offsetCounts {
		if count > bestCount {
			bestCount = count
			bestOffset = offset
		}
	}
	return time.Duration(-bestOffset) * time.Minute, bestCount, nil
}

func ApplyCSVLabels(csvPath string, alerts []*model.AlertRecord) ([]*model.AlertRecord, int64, map[string]int64, []string, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("open csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return nil, 0, nil, nil, fmt.Errorf("read csv header: %w", err)
	}
	index := buildHeaderIndex(header)

	alertMap := map[string][]*model.AlertRecord{}
	for _, alert := range alerts {
		key := model.TupleKey(alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort, alert.Protocol)
		alertMap[key] = append(alertMap[key], alert)
	}

	var warnings []string
	maliciousSeen := map[string]struct{}{}
	missedByLabel := map[string]int64{}
	var totalMalicious int64
	lineNo := 1

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		lineNo++
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("csv line %d: read failed: %v", lineNo, err))
			continue
		}
		flow, ok := parseCSVFlowRow(row, index)
		if !ok {
			continue
		}

		matches := matchAlertsForCSVFlow(flow, alertMap)
		if flow.IsBenign {
			for _, matched := range matches {
				matched.FalsePositive = true
			}
			continue
		}
		if !flow.IsMalicious {
			continue
		}
		if _, exists := maliciousSeen[flow.Key]; exists {
			continue
		}
		maliciousSeen[flow.Key] = struct{}{}
		totalMalicious++

		if len(matches) == 0 {
			missedByLabel[flow.Label]++
			alert := &model.AlertRecord{
				ID:                  int64(len(alerts) + 1),
				SrcIP:               flow.SrcIP,
				SrcPort:             flow.SrcPort,
				DstIP:               flow.DstIP,
				DstPort:             flow.DstPort,
				Protocol:            flow.Protocol,
				FlowTimestamp:       flow.Start,
				FirstAlertTimestamp: flow.Start,
				MissedDetection:     true,
				AlertCount:          0,
				Source:              "csv_missed",
			}
			alerts = append(alerts, alert)
			key := model.TupleKey(alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort, alert.Protocol)
			alertMap[key] = append(alertMap[key], alert)
		}
	}

	return alerts, totalMalicious, missedByLabel, warnings, nil
}

func parseCSVFlowRow(row []string, index map[string]int) (model.CSVFlow, bool) {
	var zero model.CSVFlow
	get := func(name string) string {
		idx, ok := index[name]
		if !ok || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	label := NormalizeLabel(get("Label"))
	if label == "" || strings.EqualFold(label, "Label") {
		return zero, false
	}
	srcPort, err := strconv.Atoi(get("Source Port"))
	if err != nil {
		return zero, false
	}
	dstPort, err := strconv.Atoi(get("Destination Port"))
	if err != nil {
		return zero, false
	}
	start, err := ParseCSVTimestamp(get("Timestamp"))
	if err != nil {
		return zero, false
	}

	flow := model.CSVFlow{
		SrcIP:        get("Source IP"),
		SrcPort:      srcPort,
		DstIP:        get("Destination IP"),
		DstPort:      dstPort,
		Protocol:     NormalizeProtocol(get("Protocol")),
		Start:        start,
		Duration:     ParseDurationMicros(get("Flow Duration")),
		Label:        label,
		IsBenign:     label == "BENIGN",
		IsMalicious:  label != "BENIGN",
		OriginalTime: get("Timestamp"),
	}
	flow.Key = fmt.Sprintf("%s|%s|%d|%s|%d|%s|%s|%d",
		flow.Label, flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol, flow.Start.Format(time.RFC3339), flow.Duration.Microseconds())
	return flow, true
}

func matchAlertsForCSVFlow(flow model.CSVFlow, alertMap map[string][]*model.AlertRecord) []*model.AlertRecord {
	key := model.TupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)
	candidates := alertMap[key]
	if len(candidates) == 0 {
		return nil
	}
	end := flow.Start.Add(flow.Duration).Add(CSVMatchGraceWindow)
	matches := make([]*model.AlertRecord, 0, 2)
	for _, alert := range candidates {
		if alert.MissedDetection {
			continue
		}
		// Flow matching is done on 5-tuple plus time window. The stored alert
		// flow timestamp must lie in:
		//   [csv_timestamp, csv_timestamp + flow_duration + 1 minute]
		if !alert.FlowTimestamp.Before(flow.Start) && !alert.FlowTimestamp.After(end) {
			matches = append(matches, alert)
		}
	}
	return matches
}

func buildHeaderIndex(header []string) map[string]int {
	index := make(map[string]int, len(header))
	for i, name := range header {
		index[strings.TrimSpace(name)] = i
	}
	return index
}
