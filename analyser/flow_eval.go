package analyser

import (
	"database/sql"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

type flowRecord struct {
	ID          string
	SrcIP       string
	SrcPort     int
	DstIP       string
	DstPort     int
	Protocol    string
	Start       time.Time
	Duration    time.Duration
	Label       string
	IsBenign    bool
	IsMalicious bool
}

type flowSet struct {
	flows []flowRecord
	index map[string][]int
	year  int
}

type alertForEval struct {
	ID        int64
	Timestamp string
	Proto     string
	SrcAP     string
	DstAP     string
	GID       int64
	SID       int64
	Rev       int64
}

func loadFlowSet(dbPath string) (flowSet, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return flowSet{}, err
	}
	defer conn.Close()
	table, err := firstUserTable(conn)
	if err != nil {
		return flowSet{}, err
	}
	query := fmt.Sprintf(`SELECT CAST(id AS TEXT), src_ip, src_port, dst_ip, dst_port, CAST(protocol AS TEXT), timestamp, CAST(flow_duration AS REAL), label FROM %s;`, quoteIdent(table))
	rows, err := conn.Query(query)
	if err != nil {
		return flowSet{}, err
	}
	defer rows.Close()
	var flows []flowRecord
	for rows.Next() {
		var id, srcIP, dstIP, tsRaw, label string
		var srcPort, dstPort int
		var protoRaw string
		var durationMicros float64
		if err := rows.Scan(&id, &srcIP, &srcPort, &dstIP, &dstPort, &protoRaw, &tsRaw, &durationMicros, &label); err != nil {
			return flowSet{}, err
		}
		start, err := parseFlowTime(tsRaw)
		if err != nil {
			continue
		}
		normalizedLabel := strings.ToUpper(strings.TrimSpace(label))
		flow := flowRecord{
			ID:          id,
			SrcIP:       strings.TrimSpace(srcIP),
			SrcPort:     srcPort,
			DstIP:       strings.TrimSpace(dstIP),
			DstPort:     dstPort,
			Protocol:    normalizeProtocol(protoRaw),
			Start:       start,
			Duration:    time.Duration(durationMicros * float64(time.Microsecond)),
			Label:       normalizedLabel,
			IsBenign:    normalizedLabel == "BENIGN",
			IsMalicious: normalizedLabel != "" && normalizedLabel != "BENIGN",
		}
		flows = append(flows, flow)
	}
	if err := rows.Err(); err != nil {
		return flowSet{}, err
	}
	if len(flows) == 0 {
		return flowSet{}, fmt.Errorf("flow db %s contains no usable flows", dbPath)
	}
	set := flowSet{flows: flows, index: make(map[string][]int), year: flows[0].Start.Year()}
	for i, flow := range flows {
		forward := tupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)
		reverse := tupleKey(flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort, flow.Protocol)
		set.index[forward] = append(set.index[forward], i)
		if reverse != forward {
			set.index[reverse] = append(set.index[reverse], i)
		}
	}
	return set, nil
}

func evaluateRun(cfg Config, set instanceSet, runID int64, runs []instanceRun, flows flowSet) (Evaluation, error) {
	alerts, err := loadEvalAlerts(set.Exp.DBPath, runID)
	if err != nil {
		return Evaluation{}, err
	}
	eval := evaluateAlerts(flows, alerts, cfg.MatchGraceWindow)
	eval.RunID = runID
	eval.RealRuleTimeUS, _ = sumRuleTimeUS(set.Real.DBPath, runID)
	eval.RealAvgCPU, eval.RealAvgMemMB, _ = latestSystemProfile(set.Real.DBPath, runID)
	for _, run := range runs {
		switch run.Name {
		case instanceBase:
			eval.BaseLoadMS = run.Duration.Milliseconds()
		case instanceExp:
			eval.ExpRuntimeMS = run.Duration.Milliseconds()
		case instanceReal:
			eval.RealRuntimeMS = run.Duration.Milliseconds()
		}
	}
	return eval, nil
}

func evaluateAlerts(flows flowSet, alerts []alertForEval, grace time.Duration) Evaluation {
	alerted := make(map[int]bool)
	unmatched := map[string]struct{}{}
	for _, alert := range alerts {
		srcIP, srcPort, ok := parseAddrPort(alert.SrcAP)
		if !ok {
			unmatched[alertUnmatchedKey(alert)] = struct{}{}
			continue
		}
		dstIP, dstPort, ok := parseAddrPort(alert.DstAP)
		if !ok {
			unmatched[alertUnmatchedKey(alert)] = struct{}{}
			continue
		}
		ts, err := parseAlertTime(alert.Timestamp, flows.year)
		if err != nil {
			unmatched[alertUnmatchedKey(alert)] = struct{}{}
			continue
		}
		key := tupleKey(srcIP, srcPort, dstIP, dstPort, normalizeProtocol(alert.Proto))
		best := -1
		bestDistance := time.Duration(math.MaxInt64)
		for _, idx := range flows.index[key] {
			flow := flows.flows[idx]
			start := flow.Start.Add(-grace)
			end := flow.Start.Add(flow.Duration).Add(grace)
			if ts.Before(start) || ts.After(end) {
				continue
			}
			distance := absDuration(ts.Sub(flow.Start))
			if distance < bestDistance {
				best = idx
				bestDistance = distance
			}
		}
		if best < 0 {
			unmatched[alertUnmatchedKey(alert)] = struct{}{}
			continue
		}
		alerted[best] = true
	}

	var eval Evaluation
	eval.TotalFlows = int64(len(flows.flows))
	eval.AlertedFlows = int64(len(alerted))
	eval.UnmatchedAlertFlows = int64(len(unmatched))
	for i, flow := range flows.flows {
		if flow.IsBenign {
			eval.BenignFlows++
			if alerted[i] {
				eval.FalsePositiveFlows++
			}
			continue
		}
		if flow.IsMalicious {
			eval.MaliciousFlows++
			if alerted[i] {
				eval.DetectedMaliciousFlows++
			} else {
				eval.MissedFlows++
			}
		}
	}
	if eval.TotalFlows > 0 {
		eval.FalsePositiveRate = float64(eval.FalsePositiveFlows) / float64(eval.TotalFlows)
	}
	if eval.MaliciousFlows > 0 {
		eval.MissRate = float64(eval.MissedFlows) / float64(eval.MaliciousFlows)
	}
	return eval
}

func loadEvalAlerts(dbPath string, runID int64) ([]alertForEval, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT id, timestamp, proto, src_ap, dst_ap, gid, sid, rev FROM alerts WHERE run_id = ? ORDER BY id;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alertForEval
	for rows.Next() {
		var a alertForEval
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.Proto, &a.SrcAP, &a.DstAP, &a.GID, &a.SID, &a.Rev); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func sumRuleTimeUS(dbPath string, runID int64) (int64, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var value sql.NullInt64
	err = conn.QueryRow("SELECT COALESCE(sum(time_us), 0) FROM rule_profiler_metrics WHERE run_id = ?;", runID).Scan(&value)
	if err != nil || !value.Valid {
		return 0, err
	}
	return value.Int64, nil
}

func latestSystemProfile(dbPath string, runID int64) (float64, float64, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	var cpu, mem sql.NullFloat64
	err = conn.QueryRow("SELECT avg_cpu, avg_mem_mb FROM system_profiles WHERE run_id = ? ORDER BY id DESC LIMIT 1;", runID).Scan(&cpu, &mem)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return nullFloat(cpu), nullFloat(mem), nil
}

func firstUserTable(conn *sql.DB) (string, error) {
	rows, err := conn.Query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1;")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", fmt.Errorf("flow db has no user table")
	}
	var table string
	if err := rows.Scan(&table); err != nil {
		return "", err
	}
	return table, rows.Err()
}

func quoteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func tupleKey(srcIP string, srcPort int, dstIP string, dstPort int, proto string) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s", srcIP, srcPort, dstIP, dstPort, strings.ToUpper(proto))
}

func normalizeProtocol(raw string) string {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	switch raw {
	case "6":
		return "TCP"
	case "17":
		return "UDP"
	case "1":
		return "ICMP"
	default:
		return raw
	}
}

func parseAddrPort(raw string) (string, int, bool) {
	raw = strings.TrimSpace(raw)
	pos := strings.LastIndex(raw, ":")
	if pos <= 0 || pos == len(raw)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(raw[pos+1:])
	if err != nil {
		return "", 0, false
	}
	host := strings.Trim(raw[:pos], "[]")
	return host, port, true
}

func parseFlowTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	layouts := []string{
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		"1/2/2006 15:04:05",
		"1/2/2006 15:04",
		"1/2/2006 3:04:05 PM",
		"1/2/2006 3:04 PM",
	}
	for _, layout := range layouts {
		if ts, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse flow timestamp %q", raw)
}

func parseAlertTime(raw string, year int) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	candidates := []string{raw}
	if year > 0 {
		candidates = append(candidates,
			strconv.Itoa(year)+"/"+strings.Replace(raw, "-", " ", 1),
			strconv.Itoa(year)+"/"+raw,
		)
	}
	layouts := []string{
		"2006/01/02 15:04:05.999999",
		"2006/01/02 15:04:05",
		"2006/1/2 15:04:05.999999",
		"2006/1/2 15:04:05",
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
	}
	for _, candidate := range candidates {
		for _, layout := range layouts {
			if ts, err := time.ParseInLocation(layout, candidate, time.Local); err == nil {
				return ts, nil
			}
		}
	}
	return time.Time{}, fmt.Errorf("parse alert timestamp %q", raw)
}

func alertUnmatchedKey(alert alertForEval) string {
	return fmt.Sprintf("%d:%d:%d|%s|%s|%s", alert.GID, alert.SID, alert.Rev, alert.SrcAP, alert.DstAP, alert.Timestamp)
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func nullFloat(value sql.NullFloat64) float64 {
	if value.Valid {
		return value.Float64
	}
	return 0
}
