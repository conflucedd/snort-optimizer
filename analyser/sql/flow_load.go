package sql

import (
	dbsql "database/sql"
	"fmt"
	"strings"
	"time"
)

func LoadFlowSet(dbPath string) (FlowSet, error) {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return FlowSet{}, err
	}
	defer conn.Close()
	table, err := firstUserTable(conn)
	if err != nil {
		return FlowSet{}, err
	}
	query := fmt.Sprintf(`SELECT CAST(id AS TEXT), src_ip, src_port, dst_ip, dst_port, CAST(protocol AS TEXT), timestamp, CAST(flow_duration AS REAL), label FROM %s;`, quoteIdent(table))
	rows, err := conn.Query(query)
	if err != nil {
		return FlowSet{}, err
	}
	defer rows.Close()
	var flows []FlowRecord
	for rows.Next() {
		var id, srcIP, dstIP, tsRaw, label string
		var srcPort, dstPort int
		var protoRaw string
		var durationMicros float64
		if err := rows.Scan(&id, &srcIP, &srcPort, &dstIP, &dstPort, &protoRaw, &tsRaw, &durationMicros, &label); err != nil {
			return FlowSet{}, err
		}
		start, err := parseFlowTime(tsRaw)
		if err != nil {
			continue
		}
		normalizedLabel := strings.ToUpper(strings.TrimSpace(label))
		flow := FlowRecord{
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
		return FlowSet{}, err
	}
	if len(flows) == 0 {
		return FlowSet{}, fmt.Errorf("flow db %s contains no usable flows", dbPath)
	}
	set := FlowSet{Flows: flows, index: make(map[string][]int), year: flows[0].Start.Year()}
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

func firstUserTable(conn *dbsql.DB) (string, error) {
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
