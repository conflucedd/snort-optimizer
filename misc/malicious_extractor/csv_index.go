package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
)

type csvStats struct {
	rows             int
	malicious        int
	attemptedIgnored int
	badProtocol      int
	badTCPUDPPorts   int
}

func buildMaliciousIndex(csvPath string, ignoreAttempt bool) (map[flowKey][]timeWindow, csvStats, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return nil, csvStats{}, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		return nil, csvStats{}, err
	}

	col := make(map[string]int)
	for i, name := range header {
		col[name] = i
	}
	for _, need := range []string{"Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label"} {
		if _, ok := col[need]; !ok {
			return nil, csvStats{}, fmt.Errorf("column %q not found", need)
		}
	}

	index := make(map[flowKey][]timeWindow)
	var stats csvStats
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		stats.rows++

		label := rec[col["Label"]]
		if label == "BENIGN" {
			continue
		}
		if ignoreAttempt && strings.Contains(label, "Attempted") {
			stats.attemptedIgnored++
			continue
		}

		win, ok := parseWindow(rec[col["Timestamp"]], rec[col["Flow Duration"]])
		if !ok {
			continue
		}

		proto, err := strconv.ParseUint(rec[col["Protocol"]], 10, 8)
		if err != nil {
			stats.badProtocol++
			continue
		}

		srcPort, dstPort, ok := parsePorts(rec[col["Src Port"]], rec[col["Dst Port"]], proto)
		if !ok {
			stats.badTCPUDPPorts++
			continue
		}

		srcIP := rec[col["Src IP"]]
		dstIP := rec[col["Dst IP"]]
		addFlowWindow(index, srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(proto), win)
		stats.malicious++
	}

	return index, stats, nil
}

func parseWindow(timestamp, duration string) (timeWindow, bool) {
	ts, err := time.Parse("2006-01-02 15:04:05.999999", timestamp)
	if err != nil {
		ts, err = time.Parse("2006-01-02 15:04:05", timestamp)
		if err != nil {
			return timeWindow{}, false
		}
	}

	flowDurationMs, err := strconv.ParseFloat(duration, 64)
	if err != nil {
		return timeWindow{}, false
	}

	start := ts.UnixNano()
	return timeWindow{
		start: start,
		end:   start + int64(flowDurationMs*float64(time.Millisecond)),
	}, true
}

func parsePorts(src, dst string, proto uint64) (uint64, uint64, bool) {
	srcPort, srcPortErr := strconv.ParseUint(src, 10, 16)
	dstPort, dstPortErr := strconv.ParseUint(dst, 10, 16)
	if proto == uint64(layers.IPProtocolTCP) || proto == uint64(layers.IPProtocolUDP) {
		return srcPort, dstPort, srcPortErr == nil && dstPortErr == nil
	}
	if srcPortErr != nil {
		srcPort = 0
	}
	if dstPortErr != nil {
		dstPort = 0
	}
	return srcPort, dstPort, true
}

func addFlowWindow(index map[flowKey][]timeWindow, srcIP, dstIP string, srcPort, dstPort uint16, proto uint8, win timeWindow) {
	k := makeKey(srcIP, dstIP, srcPort, dstPort, proto)
	index[k] = append(index[k], win)

	rk := makeKey(dstIP, srcIP, dstPort, srcPort, proto)
	index[rk] = append(index[rk], win)
}
