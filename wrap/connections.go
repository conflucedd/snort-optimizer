package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ConnectionRecord struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	TxQueue    int64  `json:"tx_queue"`
	RxQueue    int64  `json:"rx_queue"`
	UID        int    `json:"uid"`
	Interface  string `json:"interface"`
	Inode      string `json:"inode"`
}

type ConnectionQuery struct {
	Limit    int
	Offset   int
	Protocol string
	State    string
	Search   string
}

type ConnectionQueryResult struct {
	Total   int                `json:"total"`
	Items   []ConnectionRecord `json:"items"`
	Summary map[string]int     `json:"summary"`
	Source  string             `json:"source"`
}

func QueryConnections(query ConnectionQuery) (ConnectionQueryResult, error) {
	records, err := loadConnections()
	if err != nil {
		return ConnectionQueryResult{}, err
	}

	filtered := make([]ConnectionRecord, 0, len(records))
	summary := map[string]int{}
	for _, item := range records {
		if !matchesConnectionQuery(item, query) {
			continue
		}
		filtered = append(filtered, item)
		summary["all"]++
		summary["proto:"+item.Protocol]++
		summary["state:"+item.State]++
	}

	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Protocol != filtered[j].Protocol {
			return filtered[i].Protocol < filtered[j].Protocol
		}
		if filtered[i].State != filtered[j].State {
			return filtered[i].State < filtered[j].State
		}
		if filtered[i].LocalAddr != filtered[j].LocalAddr {
			return filtered[i].LocalAddr < filtered[j].LocalAddr
		}
		if filtered[i].LocalPort != filtered[j].LocalPort {
			return filtered[i].LocalPort < filtered[j].LocalPort
		}
		if filtered[i].RemoteAddr != filtered[j].RemoteAddr {
			return filtered[i].RemoteAddr < filtered[j].RemoteAddr
		}
		return filtered[i].RemotePort < filtered[j].RemotePort
	})

	total := len(filtered)
	start := min(query.Offset, total)
	end := min(start+query.Limit, total)

	return ConnectionQueryResult{
		Total:   total,
		Items:   filtered[start:end],
		Summary: summary,
		Source:  "procfs",
	}, nil
}

func CountConnections() (int, error) {
	records, err := loadConnections()
	if err != nil {
		return 0, err
	}
	return len(records), nil
}

func loadConnections() ([]ConnectionRecord, error) {
	files := []struct {
		path     string
		protocol string
	}{
		{path: "/proc/net/tcp", protocol: "tcp"},
		{path: "/proc/net/tcp6", protocol: "tcp6"},
		{path: "/proc/net/udp", protocol: "udp"},
		{path: "/proc/net/udp6", protocol: "udp6"},
	}

	var all []ConnectionRecord
	for _, file := range files {
		items, err := parseProcNet(file.path, file.protocol)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		all = append(all, items...)
	}
	return all, nil
}

func parseProcNet(path string, protocol string) ([]ConnectionRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	items := make([]ConnectionRecord, 0, 256)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localAddr, localPort, err := decodeProcAddress(fields[1])
		if err != nil {
			continue
		}
		remoteAddr, remotePort, err := decodeProcAddress(fields[2])
		if err != nil {
			continue
		}
		txQueue, rxQueue := parseQueues(fields[4])
		state := decodeTCPState(fields[3], strings.HasPrefix(protocol, "udp"))
		uid := ParseIntDefault(fields[7], 0)
		inode := fields[9]

		items = append(items, ConnectionRecord{
			Protocol:   protocol,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			State:      state,
			TxQueue:    txQueue,
			RxQueue:    rxQueue,
			UID:        uid,
			Interface:  "",
			Inode:      inode,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func decodeProcAddress(value string) (string, int, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address %q", value)
	}

	ipHex := parts[0]
	port64, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}

	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return "", 0, err
	}

	switch len(raw) {
	case 4:
		reverseBytes(raw)
	case 16:
		for i := 0; i < len(raw); i += 4 {
			reverseBytes(raw[i : i+4])
		}
	default:
		return "", 0, fmt.Errorf("unsupported ip length %d", len(raw))
	}

	ip := net.IP(raw)
	if ip.IsUnspecified() {
		return "*", int(port64), nil
	}
	return ip.String(), int(port64), nil
}

func reverseBytes(buf []byte) {
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
}

func parseQueues(value string) (int64, int64) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, 0
	}
	tx, _ := strconv.ParseInt(parts[0], 16, 64)
	rx, _ := strconv.ParseInt(parts[1], 16, 64)
	return tx, rx
}

func decodeTCPState(code string, isUDP bool) string {
	if isUDP {
		switch code {
		case "07":
			return "UNCONN"
		case "0A":
			return "LISTEN"
		default:
			return strings.ToUpper(code)
		}
	}

	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}
	if state, ok := states[strings.ToUpper(code)]; ok {
		return state
	}
	return strings.ToUpper(code)
}

func matchesConnectionQuery(item ConnectionRecord, query ConnectionQuery) bool {
	if query.Protocol != "" && !strings.EqualFold(item.Protocol, query.Protocol) {
		return false
	}
	if query.State != "" && !strings.EqualFold(item.State, query.State) {
		return false
	}
	search := strings.TrimSpace(strings.ToLower(query.Search))
	if search == "" {
		return true
	}
	haystack := strings.ToLower(fmt.Sprintf("%s %d %s %d %s %s %d",
		item.LocalAddr, item.LocalPort, item.RemoteAddr, item.RemotePort, item.Protocol, item.State, item.UID))
	return strings.Contains(haystack, search)
}
