package sql

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

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

func alertUnmatchedKey(alert AlertForEval) string {
	return fmt.Sprintf("%d:%d:%d|%s|%s|%s", alert.GID, alert.SID, alert.Rev, alert.SrcAP, alert.DstAP, alert.Timestamp)
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
