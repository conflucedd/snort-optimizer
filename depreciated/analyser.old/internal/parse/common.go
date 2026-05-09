package parse

import (
	"strconv"
	"strings"
	"time"
)

const (
	AlertMergeWindow    = 2 * time.Minute
	CSVMatchGraceWindow = time.Minute
)

func NormalizeProtocol(raw string) string {
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

func NormalizeLabel(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func ParseDurationMicros(raw string) time.Duration {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return time.Duration(value * float64(time.Microsecond))
}

func ParseCSVTimestamp(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	layouts := []string{
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
	return time.Time{}, &time.ParseError{Layout: "csv_timestamp", Value: raw}
}

func ParseSnortTimestamp(raw string, year int) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	layouts := []string{
		"2006/01/02 15:04:05.999999",
		"2006/01/02 15:04:05",
		"2006/1/2 15:04:05.999999",
		"2006/1/2 15:04:05",
	}
	candidates := []string{
		strconv.Itoa(year) + "/" + strings.ReplaceAll(raw, "-", " "),
		strconv.Itoa(year) + "/" + raw,
	}
	for _, candidate := range candidates {
		for _, layout := range layouts {
			if ts, err := time.ParseInLocation(layout, candidate, time.Local); err == nil {
				return ts, nil
			}
		}
	}
	return time.Time{}, &time.ParseError{Layout: "snort_timestamp", Value: raw}
}

func AbsDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func Int64Ptr(v int64) *int64 {
	return &v
}
