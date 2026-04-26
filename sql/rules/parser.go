package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"snort-optimizer/types"
)

var (
	optionSID       = regexp.MustCompile(`\bsid\s*:\s*(\d+)\s*;`)
	optionGID       = regexp.MustCompile(`\bgid\s*:\s*(\d+)\s*;`)
	optionRev       = regexp.MustCompile(`\brev\s*:\s*(\d+)\s*;`)
	optionMsg       = regexp.MustCompile(`\bmsg\s*:\s*"((?:\\.|[^"\\])*)"\s*;`)
	optionClasstype = regexp.MustCompile(`\bclasstype\s*:\s*([^;]+)\s*;`)
)

func ParseLine(line, sourceFile string) (types.Rule, error) {
	raw := strings.TrimSpace(line)
	if raw == "" {
		return types.Rule{}, fmt.Errorf("empty rule")
	}
	enabled := true
	if strings.HasPrefix(raw, "#") {
		enabled = false
		raw = strings.TrimSpace(strings.TrimPrefix(raw, "#"))
	}
	if raw == "" || strings.HasPrefix(raw, "#") || !isRuleAction(raw) {
		return types.Rule{}, fmt.Errorf("comment")
	}
	open := strings.Index(raw, "(")
	close := strings.LastIndex(raw, ")")
	if open < 0 || close <= open {
		return types.Rule{}, fmt.Errorf("missing rule options")
	}
	header := strings.Fields(strings.TrimSpace(raw[:open]))
	if len(header) < 2 {
		return types.Rule{}, fmt.Errorf("invalid rule header")
	}
	options := raw[open+1 : close]
	sid, err := requiredInt(optionSID, options, "sid")
	if err != nil {
		return types.Rule{}, err
	}
	gid := int64(1)
	if value, ok := optionalInt(optionGID, options); ok {
		gid = value
	}
	rev, _ := optionalInt(optionRev, options)
	rule := types.Rule{
		SID:        sid,
		GID:        gid,
		Rev:        rev,
		Action:     header[0],
		Proto:      header[1],
		Msg:        optionalString(optionMsg, options),
		Classtype:  optionalString(optionClasstype, options),
		Enabled:    enabled,
		SourceFile: sourceFile,
		RawText:    raw,
	}
	if len(header) >= 7 {
		rule.SrcNet = header[2]
		rule.SrcPort = header[3]
		rule.Direction = header[4]
		rule.DstNet = header[5]
		rule.DstPort = header[6]
	}
	return rule, nil
}

func isRuleAction(line string) bool {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "alert", "block", "drop", "log", "pass", "reject", "sdrop":
		return true
	default:
		return false
	}
}

func requiredInt(re *regexp.Regexp, input, name string) (int64, error) {
	value, ok := optionalInt(re, input)
	if !ok {
		return 0, fmt.Errorf("missing %s", name)
	}
	return value, nil
}

func optionalInt(re *regexp.Regexp, input string) (int64, bool) {
	match := re.FindStringSubmatch(input)
	if len(match) != 2 {
		return 0, false
	}
	value, err := strconv.ParseInt(match[1], 10, 64)
	return value, err == nil
}

func optionalString(re *regexp.Regexp, input string) string {
	match := re.FindStringSubmatch(input)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(match[1], `\"`, `"`))
}
