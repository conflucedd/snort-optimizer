package model

import "fmt"

func RuleKey(gid, sid, rev int64) string {
	return fmt.Sprintf("%d:%d:%d", gid, sid, rev)
}

func TupleKey(srcIP string, srcPort int, dstIP string, dstPort int, proto string) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s", srcIP, srcPort, dstIP, dstPort, proto)
}

func AlertMergeKey(alert *AlertRecord) string {
	if alert.RuleGID == nil || alert.RuleSID == nil || alert.RuleREV == nil {
		return TupleKey(alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort, alert.Protocol)
	}
	return fmt.Sprintf("%d:%d:%d|%s", *alert.RuleGID, *alert.RuleSID, *alert.RuleREV,
		TupleKey(alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort, alert.Protocol))
}

func OverlapFlowKey(alert *AlertRecord) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s|%s",
		alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort, alert.Protocol, alert.FlowTimestamp.Format("2006-01-02T15:04:05Z07:00"))
}
