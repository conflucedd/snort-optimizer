package sql

import "time"

func matchAlertsToFlows(flows FlowSet, alerts []AlertForEval) ([]matchedAlert, int64) {
	matches := make([]matchedAlert, 0, len(alerts))
	unmatched := map[string]struct{}{}
	for _, alert := range alerts {
		flowIndex, ok := matchAlertToFlow(flows, alert)
		if !ok {
			unmatched[alertUnmatchedKey(alert)] = struct{}{}
			continue
		}
		matches = append(matches, matchedAlert{Alert: alert, Flow: flowIndex})
	}
	return matches, int64(len(unmatched))
}

func matchAlertToFlow(flows FlowSet, alert AlertForEval) (int, bool) {
	srcIP, srcPort, ok := parseAddrPort(alert.SrcAP)
	if !ok {
		return 0, false
	}
	dstIP, dstPort, ok := parseAddrPort(alert.DstAP)
	if !ok {
		return 0, false
	}
	ts, err := parseAlertTime(alert.Timestamp, flows.year)
	if err != nil {
		return 0, false
	}
	key := tupleKey(srcIP, srcPort, dstIP, dstPort, normalizeProtocol(alert.Proto))
	best := -1
	var bestDistance time.Duration
	for _, idx := range flows.index[key] {
		flow := flows.Flows[idx]
		end := flow.Start.Add(flow.Duration)
		if ts.Before(flow.Start) || ts.After(end) {
			continue
		}
		distance := absDuration(ts.Sub(flow.Start))
		if best < 0 || distance < bestDistance {
			best = idx
			bestDistance = distance
		}
	}
	return best, best >= 0
}
