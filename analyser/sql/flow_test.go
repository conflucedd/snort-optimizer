package sql

import (
	"testing"
	"time"
)

func TestEvaluateAlertsCountsFalsePositiveByFlow(t *testing.T) {
	base := time.Date(2017, 7, 4, 10, 0, 0, 0, time.Local)
	flows := FlowSet{
		Flows: []FlowRecord{
			{
				ID:       "1",
				SrcIP:    "10.0.0.1",
				SrcPort:  12345,
				DstIP:    "10.0.0.2",
				DstPort:  80,
				Protocol: "TCP",
				Start:    base,
				Duration: time.Minute,
				Label:    "BENIGN",
				IsBenign: true,
			},
			{
				ID:          "2",
				SrcIP:       "10.0.0.3",
				SrcPort:     23456,
				DstIP:       "10.0.0.4",
				DstPort:     443,
				Protocol:    "TCP",
				Start:       base.Add(2 * time.Minute),
				Duration:    time.Minute,
				Label:       "ATTACK",
				IsMalicious: true,
			},
		},
		index: map[string][]int{},
		year:  2017,
	}
	for i, flow := range flows.Flows {
		flows.index[tupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)] = append(flows.index[tupleKey(flow.SrcIP, flow.SrcPort, flow.DstIP, flow.DstPort, flow.Protocol)], i)
		flows.index[tupleKey(flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort, flow.Protocol)] = append(flows.index[tupleKey(flow.DstIP, flow.DstPort, flow.SrcIP, flow.SrcPort, flow.Protocol)], i)
	}

	eval := evaluateAlerts(flows, []AlertForEval{
		{Timestamp: "07/04-10:00:10.000000", Proto: "TCP", SrcAP: "10.0.0.1:12345", DstAP: "10.0.0.2:80", GID: 1, SID: 1001, Rev: 1},
		{Timestamp: "07/04-10:00:20.000000", Proto: "TCP", SrcAP: "10.0.0.1:12345", DstAP: "10.0.0.2:80", GID: 1, SID: 1002, Rev: 1},
		{Timestamp: "07/04-10:02:05.000000", Proto: "TCP", SrcAP: "10.0.0.4:443", DstAP: "10.0.0.3:23456", GID: 1, SID: 2001, Rev: 1},
		{Timestamp: "07/04-10:03:30.000000", Proto: "TCP", SrcAP: "10.0.0.4:443", DstAP: "10.0.0.3:23456", GID: 1, SID: 2002, Rev: 1},
		{Timestamp: "07/04-10:30:00.000000", Proto: "TCP", SrcAP: "10.0.0.9:1", DstAP: "10.0.0.8:2", GID: 1, SID: 3001, Rev: 1},
	})

	if eval.AlertedFlows != 2 {
		t.Fatalf("AlertedFlows = %d, want 2", eval.AlertedFlows)
	}
	if eval.FalsePositiveFlows != 1 {
		t.Fatalf("FalsePositiveFlows = %d, want 1", eval.FalsePositiveFlows)
	}
	if eval.FalsePositiveRate != 0.5 {
		t.Fatalf("FalsePositiveRate = %f, want 0.5", eval.FalsePositiveRate)
	}
	if eval.MissedFlows != 0 {
		t.Fatalf("MissedFlows = %d, want 0", eval.MissedFlows)
	}
	if eval.UnmatchedAlertFlows != 2 {
		t.Fatalf("UnmatchedAlertFlows = %d, want 2", eval.UnmatchedAlertFlows)
	}
}
