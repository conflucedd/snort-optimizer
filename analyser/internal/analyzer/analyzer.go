package analyzer

import (
	"io"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"analyser/internal/config"
	"analyser/internal/model"
)

const serviceDetectionLimit = 2 * time.Second

type serviceContext struct {
	KnownServices map[string]bool
}

func ShiftAlerts(alerts []*model.AlertRecord, delta time.Duration) {
	for _, alert := range alerts {
		alert.FlowTimestamp = alert.FlowTimestamp.Add(delta)
		alert.FirstAlertTimestamp = alert.FirstAlertTimestamp.Add(delta)
	}
}

func ComputeMetrics(alerts []*model.AlertRecord, profilers []*model.RuleProfiler, totalMaliciousCSVFlows int64, missedByLabel map[string]int64) (model.AnalysisStats, map[string]*model.RuleMetrics) {
	profilerByRule := map[string]*model.RuleProfiler{}
	for _, profiler := range profilers {
		if profiler.RuleGID == nil || profiler.RuleSID == nil || profiler.RuleREV == nil {
			continue
		}
		profilerByRule[model.RuleKey(*profiler.RuleGID, *profiler.RuleSID, *profiler.RuleREV)] = profiler
	}

	perRule := map[string]*model.RuleMetrics{}
	stats := model.AnalysisStats{
		MissedByLabel:          missedByLabel,
		TotalMaliciousCSVFlows: totalMaliciousCSVFlows,
	}
	for _, count := range missedByLabel {
		stats.MissedMaliciousCSVFlows += count
	}

	for _, alert := range alerts {
		if alert.MissedDetection {
			continue
		}
		stats.TotalAlertFlows++
		if alert.FalsePositive {
			stats.FalsePositiveAlertFlows++
		}
		if alert.RuleGID == nil || alert.RuleSID == nil || alert.RuleREV == nil {
			continue
		}
		key := model.RuleKey(*alert.RuleGID, *alert.RuleSID, *alert.RuleREV)
		metric := perRule[key]
		if metric == nil {
			metric = &model.RuleMetrics{GID: *alert.RuleGID, SID: *alert.RuleSID, REV: *alert.RuleREV}
			if profiler := profilerByRule[key]; profiler != nil {
				metric.CheckCount = profiler.Checks
				metric.MatchCount = profiler.Matches
				metric.ProfilerAlertCount = profiler.Alerts
				metric.TotalTimeUS = profiler.TotalTimeUS
				metric.AvgMatchTime = profiler.AvgMatchTime
				metric.AvgNoMatchTime = profiler.AvgNoMatchTime
				metric.AvgCheckTime = profiler.AvgCheckTime
			}
			perRule[key] = metric
		}
		metric.HitCount++
		metric.PacketAlertCount += int64(alert.AlertCount)
		if alert.FalsePositive {
			metric.FalsePositiveCount++
		}
	}

	// false_positive_rate = false_positive_alert_flows / total_alert_flows
	if stats.TotalAlertFlows > 0 {
		stats.OverallFalsePositiveRate = float64(stats.FalsePositiveAlertFlows) / float64(stats.TotalAlertFlows)
	}
	// missed_detection_rate = missed_malicious_csv_flows / total_malicious_csv_flows
	if stats.TotalMaliciousCSVFlows > 0 {
		stats.OverallMissedDetectionRate = float64(stats.MissedMaliciousCSVFlows) / float64(stats.TotalMaliciousCSVFlows)
	}
	for _, metric := range perRule {
		if metric.HitCount > 0 {
			metric.FalsePositiveRate = float64(metric.FalsePositiveCount) / float64(metric.HitCount)
		}
	}
	return stats, perRule
}

func BuildCandidates(cfg config.Config, alerts []*model.AlertRecord, perRule map[string]*model.RuleMetrics) []model.CandidateRule {
	candidateMap := map[string]*model.CandidateRule{}
	ensureCandidate := func(metric *model.RuleMetrics) *model.CandidateRule {
		key := model.RuleKey(metric.GID, metric.SID, metric.REV)
		if candidateMap[key] == nil {
			candidateMap[key] = &model.CandidateRule{
				GID:     metric.GID,
				SID:     metric.SID,
				REV:     metric.REV,
				Metrics: map[string]interface{}{},
			}
		}
		return candidateMap[key]
	}

	for _, metric := range perRule {
		if metric.FalsePositiveRate >= cfg.FPThreshold {
			candidate := ensureCandidate(metric)
			addReason(candidate, "high_false_positive")
			fillMetrics(candidate, metric)
		}
		if cfg.EnableProfilerPrune &&
			metric.CheckCount >= cfg.ProfilerCheckMin &&
			metric.MatchCount <= cfg.ProfilerMaxMatches &&
			metric.TotalTimeUS >= cfg.ProfilerTimeMinUS &&
			metric.AvgNoMatchTime >= cfg.ProfilerAvgNoMatchUS {
			candidate := ensureCandidate(metric)
			addReason(candidate, "low_value_high_cost")
			fillMetrics(candidate, metric)
		}
	}

	if cfg.EnableOverlapPrune {
		applyOverlapPrune(alerts, perRule, candidateMap, cfg.OverlapThreshold)
	}
	if cfg.EnableServicePrune {
		applyServicePrune(perRule, candidateMap, detectServices())
	}

	candidates := make([]model.CandidateRule, 0, len(candidateMap))
	for _, candidate := range candidateMap {
		candidates = append(candidates, *candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].GID != candidates[j].GID {
			return candidates[i].GID < candidates[j].GID
		}
		if candidates[i].SID != candidates[j].SID {
			return candidates[i].SID < candidates[j].SID
		}
		return candidates[i].REV < candidates[j].REV
	})
	return candidates
}

func applyOverlapPrune(alerts []*model.AlertRecord, perRule map[string]*model.RuleMetrics, candidateMap map[string]*model.CandidateRule, threshold float64) {
	flowSets := map[string]map[string]struct{}{}
	for _, alert := range alerts {
		if alert.MissedDetection || alert.RuleGID == nil || alert.RuleSID == nil || alert.RuleREV == nil {
			continue
		}
		key := model.RuleKey(*alert.RuleGID, *alert.RuleSID, *alert.RuleREV)
		if flowSets[key] == nil {
			flowSets[key] = map[string]struct{}{}
		}
		flowSets[key][model.OverlapFlowKey(alert)] = struct{}{}
	}

	keys := make([]string, 0, len(flowSets))
	for key := range flowSets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			aSet, bSet := flowSets[keys[i]], flowSets[keys[j]]
			if len(aSet) == 0 || len(bSet) == 0 {
				continue
			}
			intersection := intersectCount(aSet, bSet)
			smaller := len(aSet)
			if len(bSet) < smaller {
				smaller = len(bSet)
			}
			// overlap_ratio = |A ∩ B| / min(|A|, |B|)
			ratio := float64(intersection) / float64(smaller)
			if ratio < threshold {
				continue
			}
			loser, winner := chooseOverlapLoser(perRule[keys[i]], perRule[keys[j]])
			if loser == nil || winner == nil {
				continue
			}
			loser.OverlapRatio = &ratio
			loser.OverlapWith = strconv.FormatInt(winner.GID, 10) + ":" + strconv.FormatInt(winner.SID, 10) + ":" + strconv.FormatInt(winner.REV, 10)
			key := model.RuleKey(loser.GID, loser.SID, loser.REV)
			if candidateMap[key] == nil {
				candidateMap[key] = &model.CandidateRule{GID: loser.GID, SID: loser.SID, REV: loser.REV, Metrics: map[string]interface{}{}}
			}
			addReason(candidateMap[key], "high_overlap")
			fillMetrics(candidateMap[key], loser)
		}
	}
}

func chooseOverlapLoser(a, b *model.RuleMetrics) (*model.RuleMetrics, *model.RuleMetrics) {
	if a == nil || b == nil {
		return nil, nil
	}
	if a.HitCount != b.HitCount {
		if a.HitCount < b.HitCount {
			return a, b
		}
		return b, a
	}
	if a.TotalTimeUS > 0 && b.TotalTimeUS > 0 && a.TotalTimeUS != b.TotalTimeUS {
		if a.TotalTimeUS > b.TotalTimeUS {
			return a, b
		}
		return b, a
	}
	if a.SID == b.SID {
		if a.REV <= b.REV {
			return b, a
		}
		return a, b
	}
	if a.SID > b.SID {
		return a, b
	}
	return b, a
}

func detectServices() serviceContext {
	ctx := serviceContext{KnownServices: map[string]bool{}}
	ports := map[int]string{22: "ssh", 53: "dns", 80: "http", 443: "https", 25: "smtp", 3306: "mysql", 5432: "postgresql"}
	for _, cmdArgs := range [][]string{{"ss", "-lntu"}, {"netstat", "-lntu"}} {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		output, err := runWithTimeout(cmd, serviceDetectionLimit)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(output, "\n") {
			for port, service := range ports {
				if strings.Contains(line, ":"+strconv.Itoa(port)) {
					ctx.KnownServices[service] = true
				}
			}
		}
		break
	}
	return ctx
}

func applyServicePrune(perRule map[string]*model.RuleMetrics, candidateMap map[string]*model.CandidateRule, ctx serviceContext) {
	for _, metric := range perRule {
		service := inferServiceFromRule(metric)
		if service == "" || ctx.KnownServices[service] {
			continue
		}
		metric.ServiceMismatchHint = service
		key := model.RuleKey(metric.GID, metric.SID, metric.REV)
		if candidateMap[key] == nil {
			candidateMap[key] = &model.CandidateRule{GID: metric.GID, SID: metric.SID, REV: metric.REV, Metrics: map[string]interface{}{}}
		}
		addReason(candidateMap[key], "service_irrelevant_hint")
		fillMetrics(candidateMap[key], metric)
	}
}

func inferServiceFromRule(metric *model.RuleMetrics) string {
	_ = metric
	return ""
}

func fillMetrics(candidate *model.CandidateRule, metric *model.RuleMetrics) {
	candidate.Metrics["false_positive_rate"] = metric.FalsePositiveRate
	candidate.Metrics["hit_count"] = metric.HitCount
	candidate.Metrics["packet_alert_count"] = metric.PacketAlertCount
	if metric.CheckCount > 0 {
		candidate.Metrics["check_count"] = metric.CheckCount
		candidate.Metrics["match_count"] = metric.MatchCount
	}
	if metric.TotalTimeUS > 0 {
		candidate.Metrics["total_time_us"] = metric.TotalTimeUS
	}
	if metric.AvgMatchTime > 0 {
		candidate.Metrics["avg_match_time"] = metric.AvgMatchTime
	}
	if metric.AvgNoMatchTime > 0 {
		candidate.Metrics["avg_no_match_time"] = metric.AvgNoMatchTime
	}
	if metric.AvgCheckTime > 0 {
		candidate.Metrics["avg_check_time"] = metric.AvgCheckTime
	}
	if metric.OverlapRatio != nil {
		candidate.Metrics["overlap_ratio"] = *metric.OverlapRatio
	}
	if metric.OverlapWith != "" {
		candidate.Metrics["overlap_with"] = metric.OverlapWith
	}
	if metric.ServiceMismatchHint != "" {
		candidate.Metrics["service_mismatch_hint"] = metric.ServiceMismatchHint
	}
}

func addReason(candidate *model.CandidateRule, reason string) {
	for _, existing := range candidate.Reasons {
		if existing == reason {
			return
		}
	}
	candidate.Reasons = append(candidate.Reasons, reason)
	sort.Strings(candidate.Reasons)
}

func intersectCount(a, b map[string]struct{}) int {
	if len(a) > len(b) {
		a, b = b, a
	}
	count := 0
	for key := range a {
		if _, ok := b[key]; ok {
			count++
		}
	}
	return count
}

func runWithTimeout(cmd *exec.Cmd, timeout time.Duration) (string, error) {
	cmd.Stderr = io.Discard
	timer := time.AfterFunc(timeout, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	out, err := cmd.Output()
	return string(out), err
}
