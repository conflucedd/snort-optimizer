package iter

import "snort-optimizer/analyser"

func HighCostRules() analyser.RegisteredFunction {
	return analyser.RegisteredFunction{
		Name: "iter_high_cost_rules",
		Type: analyser.ITER,
		Fn:   analyser.IterHighCostRules,
	}
}
