package iter

import "math"

func boundedFactor(factor float64) float64 {
	if factor < 0 {
		return 0
	}
	if factor > 1 {
		return 1
	}
	return factor
}

func scaledLimit(size int, fraction, factor float64) int {
	if size <= 0 || fraction <= 0 || factor <= 0 {
		return 0
	}
	limit := int(math.Ceil(float64(size) * fraction * factor))
	if limit < 1 {
		limit = 1
	}
	if limit > size {
		limit = size
	}
	return limit
}
