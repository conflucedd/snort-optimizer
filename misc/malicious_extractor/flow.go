package main

import (
	"net"
	"sort"
)

type flowKey struct {
	srcIP    [4]byte
	dstIP    [4]byte
	srcPort  uint16
	dstPort  uint16
	protocol uint8
}

type timeWindow struct {
	start int64
	end   int64
}

func ip4(s string) [4]byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return [4]byte{}
	}
	var b [4]byte
	copy(b[:], ip[:4])
	return b
}

func makeKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol uint8) flowKey {
	return flowKey{
		srcIP:    ip4(srcIP),
		dstIP:    ip4(dstIP),
		srcPort:  srcPort,
		dstPort:  dstPort,
		protocol: protocol,
	}
}

func inAnyWindow(nano int64, windows []timeWindow) bool {
	i := sort.Search(len(windows), func(i int) bool {
		return windows[i].end >= nano
	})
	return i < len(windows) && nano >= windows[i].start
}

func mergeIndexWindows(index map[flowKey][]timeWindow) {
	for k, wins := range index {
		sort.Slice(wins, func(i, j int) bool { return wins[i].start < wins[j].start })
		merged := wins[:0]
		for _, w := range wins {
			if len(merged) > 0 && w.start <= merged[len(merged)-1].end {
				if w.end > merged[len(merged)-1].end {
					merged[len(merged)-1].end = w.end
				}
			} else {
				merged = append(merged, w)
			}
		}
		index[k] = merged
	}
}
