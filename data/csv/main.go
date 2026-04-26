package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <csv> <pcap> <output.pcap>\n", os.Args[0])
		os.Exit(1)
	}
	csvPath := os.Args[1]
	pcapPath := os.Args[2]
	outPath := os.Args[3]

	// ---- Step 1: index malicious flows from CSV ----
	fmt.Fprintf(os.Stderr, "Reading CSV: %s\n", csvPath)
	index := make(map[flowKey][]timeWindow)

	f, err := os.Open(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	r := csv.NewReader(f)
	r.LazyQuotes = true
	header, err := r.Read()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	col := make(map[string]int)
	for i, name := range header {
		col[name] = i
	}
	for _, need := range []string{"Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration", "Label"} {
		if _, ok := col[need]; !ok {
			fmt.Fprintf(os.Stderr, "FATAL: column %q not found\n", need)
			os.Exit(1)
		}
	}

	var nLine, nMal int
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		nLine++

		if rec[col["Label"]] == "BENIGN" {
			continue
		}

		ts, err := time.Parse("2006-01-02 15:04:05.999999", rec[col["Timestamp"]])
		if err != nil {
			ts, err = time.Parse("2006-01-02 15:04:05", rec[col["Timestamp"]])
			if err != nil {
				continue
			}
		}

		durMs, err := strconv.ParseFloat(rec[col["Flow Duration"]], 64)
		if err != nil {
			continue
		}

		start := ts.UnixNano()
		end := start + int64(durMs*1e6)
		win := timeWindow{start: start, end: end}

		srcIP := rec[col["Src IP"]]
		dstIP := rec[col["Dst IP"]]
		srcPort, _ := strconv.ParseUint(rec[col["Src Port"]], 10, 16)
		dstPort, _ := strconv.ParseUint(rec[col["Dst Port"]], 10, 16)
		proto, _ := strconv.ParseUint(rec[col["Protocol"]], 10, 8)

		k := makeKey(srcIP, dstIP, uint16(srcPort), uint16(dstPort), uint8(proto))
		index[k] = append(index[k], win)

		rk := makeKey(dstIP, srcIP, uint16(dstPort), uint16(srcPort), uint8(proto))
		index[rk] = append(index[rk], win)

		nMal++
	}
	f.Close()
	fmt.Fprintf(os.Stderr, "CSV rows: %d, malicious: %d, unique keys: %d\n", nLine, nMal, len(index))

	// sort & merge time windows per key
	fmt.Fprintf(os.Stderr, "Merging time windows...\n")
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

	// ---- Step 2: scan pcap, extract matching packets ----
	fmt.Fprintf(os.Stderr, "Scanning pcap: %s\n", pcapPath)
	pf, err := os.Open(pcapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	defer pf.Close()

	ngr, err := pcapgo.NewNgReader(pf, pcapgo.NgReaderOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "LinkType: %v\n", ngr.LinkType())

	of, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	defer of.Close()

	ngw, err := pcapgo.NewNgWriter(of, ngr.LinkType())
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	defer ngw.Flush()

	var (
		eth   layers.Ethernet
		ip4   layers.IPv4
		tcp   layers.TCP
		udp   layers.UDP
		icmp4 layers.ICMPv4
	)
	decoded := make([]gopacket.LayerType, 0, 4)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp, &icmp4)
	parser.IgnoreUnsupported = true

	var totalPkt, matchedPkt int
	for {
		data, ci, err := ngr.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		totalPkt++

		if totalPkt%2000000 == 0 {
			fmt.Fprintf(os.Stderr, "  packets: %d, matched: %d\n", totalPkt, matchedPkt)
		}

		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}

		var srcIP, dstIP [4]byte
		var srcPort, dstPort uint16
		var proto uint8
		hasIP := false

		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeIPv4:
				copy(srcIP[:], ip4.SrcIP.To4())
				copy(dstIP[:], ip4.DstIP.To4())
				proto = uint8(ip4.Protocol)
				hasIP = true
			case layers.LayerTypeTCP:
				srcPort = uint16(tcp.SrcPort)
				dstPort = uint16(tcp.DstPort)
			case layers.LayerTypeUDP:
				srcPort = uint16(udp.SrcPort)
				dstPort = uint16(udp.DstPort)
			}
		}
		if !hasIP {
			continue
		}

		k := flowKey{srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, protocol: proto}
		if wins, ok := index[k]; ok && inAnyWindow(ci.Timestamp.UnixNano(), wins) {
			err = ngw.WritePacket(ci, data)
			if err == nil {
				matchedPkt++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Done! Scanned %d packets, extracted %d malicious packets\n", totalPkt, matchedPkt)
}
