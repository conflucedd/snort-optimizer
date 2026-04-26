package main

import (
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func extractMatchingPackets(pcapPath, outPath string, index map[flowKey][]timeWindow) error {
	fmt.Fprintf(os.Stderr, "Scanning pcap: %s\n", pcapPath)
	pf, err := os.Open(pcapPath)
	if err != nil {
		return err
	}
	defer pf.Close()

	ngr, err := pcapgo.NewNgReader(pf, pcapgo.NgReaderOptions{})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "LinkType: %v\n", ngr.LinkType())

	of, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer of.Close()

	ngw, err := pcapgo.NewNgWriter(of, ngr.LinkType())
	if err != nil {
		return err
	}
	defer ngw.Flush()

	parser, decoded, layers := newPacketParser()
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

		k, ok := packetFlowKey(decoded, layers)
		if !ok {
			continue
		}
		if wins, ok := index[k]; ok && inAnyWindow(ci.Timestamp.UnixNano(), wins) {
			err = ngw.WritePacket(ci, data)
			if err == nil {
				matchedPkt++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Done! Scanned %d packets, extracted %d malicious packets\n", totalPkt, matchedPkt)
	return nil
}

type packetLayers struct {
	eth   layers.Ethernet
	ip4   layers.IPv4
	tcp   layers.TCP
	udp   layers.UDP
	icmp4 layers.ICMPv4
}

func newPacketParser() (*gopacket.DecodingLayerParser, []gopacket.LayerType, *packetLayers) {
	pls := &packetLayers{}
	decoded := make([]gopacket.LayerType, 0, 4)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &pls.eth, &pls.ip4, &pls.tcp, &pls.udp, &pls.icmp4)
	parser.IgnoreUnsupported = true
	return parser, decoded, pls
}

func packetFlowKey(decoded []gopacket.LayerType, pls *packetLayers) (flowKey, bool) {
	var srcIP, dstIP [4]byte
	var srcPort, dstPort uint16
	var proto uint8
	hasIP := false

	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			copy(srcIP[:], pls.ip4.SrcIP.To4())
			copy(dstIP[:], pls.ip4.DstIP.To4())
			proto = uint8(pls.ip4.Protocol)
			hasIP = true
		case layers.LayerTypeTCP:
			srcPort = uint16(pls.tcp.SrcPort)
			dstPort = uint16(pls.tcp.DstPort)
		case layers.LayerTypeUDP:
			srcPort = uint16(pls.udp.SrcPort)
			dstPort = uint16(pls.udp.DstPort)
		}
	}
	if !hasIP {
		return flowKey{}, false
	}
	return flowKey{srcIP: srcIP, dstIP: dstIP, srcPort: srcPort, dstPort: dstPort, protocol: proto}, true
}
