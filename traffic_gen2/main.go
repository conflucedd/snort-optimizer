package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type config struct {
	ifaceName string
	targetIP  net.IP
	gatewayIP net.IP
	srcIP     net.IP
	dstMAC    net.HardwareAddr
	srcMAC    net.HardwareAddr
	ports     []uint16
	rate      int
	ttl       uint8
	window    uint16
	dryRun    bool
	allowWAN  bool
}

func main() {
	log.SetFlags(0)

	cfg, err := parseConfig()
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}

	if !cfg.allowWAN && !isPrivateOrLoopback(cfg.targetIP) {
		log.Fatalf("拒绝扫描公网目标 %s；实验室外部目标请显式加 -allow-wan", cfg.targetIP)
	}

	if cfg.dryRun {
		log.Printf("dry-run: iface=%s src=%s target=%s ports=%d rate=%d/s dst-mac=%s",
			cfg.ifaceName, cfg.srcIP, cfg.targetIP, len(cfg.ports), cfg.rate, cfg.dstMAC)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runScan(ctx, cfg); err != nil {
		log.Fatalf("扫描失败: %v", err)
	}
}

func parseConfig() (config, error) {
	var cfg config
	var target, ports, srcIP, dstMAC, gateway string
	var ttl, window uint

	flag.StringVar(&cfg.ifaceName, "iface", "enp11s0", "发包网卡")
	flag.StringVar(&target, "target", "", "目标 IPv4 地址，必须显式指定")
	flag.StringVar(&ports, "ports", "1-1024", "端口列表，例如 22,80,443 或 1-1024")
	flag.StringVar(&srcIP, "src-ip", "", "源 IPv4 地址；默认自动取网卡 IPv4")
	flag.StringVar(&dstMAC, "dst-mac", "", "目的 MAC；同网段目标默认 ARP 解析，跨网段可指定网关 MAC")
	flag.StringVar(&gateway, "gateway", "", "网关 IPv4；目标不在本网段时用于 ARP 解析目的 MAC")
	flag.IntVar(&cfg.rate, "rate", 200, "每秒发送包数")
	flag.UintVar(&ttl, "ttl", 64, "IPv4 TTL")
	flag.UintVar(&window, "window", 64240, "TCP window")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "只打印配置，不发包")
	flag.BoolVar(&cfg.allowWAN, "allow-wan", false, "允许扫描公网地址")
	flag.Parse()

	if ttl > 255 {
		return cfg, fmt.Errorf("ttl 必须在 0..255 之间: %d", ttl)
	}
	if window > 65535 {
		return cfg, fmt.Errorf("window 必须在 0..65535 之间: %d", window)
	}
	cfg.ttl = uint8(ttl)
	cfg.window = uint16(window)

	if target == "" {
		return cfg, errors.New("缺少 -target")
	}
	cfg.targetIP = parseIPv4(target)
	if cfg.targetIP == nil {
		return cfg, fmt.Errorf("无效目标 IPv4: %q", target)
	}
	if cfg.rate <= 0 || cfg.rate > 100000 {
		return cfg, fmt.Errorf("rate 必须在 1..100000 之间: %d", cfg.rate)
	}

	var err error
	cfg.ports, err = parsePorts(ports)
	if err != nil {
		return cfg, err
	}

	iface, err := net.InterfaceByName(cfg.ifaceName)
	if err != nil {
		return cfg, fmt.Errorf("找不到网卡 %q: %w", cfg.ifaceName, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return cfg, fmt.Errorf("网卡 %q 未启用", cfg.ifaceName)
	}
	if len(iface.HardwareAddr) == 0 {
		return cfg, fmt.Errorf("网卡 %q 没有硬件地址", cfg.ifaceName)
	}
	cfg.srcMAC = iface.HardwareAddr

	if srcIP != "" {
		cfg.srcIP = parseIPv4(srcIP)
		if cfg.srcIP == nil {
			return cfg, fmt.Errorf("无效源 IPv4: %q", srcIP)
		}
	} else {
		cfg.srcIP, err = firstInterfaceIPv4(iface)
		if err != nil {
			return cfg, err
		}
	}

	if dstMAC != "" {
		cfg.dstMAC, err = net.ParseMAC(dstMAC)
		if err != nil {
			return cfg, fmt.Errorf("无效目的 MAC: %w", err)
		}
	} else {
		arpIP := cfg.targetIP
		if gateway != "" {
			arpIP = parseIPv4(gateway)
			if arpIP == nil {
				return cfg, fmt.Errorf("无效网关 IPv4: %q", gateway)
			}
			cfg.gatewayIP = arpIP
		}
		cfg.dstMAC, err = resolveMAC(cfg.ifaceName, cfg.srcMAC, cfg.srcIP, arpIP)
		if err != nil {
			return cfg, fmt.Errorf("ARP 解析失败，可用 -dst-mac 手动指定: %w", err)
		}
	}

	return cfg, nil
}

func runScan(ctx context.Context, cfg config) error {
	handle, err := pcap.OpenLive(cfg.ifaceName, 65535, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("打开网卡失败，可能需要 sudo 或 CAP_NET_RAW: %w", err)
	}
	defer handle.Close()

	interval := time.Second / time.Duration(cfg.rate)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("开始 SYN 扫描流量: iface=%s src=%s target=%s ports=%d rate=%d/s dst-mac=%s",
		cfg.ifaceName, cfg.srcIP, cfg.targetIP, len(cfg.ports), cfg.rate, cfg.dstMAC)

	sent := 0
	for _, port := range cfg.ports {
		select {
		case <-ctx.Done():
			log.Printf("已中断，已发送 %d 个 SYN 包", sent)
			return nil
		case <-ticker.C:
		}

		packet, err := buildSynPacket(cfg, port)
		if err != nil {
			return err
		}
		if err := handle.WritePacketData(packet); err != nil {
			return fmt.Errorf("发送端口 %d 失败: %w", port, err)
		}
		sent++
		if sent%100 == 0 || sent == len(cfg.ports) {
			log.Printf("进度: %d/%d", sent, len(cfg.ports))
		}
	}

	log.Printf("完成，已发送 %d 个 SYN 包", sent)
	return nil
}

func buildSynPacket(cfg config, dstPort uint16) ([]byte, error) {
	ethernet := &layers.Ethernet{
		SrcMAC:       cfg.srcMAC,
		DstMAC:       cfg.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      cfg.ttl,
		SrcIP:    cfg.srcIP,
		DstIP:    cfg.targetIP,
		Protocol: layers.IPProtocolTCP,
		Id:       randomUint16(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(32768 + randomUint16()%28232),
		DstPort: layers.TCPPort(dstPort),
		Seq:     randomUint32(),
		SYN:     true,
		Window:  cfg.window,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{7}},
		},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ethernet, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func resolveMAC(ifaceName string, srcMAC net.HardwareAddr, srcIP, targetIP net.IP) (net.HardwareAddr, error) {
	handle, err := pcap.OpenLive(ifaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(fmt.Sprintf("arp and src host %s", targetIP)); err != nil {
		return nil, err
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		return nil, err
	}
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(2 * time.Second)
	for {
		select {
		case packet := <-source.Packets():
			if packet == nil {
				continue
			}
			layer := packet.Layer(layers.LayerTypeARP)
			if layer == nil {
				continue
			}
			reply, ok := layer.(*layers.ARP)
			if !ok || reply.Operation != layers.ARPReply {
				continue
			}
			if net.IP(reply.SourceProtAddress).Equal(targetIP) {
				return net.HardwareAddr(reply.SourceHwAddress), nil
			}
		case <-timeout:
			return nil, fmt.Errorf("等待 %s 的 ARP 响应超时", targetIP)
		}
	}
}

func firstInterfaceIPv4(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := parseIPv4(ip.String()); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("网卡 %q 没有 IPv4 地址", iface.Name)
}

func parseIPv4(value string) net.IP {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

func parsePorts(value string) ([]uint16, error) {
	seen := make(map[uint16]struct{})
	var ports []uint16
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := parsePort(bounds[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(bounds[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("端口范围错误: %s", part)
			}
			for port := start; port <= end; port++ {
				if _, ok := seen[port]; !ok {
					seen[port] = struct{}{}
					ports = append(ports, port)
				}
			}
			continue
		}
		port, err := parsePort(part)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("端口列表为空")
	}
	return ports, nil
}

func parsePort(value string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("无效端口: %q", value)
	}
	return uint16(n), nil
}

func isPrivateOrLoopback(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	return false
}

func randomUint16() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}
