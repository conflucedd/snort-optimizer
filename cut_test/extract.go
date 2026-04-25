package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	_ "github.com/mattn/go-sqlite3"
)

// ---------- 数据结构 ----------

type TimeSpan struct {
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
	Protocol uint8
	StartUTC time.Time
	EndUTC   time.Time
	Label    string

	// 原始 CSV 信息
	CSVTimestamp string
	DurationUS   int64
	CSVLine      int // 行号
}

type MatchStats struct {
	MatchedPackets int
	FirstPacketUTC *time.Time
	LastPacketUTC  *time.Time
}

// ---------- 5元组 Key ----------

func makeKey(sip, dip string, sp, dp uint16, proto uint8) string {
	return fmt.Sprintf("%s|%d|%s|%d|%d", sip, sp, dip, dp, proto)
}

// ---------- CSV 解析 ----------

func parseTimestamp(s string, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	formats := []string{
		"2/1/2006 15:04",
		"2/1/2006 15:04:05",
		"02/01/2006 15:04",
		"02/01/2006 15:04:05",
		"1/2/2006 15:04",
		"1/2/2006 15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.ParseInLocation(f, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析时间戳: %s", s)
}

func parseCSV(path string, loc *time.Location) (
	malIndex map[string][]TimeSpan,
	benIndex map[string][]TimeSpan,
	malFlows []TimeSpan,
	stats map[string]int,
	err error,
) {
	malIndex = make(map[string][]TimeSpan)
	benIndex = make(map[string][]TimeSpan)
	stats = make(map[string]int)

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("打开CSV失败: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.LazyQuotes = true

	// 读表头
	header, err := reader.Read()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("读取CSV表头失败: %w", err)
	}

	// 找到需要的列
	colIdx := func(name string) int {
		for i, h := range header {
			if strings.TrimSpace(h) == name {
				return i
			}
		}
		return -1
	}

	idxSrcIP := colIdx("Source IP")
	idxSrcPort := colIdx("Source Port")
	idxDstIP := colIdx("Destination IP")
	idxDstPort := colIdx("Destination Port")
	idxProtocol := colIdx("Protocol")
	idxTimestamp := colIdx("Timestamp")
	idxDuration := colIdx("Flow Duration")
	idxLabel := colIdx("Label")

	if idxSrcIP < 0 || idxDstIP < 0 || idxSrcPort < 0 || idxDstPort < 0 ||
		idxProtocol < 0 || idxTimestamp < 0 || idxDuration < 0 || idxLabel < 0 {
		return nil, nil, nil, nil, fmt.Errorf("CSV缺少必要列，检查列名: %v", header)
	}

	lineNum := 1
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[警告] 第 %d 行解析失败: %v", lineNum+1, err)
			lineNum++
			continue
		}
		lineNum++

		label := strings.TrimSpace(record[idxLabel])
		if label == "" || label == "Label" {
			continue
		}

		// 解析时间（CSV时间为加拿大东部时间）
		tsEDT, err := parseTimestamp(record[idxTimestamp], loc)
		if err != nil {
			log.Printf("[警告] 第 %d 行时间解析失败: %v", lineNum, err)
			continue
		}

		// 转为 UTC（pcap 中的时间戳是 UTC）
		tsUTC := tsEDT.UTC()

		// 解析流持续时间（微秒）
		var durationUS int64
		fmt.Sscanf(strings.TrimSpace(record[idxDuration]), "%d", &durationUS)
		duration := time.Duration(durationUS) * time.Microsecond

		// 时间窗口: [分钟开始, 分钟开始 + 60s + duration]
		// 因为 CSV 只有分钟精度，实际开始时间在分钟内的任意位置
		startOfMinute := time.Date(
			tsUTC.Year(), tsUTC.Month(), tsUTC.Day(),
			tsUTC.Hour(), tsUTC.Minute(), 0, 0, time.UTC,
		)
		windowStart := startOfMinute
		windowEnd := startOfMinute.Add(60*time.Second + duration)

		// 解析端口
		var srcPort, dstPort uint64
		fmt.Sscanf(strings.TrimSpace(record[idxSrcPort]), "%d", &srcPort)
		fmt.Sscanf(strings.TrimSpace(record[idxDstPort]), "%d", &dstPort)

		var protocol uint64
		fmt.Sscanf(strings.TrimSpace(record[idxProtocol]), "%d", &protocol)

		ts := TimeSpan{
			SrcIP:    strings.TrimSpace(record[idxSrcIP]),
			SrcPort:  uint16(srcPort),
			DstIP:    strings.TrimSpace(record[idxDstIP]),
			DstPort:  uint16(dstPort),
			Protocol: uint8(protocol),
			StartUTC: windowStart,
			EndUTC:   windowEnd,
			Label:    label,

			CSVTimestamp: strings.TrimSpace(record[idxTimestamp]),
			DurationUS:   durationUS,
			CSVLine:      lineNum,
		}

		// 按标签分组
		if label == "BENIGN" {
			keyF := makeKey(ts.SrcIP, ts.DstIP, ts.SrcPort, ts.DstPort, ts.Protocol)
			benIndex[keyF] = append(benIndex[keyF], ts)

			keyR := makeKey(ts.DstIP, ts.SrcIP, ts.DstPort, ts.SrcPort, ts.Protocol)
			benIndex[keyR] = append(benIndex[keyR], ts)
		} else {
			keyF := makeKey(ts.SrcIP, ts.DstIP, ts.SrcPort, ts.DstPort, ts.Protocol)
			malIndex[keyF] = append(malIndex[keyF], ts)

			keyR := makeKey(ts.DstIP, ts.SrcIP, ts.DstPort, ts.SrcPort, ts.Protocol)
			malIndex[keyR] = append(malIndex[keyR], ts)

			malFlows = append(malFlows, ts)
		}

		stats[label]++
	}

	return malIndex, benIndex, malFlows, stats, nil
}

// ---------- 匹配逻辑 ----------

func timeInSpan(ts time.Time, spans []TimeSpan) *TimeSpan {
	for i := range spans {
		if (ts.Equal(spans[i].StartUTC) || ts.After(spans[i].StartUTC)) &&
			(ts.Equal(spans[i].EndUTC) || ts.Before(spans[i].EndUTC)) {
			return &spans[i]
		}
	}
	return nil
}

func findMatch(
	packetTS time.Time,
	srcIP string, dstIP string,
	srcPort, dstPort uint16,
	protocol uint8,
	malIndex, benIndex map[string][]TimeSpan,
) *TimeSpan {
	keyF := makeKey(srcIP, dstIP, srcPort, dstPort, protocol)
	keyR := makeKey(dstIP, srcIP, dstPort, srcPort, protocol)

	// 先查恶意
	malMatch := timeInSpan(packetTS, malIndex[keyF])
	if malMatch == nil {
		malMatch = timeInSpan(packetTS, malIndex[keyR])
	}
	if malMatch == nil {
		return nil
	}

	// 检查 BENIGN 冲突：同一个 5 元组的 BENIGN 时间窗口是否也覆盖这个包
	if timeInSpan(packetTS, benIndex[keyF]) != nil {
		return nil // 冲突，跳过
	}
	if timeInSpan(packetTS, benIndex[keyR]) != nil {
		return nil // 冲突，跳过
	}

	return malMatch
}

// ---------- pcap 处理 ----------

// 通用 pcap 处理循环：从 reader 读取包，匹配后写入 writer
func runPcapLoop(
	r packetReader, w packetWriter,
	malIndex, benIndex map[string][]TimeSpan,
	malFlows []TimeSpan,
) (totalPackets int64, matchedPackets int64, flowMatches map[int]*MatchStats, flushErr error) {

	flowMatches = make(map[int]*MatchStats)
	for _, f := range malFlows {
		flowMatches[f.CSVLine] = &MatchStats{}
	}

	// 用于零拷贝解析的 decoder
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP

	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	decoder.IgnoreUnsupported = true

	lastLogTime := time.Now()
	decoded := make([]gopacket.LayerType, 0, 10)

	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("[警告] 读取数据包失败: %v", err)
			continue
		}
		totalPackets++

		// 零拷贝解析 — 注意: DecodeLayers 返回 error 时 decoded 中仍有已解析的层
		decoded = decoded[:0]
		_ = decoder.DecodeLayers(data, &decoded)

		// 提取 5 元组
		var srcIP, dstIP string
		var srcPort, dstPort uint16
		var protocol uint8
		hasIP := false

		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeIPv4:
				srcIP = ip4.SrcIP.String()
				dstIP = ip4.DstIP.String()
				protocol = uint8(ip4.Protocol)
				hasIP = true
			case layers.LayerTypeIPv6:
				srcIP = ip6.SrcIP.String()
				dstIP = ip6.DstIP.String()
				protocol = uint8(ip6.NextHeader)
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

		// 检查匹配
		packetTS := ci.Timestamp.UTC()

		if match := findMatch(packetTS, srcIP, dstIP, srcPort, dstPort, protocol, malIndex, benIndex); match != nil {
			err := w.WritePacket(ci, data)
			if err != nil {
				log.Printf("[警告] 写入数据包失败: %v", err)
				continue
			}
			matchedPackets++

	// 更新流统计 — 使用 CSVLine 做 key（因为 map 中的 TimeSpan 是副本，指针不相等）
	flowKey := match.CSVLine
	stats := flowMatches[flowKey]
	if stats != nil {
		stats.MatchedPackets++
		if stats.FirstPacketUTC == nil || packetTS.Before(*stats.FirstPacketUTC) {
			stats.FirstPacketUTC = &packetTS
		}
		if stats.LastPacketUTC == nil || packetTS.After(*stats.LastPacketUTC) {
			stats.LastPacketUTC = &packetTS
		}
	}
		}

		// 进度日志
		if totalPackets%1000000 == 0 || time.Since(lastLogTime) > 10*time.Second {
			log.Printf("[处理] 已处理 %.1fM 个数据包 | 已匹配 %d 个恶意包 | 命中流: %d",
				float64(totalPackets)/1000000, matchedPackets, countMatchedFlows(flowMatches))
			lastLogTime = time.Now()
		}
	}

	return totalPackets, matchedPackets, flowMatches, nil
}

type packetReader interface {
	ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error)
}

type packetWriter interface {
	WritePacket(ci gopacket.CaptureInfo, data []byte) error
}

func processPcap(
	pcapPath, outputPath string,
	malIndex, benIndex map[string][]TimeSpan,
	malFlows []TimeSpan,
) (totalPackets int64, matchedPackets int64, flowMatches map[int]*MatchStats, err error) {

	f, err := os.Open(pcapPath)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("打开pcap失败: %w", err)
	}
	defer f.Close()

	// 检测 pcap 格式
	magic := make([]byte, 4)
	f.Read(magic)
	f.Seek(0, 0)
	isPcapng := magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a

	outF, err := os.Create(outputPath)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("创建输出pcap失败: %w", err)
	}
	defer outF.Close()

	if isPcapng {
		log.Printf("[PCAP] 格式: pcapng")
		ngReader, err := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{})
		if err != nil {
			return 0, 0, nil, fmt.Errorf("读取pcapng header失败: %w", err)
		}

		ngWriter, err := pcapgo.NewNgWriter(outF, ngReader.LinkType())
		if err != nil {
			return 0, 0, nil, fmt.Errorf("创建pcapng writer失败: %w", err)
		}
		defer ngWriter.Flush()

		return runPcapLoop(ngReader, ngWriter, malIndex, benIndex, malFlows)
	}

	// 传统 pcap 格式
	log.Printf("[PCAP] 格式: 传统 pcap")
	oldReader, err := pcapgo.NewReader(f)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("读取pcap header失败: %w", err)
	}

	w := pcapgo.NewWriter(outF)
	err = w.WriteFileHeader(oldReader.Snaplen(), oldReader.LinkType())
	if err != nil {
		return 0, 0, nil, fmt.Errorf("写入pcap header失败: %w", err)
	}

	return runPcapLoop(oldReader, w, malIndex, benIndex, malFlows)
}
func countMatchedFlows(flowMatches map[int]*MatchStats) int {
	count := 0
	for _, s := range flowMatches {
		if s.MatchedPackets > 0 {
			count++
		}
	}
	return count
}

// ---------- SQLite ----------

func initDB(dbPath string) (*sql.DB, error) {
	// 删除旧数据库
	os.Remove(dbPath)

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	// 设置 pragma 优化
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=OFF",
		"PRAGMA cache_size=-80000", // 80MB cache
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			log.Printf("[警告] SQLite pragma 失败: %v", err)
		}
	}

	schema := `
	CREATE TABLE malicious_flows (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		src_ip TEXT NOT NULL,
		src_port INTEGER NOT NULL,
		dst_ip TEXT NOT NULL,
		dst_port INTEGER NOT NULL,
		protocol INTEGER NOT NULL,
		label TEXT NOT NULL,
		csv_timestamp_edt TEXT NOT NULL,
		flow_duration_us INTEGER NOT NULL,
		flow_window_start_utc TEXT NOT NULL,
		flow_window_end_utc TEXT NOT NULL,
		matched_packets INTEGER NOT NULL DEFAULT 0,
		first_packet_utc TEXT,
		last_packet_utc TEXT
	);
	CREATE INDEX idx_label ON malicious_flows(label);
	CREATE INDEX idx_src ON malicious_flows(src_ip, src_port);
	CREATE INDEX idx_dst ON malicious_flows(dst_ip, dst_port);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("建表失败: %w", err)
	}

	return db, nil
}

func writeResults(db *sql.DB, flows []TimeSpan, stats map[int]*MatchStats) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO malicious_flows
		(src_ip, src_port, dst_ip, dst_port, protocol, label,
		 csv_timestamp_edt, flow_duration_us,
		 flow_window_start_utc, flow_window_end_utc,
		 matched_packets, first_packet_utc, last_packet_utc)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return fmt.Errorf("准备SQL失败: %w", err)
	}
	defer stmt.Close()

	for _, f := range flows {
		s := stats[f.CSVLine]
		var firstUTC, lastUTC *string
		if s.FirstPacketUTC != nil {
			v := s.FirstPacketUTC.Format(time.RFC3339Nano)
			firstUTC = &v
		}
		if s.LastPacketUTC != nil {
			v := s.LastPacketUTC.Format(time.RFC3339Nano)
			lastUTC = &v
		}

		_, err := stmt.Exec(
			f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol, f.Label,
			f.CSVTimestamp, f.DurationUS,
			f.StartUTC.Format(time.RFC3339Nano), f.EndUTC.Format(time.RFC3339Nano),
			s.MatchedPackets, firstUTC, lastUTC,
		)
		if err != nil {
			log.Printf("[警告] 插入行 %d 失败: %v", f.CSVLine, err)
			continue
		}
	}

	return tx.Commit()
}

// ---------- 统计工具 ----------

func formatDuration(d time.Duration) string {
	if d >= time.Minute {
		return fmt.Sprintf("%d分%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func formatBytes(b int64) string {
	if b >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	}
	if b >= 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	}
	return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
}

// ---------- Main ----------

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.SetPrefix("▶ ")

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("   CIC-IDS-2017 恶意流量提取器")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	pcapPath := "Tuesday-WorkingHours.pcap"
	csvPath := "Tuesday-WorkingHours.pcap_ISCX.csv"
	outputPcap := "malicious_output.pcap"
	dbPath := "malicious_flows.db"

	// ----- 1. 解析 CSV -----
	log.Printf("[CSV] 正在读取标签文件: %s", csvPath)

	// CIC-IDS-2017 采集于 New Brunswick 大学（加拿大），属大西洋时区
	// 7月使用 ADT (Atlantic Daylight Time) = UTC-3
	loc, err := time.LoadLocation("America/Halifax")
	if err != nil {
		log.Printf("[警告] 无法加载时区 America/Halifax，使用 UTC-3 固定偏移")
		loc = time.FixedZone("ADT", -3*60*60)
	}

	malIndex, benIndex, malFlows, csvStats, err := parseCSV(csvPath, loc)
	if err != nil {
		log.Fatalf("[错误] CSV解析失败: %v", err)
	}

	totalCSV := 0
	log.Printf("[CSV] 标签统计:")
	// 先输出 BENIGN，再输出其他
	labels := make([]string, 0, len(csvStats))
	for l := range csvStats {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	for _, l := range labels {
		cnt := csvStats[l]
		totalCSV += cnt
		if l == "BENIGN" {
			log.Printf("       %-20s %7d", "BENIGN", cnt)
		}
	}
	for _, l := range labels {
		cnt := csvStats[l]
		if l != "BENIGN" {
			log.Printf("       %-20s %7d  ← 恶意", l, cnt)
		}
	}
	log.Printf("       %-20s %7d", "合计", totalCSV)
	// 计算时区偏移（2017年7月 America/Halifax 是 ADT = UTC-3）
	_, offset := time.Date(2017, 7, 1, 0, 0, 0, 0, loc).Zone()
	log.Printf("[CSV] 标签时区: America/Halifax (UTC%+d)", offset/3600)
	log.Printf("[CSV] 恶意流总数: %d", len(malFlows))
	fmt.Println()

	// 统计 BENIGN 流数量
	benCount := 0
	for _, spans := range benIndex {
		benCount += len(spans)
	}
	// 去重（因为正反向都索引了，实际流数是 benCount/2 约等于）
	log.Printf("[CSV] BENIGN 流总数: ~%d (双向索引)", benCount)
	fmt.Println()

	// ----- 2. 处理 pcap -----
	pcapInfo, err := os.Stat(pcapPath)
	if err != nil {
		log.Fatalf("[错误] 无法获取pcap文件信息: %v", err)
	}
	log.Printf("[PCAP] 打开流量文件: %s (%s)", pcapPath, formatBytes(pcapInfo.Size()))
	log.Printf("[PCAP] 内存模式: 流式处理（不预加载）")
	fmt.Println()

	// ----- 3. 初始化数据库 -----
	log.Printf("[DB] 初始化数据库: %s", dbPath)
	db, err := initDB(dbPath)
	if err != nil {
		log.Fatalf("[错误] 数据库初始化失败: %v", err)
	}
	defer db.Close()
	log.Printf("[DB] 表已重建: malicious_flows")
	fmt.Println()

	// ----- 4. 处理 -----
	startTime := time.Now()
	totalPackets, matchedPackets, flowMatches, err := processPcap(
		pcapPath, outputPcap, malIndex, benIndex, malFlows,
	)
	if err != nil {
		log.Fatalf("[错误] pcap处理失败: %v", err)
	}
	elapsed := time.Since(startTime)

	fmt.Println()
	log.Printf("[完成] 处理完成! 耗时: %s", formatDuration(elapsed))

	// ----- 5. 写入数据库 -----
	log.Printf("[DB] 正在写入结果到数据库...")
	err = writeResults(db, malFlows, flowMatches)
	if err != nil {
		log.Fatalf("[错误] 写入数据库失败: %v", err)
	}

	// ----- 6. 输出统计 -----
	outInfo, _ := os.Stat(outputPcap)
	matchedFlowCount := countMatchedFlows(flowMatches)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("   处理统计")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("   %-24s %12d\n", "总数据包", totalPackets)
	fmt.Printf("   %-24s %12d\n", "CSV恶意流总数", len(malFlows))
	fmt.Printf("   %-24s %12d  (命中率 %.1f%%)\n",
		"命中恶意流", matchedFlowCount,
		float64(matchedFlowCount)/float64(len(malFlows))*100)
	fmt.Printf("   %-24s %12d  (占总包 %.2f%%)\n",
		"提取恶意包", matchedPackets,
		float64(matchedPackets)/float64(totalPackets)*100)
	fmt.Printf("   %-24s %12s\n", "输出pcap大小", formatBytes(outInfo.Size()))
	fmt.Printf("   %-24s %12s\n", "处理速率", formatHumanRate(totalPackets, elapsed))
	fmt.Println()

	// 未命中的流统计
	zeroHit := 0
	for _, s := range flowMatches {
		if s.MatchedPackets == 0 {
			zeroHit++
		}
	}
	if zeroHit > 0 {
		log.Printf("[注意] 有 %d 个恶意流未匹配到任何数据包（CSV 时间精度不足或 pcap 中无对应流量）", zeroHit)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("   输出文件")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("   %-24s %s\n", "恶意流量 pcap:", outputPcap)
	fmt.Printf("   %-24s %s\n", "恶意流数据库:", dbPath)
	fmt.Println()
	fmt.Println("数据库表: malicious_flows")
	fmt.Println("  ────────────")
	fmt.Println("  src_ip, src_port, dst_ip, dst_port, protocol  ← 5元组")
	fmt.Println("  label                                         ← 攻击类型")
	fmt.Println("  matched_packets                               ← 匹配包数(=0表示漏报)")
	fmt.Println("  first/last_packet_utc                         ← 时间范围")
	fmt.Println("  csv_timestamp_edt, flow_duration_us           ← CSV原始信息")
	fmt.Println()
	log.Printf("[提示] 可用于 Snort 漏报率统计：")
	log.Printf("       1. snort -r malicious_output.pcap -c /path/to/snort.lua")
	log.Printf("       2. 比对告警与数据库中的流，matched_packets>0 且无告警 = 漏报")
}

func formatHumanRate(packets int64, elapsed time.Duration) string {
	rate := float64(packets) / elapsed.Seconds()
	if rate >= 1000000 {
		return fmt.Sprintf("%.2fM pkt/s", rate/1000000)
	}
	if rate >= 1000 {
		return fmt.Sprintf("%.0fK pkt/s", rate/1000)
	}
	return fmt.Sprintf("%.0f pkt/s", rate)
}
