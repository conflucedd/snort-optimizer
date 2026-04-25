package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
)

type lineInfo struct {
	lineNum int
	record  []string
}

type duplicateGroup struct {
	timestamp string
	quad      string
	count     int
	infos     []lineInfo
}

// 用于按重复次数排序
type byCount []duplicateGroup

func (a byCount) Len() int           { return len(a) }
func (a byCount) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byCount) Less(i, j int) bool { return a[i].count > a[j].count } // 降序

// 生成规范化流标识（不考虑方向）
// 如果 srcIP < dstIP，使用 srcIP:srcPort->dstIP:dstPort/protocol
// 否则使用 dstIP:dstPort->srcIP:srcPort/protocol
func normalizedFlow(srcIP, srcPort, dstIP, dstPort, protocol string) string {
	if srcIP < dstIP {
		return fmt.Sprintf("%s:%s->%s:%s/%s", srcIP, srcPort, dstIP, dstPort, protocol)
	} else if srcIP > dstIP {
		return fmt.Sprintf("%s:%s->%s:%s/%s", dstIP, dstPort, srcIP, srcPort, protocol)
	} else {
		// IP相同，比较端口
		if srcPort < dstPort {
			return fmt.Sprintf("%s:%s->%s:%s/%s", srcIP, srcPort, dstIP, dstPort, protocol)
		} else {
			return fmt.Sprintf("%s:%s->%s:%s/%s", dstIP, dstPort, srcIP, srcPort, protocol)
		}
	}
}

func main() {
	filename := "Thursday.csv"
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file %s: %v\n", filename, err)
		os.Exit(1)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1 // allow variable fields
	reader.LazyQuotes = true

	// read header
	headers, err := reader.Read()
	if err != nil {
		fmt.Printf("Error reading header: %v\n", err)
		os.Exit(1)
	}

	// find column indices
	srcIPIdx, srcPortIdx, dstIPIdx, dstPortIdx, protoIdx, tsIdx := -1, -1, -1, -1, -1, -1
	for i, h := range headers {
		h = strings.TrimSpace(h)
		switch h {
		case "Source IP":
			srcIPIdx = i
		case "Source Port":
			srcPortIdx = i
		case "Destination IP":
			dstIPIdx = i
		case "Destination Port":
			dstPortIdx = i
		case "Protocol":
			protoIdx = i
		case "Timestamp":
			tsIdx = i
		}
	}
	if srcIPIdx == -1 || srcPortIdx == -1 || dstIPIdx == -1 || dstPortIdx == -1 || protoIdx == -1 || tsIdx == -1 {
		fmt.Println("Required columns not found")
		os.Exit(1)
	}

	fmt.Printf("Using columns: Source IP=%d, Source Port=%d, Destination IP=%d, Destination Port=%d, Protocol=%d, Timestamp=%d\n",
		srcIPIdx, srcPortIdx, dstIPIdx, dstPortIdx, protoIdx, tsIdx)

	// map[timestamp]map[quadruplet][]lineInfo
	groups := make(map[string]map[string][]lineInfo)

	lineNum := 1 // header line number
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("Error reading line %d: %v\n", lineNum, err)
			continue
		}
		lineNum++

		timestamp := strings.TrimSpace(record[tsIdx])
		srcIP := strings.TrimSpace(record[srcIPIdx])
		srcPort := strings.TrimSpace(record[srcPortIdx])
		dstIP := strings.TrimSpace(record[dstIPIdx])
		dstPort := strings.TrimSpace(record[dstPortIdx])
		protocol := strings.TrimSpace(record[protoIdx])

		// 跳过关键字段为空的行
		if timestamp == "" || srcIP == "" || srcPort == "" || dstIP == "" || dstPort == "" || protocol == "" {
			continue
		}

		// 五元组: 源IP:端口->目的IP:端口/协议
		quad := fmt.Sprintf("%s:%s->%s:%s/%s", srcIP, srcPort, dstIP, dstPort, protocol)

		if groups[timestamp] == nil {
			groups[timestamp] = make(map[string][]lineInfo)
		}
		groups[timestamp][quad] = append(groups[timestamp][quad], lineInfo{lineNum, record})
	}

	// collect duplicate groups
	var dupGroups []duplicateGroup
	totalDuplicates := 0

	for timestamp, quadMap := range groups {
		for quad, infos := range quadMap {
			if len(infos) > 1 {
				totalDuplicates++
				dupGroups = append(dupGroups, duplicateGroup{
					timestamp: timestamp,
					quad:      quad,
					count:     len(infos),
					infos:     infos,
				})
			}
		}
	}

	// sort by count (descending)
	sort.Sort(byCount(dupGroups))

	// output sorted duplicates
	for _, group := range dupGroups {
		fmt.Printf("\n%s=== 重复时间戳: %s 五元组: %s (共%d次) ===%s\n",
			colorYellow, group.timestamp, group.quad, group.count, colorReset)
		for i, info := range group.infos {
			color := colorGreen
			if i > 0 {
				color = colorRed
			}
			fmt.Printf("%s[重复 %d 行号:%d]%s ", color, i+1, info.lineNum, colorReset)
			// print key fields
			rec := info.record
			fmt.Printf("Flow ID: %s, Timestamp: %s, Src: %s:%s, Dst: %s:%s, Proto: %s\n",
				rec[0], rec[tsIdx], rec[srcIPIdx], rec[srcPortIdx], rec[dstIPIdx], rec[dstPortIdx], rec[protoIdx])
		}
		fmt.Printf("%s%s%s\n", colorBlue, strings.Repeat("-", 80), colorReset)
	}

	if totalDuplicates == 0 {
		fmt.Println("未发现重复五元组（相同时间戳下）")
	} else {
		fmt.Printf("\n%s总共发现 %d 组重复五元组%s\n", colorCyan, totalDuplicates, colorReset)
		// 输出重复次数统计摘要
		fmt.Printf("%s重复次数统计 (从高到低):%s\n", colorPurple, colorReset)
		for i, group := range dupGroups {
			if i >= 20 { // 只显示前20个
				fmt.Printf("%s... 还有 %d 组 ...%s\n", colorCyan, len(dupGroups)-20, colorReset)
				break
			}
			fmt.Printf("  %d. %s (时间戳: %s) - 重复 %d 次\n",
				i+1, group.quad, group.timestamp, group.count)
		}
	}
}