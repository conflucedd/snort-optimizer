package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 4 {
		log.Fatal(`用法: ./count_re file.csv --cols "col1,col2" [--warn-col "col3"]`)
	}

	filename := os.Args[1]

	var colsStr string
	var warnCol string

	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--cols" && i+1 < len(os.Args) {
			colsStr = os.Args[i+1]
			i++
			continue
		}
		if os.Args[i] == "--warn-col" && i+1 < len(os.Args) {
			warnCol = os.Args[i+1]
			i++
			continue
		}
	}

	if colsStr == "" {
		log.Fatal("请使用 --cols 指定列名")
	}

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	header, err := reader.Read()
	if err != nil {
		log.Fatal(err)
	}

	colMap := make(map[string]int)
	for i, name := range header {
		colMap[strings.TrimSpace(name)] = i
	}

	colNames := strings.Split(colsStr, ",")
	colIndexes := make([]int, 0, len(colNames))

	for _, name := range colNames {
		name = strings.TrimSpace(name)
		idx, ok := colMap[name]
		if !ok {
			log.Fatalf("找不到列名: %s", name)
		}
		colIndexes = append(colIndexes, idx)
	}

	warnIdx := -1
	if warnCol != "" {
		var ok bool
		warnIdx, ok = colMap[strings.TrimSpace(warnCol)]
		if !ok {
			log.Fatalf("找不到警告列名: %s", warnCol)
		}
	}

	seen := make(map[string]int)
	firstWarnValue := make(map[string]string)
	warned := make(map[string]bool)

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		values := make([]string, 0, len(colIndexes))
		for _, idx := range colIndexes {
			if idx >= len(row) {
				log.Fatalf("行字段数不足，无法读取列 %d: %v", idx, row)
			}
			values = append(values, row[idx])
		}

		key := strings.Join(values, ",")
		seen[key]++

		if seen[key] > 1 {
			fmt.Println(key)
		}

		if warnIdx >= 0 {
			if warnIdx >= len(row) {
				log.Fatalf("行字段数不足，无法读取警告列 %d: %v", warnIdx, row)
			}

			curWarnValue := row[warnIdx]

			if old, ok := firstWarnValue[key]; !ok {
				firstWarnValue[key] = curWarnValue
			} else if old != curWarnValue && !warned[key] {
				fmt.Printf("重大警告: 重复键 [%s] 的列 [%s] 出现不同值: [%s] vs [%s]\n",
					key, warnCol, old, curWarnValue)
				warned[key] = true
			}
		}
	}
}
