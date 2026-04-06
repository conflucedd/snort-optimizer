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
		log.Fatal("用法: ./count_re file.csv --cols \"col1,col2\"")
	}

	filename := os.Args[1]

	var colsStr string
	for i := 2; i < len(os.Args)-1; i++ {
		if os.Args[i] == "--cols" {
			colsStr = os.Args[i+1]
			break
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

	seen := make(map[string]int)

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
			values = append(values, row[idx])
		}

		key := strings.Join(values, ",")
		seen[key]++

		if seen[key] > 1 {
			fmt.Println(key)
		}
	}
}
