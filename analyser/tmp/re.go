package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	input := flag.String("input", "", "input file path")
	flag.Parse()

	if *input == "" {
		log.Fatal("please use -input to specify file")
	}

	file, err := os.Open(*input)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	counts := make(map[string]int)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		counts[line]++

		// 第二次出现时立刻输出
		if counts[line] == 2 {
			fmt.Printf("重复行: %s\n", line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
