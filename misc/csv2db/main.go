package main

import (
	"fmt"
	"os"

	"csv2db/convert"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: csv2db <csv> <db>\n")
		os.Exit(1)
	}

	data, err := convert.ReadCSV(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Read %d data rows with %d columns\n", len(data.Rows), len(data.Headers))

	if err := convert.WriteDB(os.Args[2], data); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}
