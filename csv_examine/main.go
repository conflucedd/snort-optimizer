package main

import (
	"database/sql"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	_ "github.com/mattn/go-sqlite3"
)

const tableName = "records"

type options struct {
	ignoreDuplicates bool
	csvPath          string
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "csv_idb:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseArgs(args)
	if err != nil {
		return err
	}

	file, err := os.Open(opts.csvPath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true

	rawHeader, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("empty csv")
		}
		return err
	}

	headers, renamed := normalizeHeaders(rawHeader)
	for _, name := range headers {
		if name == "" {
			return fmt.Errorf("csv header contains empty field name")
		}
	}
	for _, msg := range renamed {
		fmt.Fprintln(os.Stderr, "warning:", msg)
	}

	dbPath := outputDBPath(opts.csvPath)
	if err := removeDBFiles(dbPath); err != nil {
		return err
	}
	importOK := false
	defer func() {
		if !importOK {
			_ = removeDBFiles(dbPath)
		}
	}()

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := initDB(db, headers); err != nil {
		return err
	}

	insertSQL := buildInsertSQL(headers)
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()

	rowNum := 1
	imported := 0
	skippedBlank := 0
	skippedDuplicate := 0
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read row %d: %w", rowNum+1, err)
		}
		rowNum++

		if isBlankRecord(record) {
			skippedBlank++
			continue
		}
		if len(record) != len(headers) {
			return fmt.Errorf("row %d has %d fields, want %d", rowNum, len(record), len(headers))
		}

		values := make([]any, len(record))
		for i := range record {
			values[i] = record[i]
		}
		if _, err := stmt.Exec(values...); err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				if opts.ignoreDuplicates {
					skippedDuplicate++
					fmt.Fprintf(os.Stderr, "warning: row %d duplicates an earlier record, skipped\n", rowNum)
					continue
				}
				return fmt.Errorf("row %d duplicates an earlier record", rowNum)
			}
			return fmt.Errorf("insert row %d: duplicate or invalid record: %w", rowNum, err)
		}
		imported++
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	importOK = true

	fmt.Printf("created %s, table %s, imported %d rows", dbPath, tableName, imported)
	if skippedBlank > 0 {
		fmt.Printf(", skipped %d blank rows", skippedBlank)
	}
	if skippedDuplicate > 0 {
		fmt.Printf(", skipped %d duplicate rows", skippedDuplicate)
	}
	fmt.Println()
	return nil
}

func parseArgs(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&opts.ignoreDuplicates, "ignore-duplicates", false, "warn and skip duplicate records instead of failing")
	fs.BoolVar(&opts.ignoreDuplicates, "compat", false, "alias for -ignore-duplicates")
	if err := fs.Parse(args[1:]); err != nil {
		return opts, fmt.Errorf("usage: csv_idb [-ignore-duplicates|-compat] xxx.csv")
	}
	if fs.NArg() != 1 {
		return opts, fmt.Errorf("usage: csv_idb [-ignore-duplicates|-compat] xxx.csv")
	}
	opts.csvPath = fs.Arg(0)
	return opts, nil
}

func outputDBPath(csvPath string) string {
	ext := filepath.Ext(csvPath)
	if ext == "" {
		return csvPath + ".db"
	}
	return strings.TrimSuffix(csvPath, ext) + ".db"
}

func removeDBFiles(dbPath string) error {
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func normalizeHeaders(raw []string) ([]string, []string) {
	headers := make([]string, len(raw))
	seen := make(map[string]int, len(raw))
	var renamed []string
	for i, field := range raw {
		name := strings.TrimSpace(strings.TrimPrefix(field, "\ufeff"))
		seen[name]++
		if seen[name] > 1 {
			renamedName := fmt.Sprintf("%s_%d", name, seen[name])
			renamed = append(renamed, fmt.Sprintf("duplicate column %q renamed to %q", name, renamedName))
			name = renamedName
		}
		headers[i] = name
	}
	return headers, renamed
}

func isBlankRecord(record []string) bool {
	for _, field := range record {
		if strings.TrimSpace(field) != "" {
			return false
		}
	}
	return true
}

func initDB(db *sql.DB, headers []string) error {
	var b strings.Builder
	b.WriteString("CREATE TABLE ")
	b.WriteString(quoteIdentifier(tableName))
	b.WriteString(" (")
	for i, header := range headers {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(quoteIdentifier(header))
		b.WriteString(" TEXT")
	}
	b.WriteString(");")
	if _, err := db.Exec(b.String()); err != nil {
		return err
	}

	var idx strings.Builder
	idx.WriteString("CREATE UNIQUE INDEX ")
	idx.WriteString(quoteIdentifier("records_unique_all_columns"))
	idx.WriteString(" ON ")
	idx.WriteString(quoteIdentifier(tableName))
	idx.WriteString(" (")
	for i, header := range headers {
		if i > 0 {
			idx.WriteString(", ")
		}
		idx.WriteString(quoteIdentifier(header))
	}
	idx.WriteString(");")
	_, err := db.Exec(idx.String())
	return err
}

func buildInsertSQL(headers []string) string {
	var b strings.Builder
	b.WriteString("INSERT INTO ")
	b.WriteString(quoteIdentifier(tableName))
	b.WriteString(" (")
	for i, header := range headers {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(quoteIdentifier(header))
	}
	b.WriteString(") VALUES (")
	for i := range headers {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("?")
	}
	b.WriteString(");")
	return b.String()
}

func quoteIdentifier(s string) string {
	var b strings.Builder
	b.Grow(len(s) + utf8.RuneCountInString(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		if r == '"' {
			b.WriteByte('"')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}
