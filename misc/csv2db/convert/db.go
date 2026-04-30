package convert

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

func WriteDB(dbPath string, data *CSVData) error {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := createTable(db, data.TableName, data.Columns); err != nil {
		return err
	}
	if err := insertRows(db, data.TableName, data.Columns, data.Rows); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Done: %d rows inserted into table %q\n", len(data.Rows), data.TableName)
	return nil
}

func createTable(db *sql.DB, tableName string, cols []ColumnInfo) error {
	defs := make([]string, len(cols))
	for i, c := range cols {
		defs[i] = fmt.Sprintf(`"%s" %s`, strings.ReplaceAll(c.Name, `"`, `""`), colTypeSQL(c.Type))
	}
	ddl := fmt.Sprintf(`CREATE TABLE "%s" (%s);`, tableName, strings.Join(defs, ", "))
	_, err := db.Exec(ddl)
	return err
}

func insertRows(db *sql.DB, tableName string, cols []ColumnInfo, rows [][]string) error {
	placeholders := make([]string, len(cols))
	quoted := make([]string, len(cols))
	for i, c := range cols {
		placeholders[i] = "?"
		quoted[i] = fmt.Sprintf(`"%s"`, strings.ReplaceAll(c.Name, `"`, `""`))
	}

	stmt := fmt.Sprintf(`INSERT INTO "%s" (%s) VALUES (%s);`,
		tableName, strings.Join(quoted, ", "), strings.Join(placeholders, ", "))

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	prep, err := tx.Prepare(stmt)
	if err != nil {
		return err
	}
	defer prep.Close()

	for _, row := range rows {
		vals := make([]any, len(row))
		for i, v := range row {
			val, err := convertValue(v, cols[i].Type)
			if err != nil {
				return fmt.Errorf("column %q: %w", cols[i].Name, err)
			}
			vals[i] = val
		}
		if _, err := prep.Exec(vals...); err != nil {
			return fmt.Errorf("row insert failed: %w", err)
		}
	}

	return tx.Commit()
}
