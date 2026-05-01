package sql

import (
	dbsql "database/sql"
	"fmt"
	"time"

	atypes "snort-optimizer/analyser/types"
	sqlstore "snort-optimizer/sql"
)

func CloneRulesForRun(dbPaths []string, fromRunID, toRunID int64, decisions []atypes.TrimmedRule) error {
	for _, dbPath := range dbPaths {
		if err := CloneRulesInDB(dbPath, fromRunID, toRunID, decisions); err != nil {
			return fmt.Errorf("%s clone rules: %w", dbPath, err)
		}
	}
	return nil
}

func CloneRulesInDB(dbPath string, fromRunID, toRunID int64, decisions []atypes.TrimmedRule) error {
	if err := sqlstore.EnsureRules(sqlstore.Config{DBPath: dbPath, RunID: toRunID}); err != nil {
		return err
	}
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM rules WHERE run_id = ?;", toRunID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO rules
(run_id, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, created_at)
SELECT ?, sid, gid, rev, action, proto, src_net, src_port, direction, dst_net, dst_port, msg, classtype, enabled, source_file, raw_text, ?
FROM rules WHERE run_id = ?;`, toRunID, time.Now().UTC().Format(time.RFC3339Nano), fromRunID); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare("UPDATE rules SET enabled = 0 WHERE run_id = ? AND gid = ? AND sid = ?;")
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, d := range decisions {
		if _, err := stmt.Exec(toRunID, d.GID, d.SID); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
