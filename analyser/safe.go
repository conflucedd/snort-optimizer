package analyser

import (
	"context"
	"database/sql"
	"fmt"
)

func SafeSourceFileBrowser(ctx context.Context, input FunctionInput) ([]TrimDecision, error) {
	conn, err := sql.Open("sqlite", input.ExpDBPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.QueryContext(ctx, `SELECT gid, sid, rev, COALESCE(source_file, ''), COALESCE(msg, '')
FROM rules
WHERE run_id = ? AND enabled = 1
  AND (
    lower(source_file) LIKE '%browser%'
    OR lower(source_file) LIKE 'snort3-file-%'
    OR lower(source_file) LIKE '%/snort3-file-%'
    OR lower(source_file) LIKE '%\snort3-file-%'
  )
ORDER BY gid, sid;`, input.SourceRunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrimDecision
	for rows.Next() {
		var d TrimDecision
		if err := rows.Scan(&d.GID, &d.SID, &d.Rev, &d.SourceFile, &d.Msg); err != nil {
			return nil, err
		}
		d.Reason = fmt.Sprintf("source_file %q is in file/browser rule category", d.SourceFile)
		out = append(out, d)
	}
	return out, rows.Err()
}
