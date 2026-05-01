package sql

import dbsql "database/sql"

func loadEvalAlerts(dbPath string, runID int64) ([]AlertForEval, error) {
	conn, err := dbsql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	rows, err := conn.Query(`SELECT id, timestamp, proto, src_ap, dst_ap, gid, sid, rev FROM alerts WHERE run_id = ? ORDER BY id;`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AlertForEval
	for rows.Next() {
		var a AlertForEval
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.Proto, &a.SrcAP, &a.DstAP, &a.GID, &a.SID, &a.Rev); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
