package alerts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	commontypes "snort-optimizer/types"
	"snort-optimizer/wrap2/sqliteutil"
)

func DBPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "alerts.db")
}

func AlertJSONPath(snortWorkingDir string) string {
	return filepath.Join(snortWorkingDir, "alert_json.txt")
}

func EnsureDB(snortWorkingDir string) error {
	if err := os.MkdirAll(snortWorkingDir, 0755); err != nil {
		return fmt.Errorf("create snort working dir: %w", err)
	}
	schema := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS alerts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp TEXT,
	pkt_num INTEGER,
	proto TEXT,
	pkt_gen TEXT,
	pkt_len INTEGER,
	dir TEXT,
	src_ap TEXT,
	dst_ap TEXT,
	gid INTEGER,
	sid INTEGER,
	rev INTEGER,
	rule TEXT,
	action TEXT,
	raw_json TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts (sid);
`
	return sqliteutil.RunScript(DBPath(snortWorkingDir), []byte(schema))
}

func Insert(snortWorkingDir string, alert commontypes.Alert) error {
	if err := EnsureDB(snortWorkingDir); err != nil {
		return err
	}
	if alert.CreatedAt == "" {
		alert.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	sql := fmt.Sprintf(`INSERT INTO alerts (timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, gid, sid, rev, rule, action, raw_json, created_at)
VALUES (%s, %d, %s, %s, %d, %s, %s, %s, %d, %d, %d, %s, %s, %s, %s);`,
		sqliteutil.Quote(alert.Timestamp),
		alert.PktNum,
		sqliteutil.Quote(alert.Proto),
		sqliteutil.Quote(alert.PktGen),
		alert.PktLen,
		sqliteutil.Quote(alert.Dir),
		sqliteutil.Quote(alert.SrcAP),
		sqliteutil.Quote(alert.DstAP),
		alert.GID,
		alert.SID,
		alert.Rev,
		sqliteutil.Quote(alert.Rule),
		sqliteutil.Quote(alert.Action),
		sqliteutil.Quote(alert.RawJSON),
		sqliteutil.Quote(alert.CreatedAt),
	)
	return sqliteutil.RunScript(DBPath(snortWorkingDir), []byte(sql))
}

type rawAlert struct {
	Timestamp string `json:"timestamp"`
	PktNum    int64  `json:"pkt_num"`
	Proto     string `json:"proto"`
	PktGen    string `json:"pkt_gen"`
	PktLen    int64  `json:"pkt_len"`
	Dir       string `json:"dir"`
	SrcAP     string `json:"src_ap"`
	DstAP     string `json:"dst_ap"`
	Rule      string `json:"rule"`
	Action    string `json:"action"`
}

func ParseLine(line string) (commontypes.Alert, error) {
	rawJSON := strings.TrimSpace(line)
	var raw rawAlert
	if err := json.Unmarshal([]byte(rawJSON), &raw); err != nil {
		return commontypes.Alert{}, err
	}
	gid, sid, rev := parseRuleID(raw.Rule)
	return commontypes.Alert{
		Timestamp: raw.Timestamp,
		PktNum:    raw.PktNum,
		Proto:     raw.Proto,
		PktGen:    raw.PktGen,
		PktLen:    raw.PktLen,
		Dir:       raw.Dir,
		SrcAP:     raw.SrcAP,
		DstAP:     raw.DstAP,
		GID:       gid,
		SID:       sid,
		Rev:       rev,
		Rule:      raw.Rule,
		Action:    raw.Action,
		RawJSON:   rawJSON,
	}, nil
}

func ImportFile(snortWorkingDir string, logger *log.Logger) error {
	if err := EnsureDB(snortWorkingDir); err != nil {
		return err
	}
	path := AlertJSONPath(snortWorkingDir)
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open alert json: %w", err)
	}
	defer file.Close()
	return importLines(file, snortWorkingDir, logger)
}

func TailToDB(ctx context.Context, snortWorkingDir string, logger *log.Logger) error {
	if err := EnsureDB(snortWorkingDir); err != nil {
		return err
	}

	path := AlertJSONPath(snortWorkingDir)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	var file *os.File
	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	for file == nil {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			opened, err := os.Open(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				logger.Printf("open alert json failed: %v", err)
				continue
			}
			file = opened
		}
	}

	var offset int64
	for {
		select {
		case <-ctx.Done():
			if err := readFromOffset(file, &offset, snortWorkingDir, logger); err != nil {
				logger.Printf("final alert import failed: %v", err)
			}
			return nil
		case <-ticker.C:
			if err := readFromOffset(file, &offset, snortWorkingDir, logger); err != nil {
				logger.Printf("tail alert json failed: %v", err)
			}
		}
	}
}

func readFromOffset(file *os.File, offset *int64, snortWorkingDir string, logger *log.Logger) error {
	stat, err := file.Stat()
	if err != nil {
		return err
	}
	if stat.Size() <= *offset {
		return nil
	}
	if _, err := file.Seek(*offset, io.SeekStart); err != nil {
		return err
	}
	counting := &countingReader{Reader: file}
	if err := importLines(counting, snortWorkingDir, logger); err != nil {
		return err
	}
	*offset += counting.N
	return nil
}

func importLines(reader io.Reader, snortWorkingDir string, logger *log.Logger) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	batch := make([]commontypes.Alert, 0, 128)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := InsertBatch(snortWorkingDir, batch); err != nil {
			logger.Printf("insert alert batch failed: %v", err)
		}
		batch = batch[:0]
	}
	for scanner.Scan() {
		alert, err := ParseLine(scanner.Text())
		if err != nil {
			logger.Printf("skip invalid alert json line: %v", err)
			continue
		}
		batch = append(batch, alert)
		if len(batch) >= 128 {
			flush()
		}
	}
	flush()
	return scanner.Err()
}

type countingReader struct {
	Reader io.Reader
	N      int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.N += int64(n)
	return n, err
}

func parseRuleID(rule string) (int64, int64, int64) {
	parts := strings.Split(rule, ":")
	if len(parts) != 3 {
		return 0, 0, 0
	}
	gid, _ := strconv.ParseInt(parts[0], 10, 64)
	sid, _ := strconv.ParseInt(parts[1], 10, 64)
	rev, _ := strconv.ParseInt(parts[2], 10, 64)
	return gid, sid, rev
}

func InsertBatch(snortWorkingDir string, batch []commontypes.Alert) error {
	if len(batch) == 0 {
		return nil
	}
	if err := EnsureDB(snortWorkingDir); err != nil {
		return err
	}
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, alert := range batch {
		if alert.CreatedAt == "" {
			alert.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		fmt.Fprintf(&script, `INSERT INTO alerts (timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, gid, sid, rev, rule, action, raw_json, created_at)
VALUES (%s, %d, %s, %s, %d, %s, %s, %s, %d, %d, %d, %s, %s, %s, %s);
`,
			sqliteutil.Quote(alert.Timestamp), alert.PktNum, sqliteutil.Quote(alert.Proto),
			sqliteutil.Quote(alert.PktGen), alert.PktLen, sqliteutil.Quote(alert.Dir),
			sqliteutil.Quote(alert.SrcAP), sqliteutil.Quote(alert.DstAP), alert.GID,
			alert.SID, alert.Rev, sqliteutil.Quote(alert.Rule), sqliteutil.Quote(alert.Action),
			sqliteutil.Quote(alert.RawJSON), sqliteutil.Quote(alert.CreatedAt))
	}
	script.WriteString("COMMIT;\n")
	return sqliteutil.RunScript(DBPath(snortWorkingDir), script.Bytes())
}
