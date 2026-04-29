package alerts

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
	"snort-optimizer/sql/schema"
	"snort-optimizer/types"
)

type Query struct {
	Limit  int
	RunID  int64
	SID    int64
	Proto  string
	Action string
	SrcAP  string
	DstAP  string
}

type Tailer struct {
	cfg    config.Config
	logger *log.Logger
	file   *os.File
	offset int64
}

func InsertBatch(cfg config.Config, batch []types.Alert) error {
	if len(batch) == 0 {
		return nil
	}
	if err := schema.Ensure(cfg); err != nil {
		return err
	}
	var script bytes.Buffer
	now := time.Now().UTC().Format(time.RFC3339Nano)
	script.WriteString("BEGIN;\n")
	for _, a := range batch {
		if a.CreatedAt == "" {
			a.CreatedAt = now
		}
		fmt.Fprintf(&script, `INSERT INTO alerts (run_id, timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, gid, sid, rev, rule, action, raw_json, source_file, created_at)
VALUES (%d, %s, %d, %s, %s, %d, %s, %s, %s, %d, %d, %d, %s, %s, %s, %s, %s);
`,
			cfg.RunID, db.Quote(a.Timestamp), a.PktNum, db.Quote(a.Proto), db.Quote(a.PktGen), a.PktLen,
			db.Quote(a.Dir), db.Quote(a.SrcAP), db.Quote(a.DstAP), a.GID, a.SID, a.Rev,
			db.Quote(a.Rule), db.Quote(a.Action), db.Quote(a.RawJSON), db.Quote(cfg.AlertPath), db.Quote(a.CreatedAt),
		)
	}
	script.WriteString("COMMIT;\n")
	return db.RunScript(cfg.DBPath, script.Bytes())
}

func ImportFile(cfg config.Config, logger *log.Logger) (int, error) {
	if err := schema.Ensure(cfg); err != nil {
		return 0, err
	}
	file, err := os.Open(cfg.AlertPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open alert file: %w", err)
	}
	defer file.Close()
	return importLines(cfg, file, logger)
}

func TailFile(ctx context.Context, cfg config.Config, logger *log.Logger) error {
	tailer, err := NewTailer(cfg, logger, false)
	if err != nil {
		return err
	}
	return tailer.Tail(ctx)
}

func NewTailer(cfg config.Config, logger *log.Logger, startExistingAtEnd bool) (*Tailer, error) {
	cfg = cfg.WithDefaults()
	if err := schema.Ensure(cfg); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	tailer := &Tailer{cfg: cfg, logger: logger}
	file, err := os.Open(cfg.AlertPath)
	if os.IsNotExist(err) {
		return tailer, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open alert file: %w", err)
	}
	tailer.file = file
	if startExistingAtEnd {
		stat, err := file.Stat()
		if err != nil {
			file.Close()
			return nil, err
		}
		tailer.offset = stat.Size()
	}
	return tailer, nil
}

func (t *Tailer) Tail(ctx context.Context) error {
	ticker := time.NewTicker(t.cfg.TailInterval)
	defer ticker.Stop()
	defer t.Close()
	for t.file == nil {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			opened, err := os.Open(t.cfg.AlertPath)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				t.logger.Printf("open alert file failed: %v", err)
				continue
			}
			t.file = opened
		}
	}
	for {
		select {
		case <-ctx.Done():
			_, _ = t.readAvailable(true)
			return nil
		case <-ticker.C:
			if _, err := t.readAvailable(false); err != nil {
				t.logger.Printf("tail alert file failed: %v", err)
			}
		}
	}
}

func (t *Tailer) Close() error {
	if t.file == nil {
		return nil
	}
	err := t.file.Close()
	t.file = nil
	return err
}

func List(cfg config.Config, q Query) ([]types.Alert, error) {
	where := []string{"1=1"}
	where = append(where, fmt.Sprintf("run_id = %d", q.RunID))
	if q.SID > 0 {
		where = append(where, fmt.Sprintf("sid = %d", q.SID))
	}
	if q.Proto != "" {
		where = append(where, "proto = "+db.Quote(q.Proto))
	}
	if q.Action != "" {
		where = append(where, "action = "+db.Quote(q.Action))
	}
	if q.SrcAP != "" {
		where = append(where, "src_ap LIKE "+db.Like(q.SrcAP))
	}
	if q.DstAP != "" {
		where = append(where, "dst_ap LIKE "+db.Like(q.DstAP))
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	sql := fmt.Sprintf(`SELECT id,run_id,timestamp,pkt_num,proto,pkt_gen,pkt_len,dir,src_ap,dst_ap,gid,sid,rev,rule,action,raw_json,created_at FROM alerts WHERE %s ORDER BY id DESC LIMIT %d;`, strings.Join(where, " AND "), limit)
	rows, err := db.QueryJSON(cfg.DBPath, sql)
	if err != nil {
		return nil, err
	}
	out := make([]types.Alert, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToAlert(row))
	}
	return out, nil
}

func (t *Tailer) readAvailable(final bool) (int, error) {
	stat, err := t.file.Stat()
	if err != nil {
		return 0, err
	}
	if stat.Size() < t.offset {
		t.offset = 0
	}
	if stat.Size() <= t.offset {
		return 0, nil
	}
	if _, err := t.file.Seek(t.offset, io.SeekStart); err != nil {
		return 0, err
	}
	buf, err := io.ReadAll(io.LimitReader(t.file, stat.Size()-t.offset))
	if err != nil {
		return 0, err
	}
	lastNewline := bytes.LastIndexByte(buf, '\n')
	if lastNewline < 0 {
		if !final {
			return 0, nil
		}
		lastNewline = len(buf) - 1
	}
	complete := buf[:lastNewline+1]
	if final {
		complete = buf
	}
	n, err := importLineBytes(t.cfg, complete, t.logger)
	if err != nil {
		return n, err
	}
	t.offset += int64(len(complete))
	return n, nil
}

func importLineBytes(cfg config.Config, data []byte, logger *log.Logger) (int, error) {
	return importLines(cfg, bytes.NewReader(data), logger)
}

func importLines(cfg config.Config, reader io.Reader, logger *log.Logger) (int, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	batch := make([]types.Alert, 0, 256)
	imported := 0
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := InsertBatch(cfg, batch); err != nil {
			logger.Printf("insert alert batch failed: %v", err)
			return
		}
		imported += len(batch)
		batch = batch[:0]
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		alert, err := ParseLine(line)
		if err != nil {
			logger.Printf("skip invalid alert json line: %v", err)
			continue
		}
		batch = append(batch, alert)
		if len(batch) >= 256 {
			flush()
		}
	}
	flush()
	return imported, scanner.Err()
}

func rowToAlert(row map[string]any) types.Alert {
	return types.Alert{
		ID:        asInt(row["id"]),
		RunID:     asInt(row["run_id"]),
		Timestamp: asString(row["timestamp"]),
		PktNum:    asInt(row["pkt_num"]),
		Proto:     asString(row["proto"]),
		PktGen:    asString(row["pkt_gen"]),
		PktLen:    asInt(row["pkt_len"]),
		Dir:       asString(row["dir"]),
		SrcAP:     asString(row["src_ap"]),
		DstAP:     asString(row["dst_ap"]),
		GID:       asInt(row["gid"]),
		SID:       asInt(row["sid"]),
		Rev:       asInt(row["rev"]),
		Rule:      asString(row["rule"]),
		Action:    asString(row["action"]),
		RawJSON:   asString(row["raw_json"]),
		CreatedAt: asString(row["created_at"]),
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	default:
		return 0
	}
}
