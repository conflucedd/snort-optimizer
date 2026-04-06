package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AlertEvent struct {
	ID             int64  `json:"id,omitempty"`
	SnortTimestamp string `json:"snort_timestamp"`
	PktNum         int    `json:"pkt_num"`
	Proto          string `json:"proto"`
	PktGen         string `json:"pkt_gen"`
	PktLen         int    `json:"pkt_len"`
	Dir            string `json:"dir"`
	SrcAP          string `json:"src_ap"`
	DstAP          string `json:"dst_ap"`
	Rule           string `json:"rule"`
	Action         string `json:"action"`
	RawJSON        string `json:"raw_json,omitempty"`
	GID            int    `json:"gid,omitempty"`
	SID            int    `json:"sid,omitempty"`
	Rev            int    `json:"rev,omitempty"`
}

type AlertStore struct {
	dbPath string
	logger *log.Logger

	inputCh chan AlertEvent
	doneCh  chan struct{}
	once    sync.Once
}

func NewAlertStore(dbPath string, logger *log.Logger) *AlertStore {
	return &AlertStore{
		dbPath:  dbPath,
		logger:  logger,
		inputCh: make(chan AlertEvent, 2048),
		doneCh:  make(chan struct{}),
	}
}

func (s *AlertStore) Init() error {
	if err := os.MkdirAll(filepath.Dir(s.dbPath), 0755); err != nil {
		return fmt.Errorf("create alert db dir: %w", err)
	}

	schema := `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snort_timestamp TEXT,
    pkt_num INTEGER,
    proto TEXT,
    pkt_gen TEXT,
    pkt_len INTEGER,
    dir TEXT,
    src_ap TEXT,
    dst_ap TEXT,
    rule TEXT,
    action TEXT,
    gid INTEGER,
    sid INTEGER,
    rev INTEGER,
    raw_json TEXT,
    ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_alerts_ingested_at ON alerts (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts (sid);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule);
`
	if err := RunSQLiteScript(s.dbPath, []byte(schema)); err != nil {
		return fmt.Errorf("init alert db: %w", err)
	}

	go s.writer()
	return nil
}

func (s *AlertStore) Insert(alert AlertEvent) {
	select {
	case s.inputCh <- alert:
	default:
		s.logger.Printf("dropping alert because insert queue is full")
	}
}

func (s *AlertStore) Close() {
	s.once.Do(func() {
		close(s.inputCh)
		<-s.doneCh
	})
}

func (s *AlertStore) writer() {
	defer close(s.doneCh)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]AlertEvent, 0, 128)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.flushBatch(batch); err != nil {
			s.logger.Printf("flush alert batch failed: %v", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case alert, ok := <-s.inputCh:
			if !ok {
				flush()
				return
			}
			batch = append(batch, alert)
			if len(batch) >= 128 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (s *AlertStore) flushBatch(batch []AlertEvent) error {
	var script bytes.Buffer
	script.WriteString("BEGIN;\n")
	for _, alert := range batch {
		fmt.Fprintf(&script, "INSERT INTO alerts (snort_timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, rule, action, gid, sid, rev, raw_json) VALUES (%s, %d, %s, %s, %d, %s, %s, %s, %s, %s, %d, %d, %d, %s);\n",
			SQLQuote(alert.SnortTimestamp),
			alert.PktNum,
			SQLQuote(alert.Proto),
			SQLQuote(alert.PktGen),
			alert.PktLen,
			SQLQuote(alert.Dir),
			SQLQuote(alert.SrcAP),
			SQLQuote(alert.DstAP),
			SQLQuote(alert.Rule),
			SQLQuote(alert.Action),
			alert.GID,
			alert.SID,
			alert.Rev,
			SQLQuote(alert.RawJSON),
		)
	}
	script.WriteString("COMMIT;\n")
	return RunSQLiteScript(s.dbPath, script.Bytes())
}

type AlertQuery struct {
	Limit    int
	Offset   int
	BeforeID int64
	SID      int
	Action   string
	Proto    string
	Rule     string
	Src      string
	Dst      string
}

type AlertQueryResult struct {
	Total int          `json:"total"`
	Items []AlertEvent `json:"items"`
}

type AlertSummary struct {
	Total       int `json:"total"`
	LastHour    int `json:"last_hour"`
	Last24Hours int `json:"last_24_hours"`
	UniqueSIDs  int `json:"unique_sids"`
}

func (s *AlertStore) Query(query AlertQuery) (AlertQueryResult, error) {
	where := buildAlertWhere(query)
	countRows, err := QuerySQLiteJSON(s.dbPath, "SELECT COUNT(*) AS total FROM alerts "+where+";")
	if err != nil {
		return AlertQueryResult{}, err
	}

	total := 0
	if len(countRows) > 0 {
		total = toInt(countRows[0]["total"])
	}

	sql := fmt.Sprintf(`SELECT id, snort_timestamp, pkt_num, proto, pkt_gen, pkt_len, dir, src_ap, dst_ap, rule, action, gid, sid, rev, raw_json, ingested_at
FROM alerts %s
ORDER BY id DESC
LIMIT %d OFFSET %d;`, where, query.Limit, query.Offset)

	rows, err := QuerySQLiteJSON(s.dbPath, sql)
	if err != nil {
		return AlertQueryResult{}, err
	}

	items := make([]AlertEvent, 0, len(rows))
	for _, row := range rows {
		item := AlertEvent{
			ID:             int64(toInt(row["id"])),
			SnortTimestamp: toString(row["snort_timestamp"]),
			PktNum:         toInt(row["pkt_num"]),
			Proto:          toString(row["proto"]),
			PktGen:         toString(row["pkt_gen"]),
			PktLen:         toInt(row["pkt_len"]),
			Dir:            toString(row["dir"]),
			SrcAP:          toString(row["src_ap"]),
			DstAP:          toString(row["dst_ap"]),
			Rule:           toString(row["rule"]),
			Action:         toString(row["action"]),
			GID:            toInt(row["gid"]),
			SID:            toInt(row["sid"]),
			Rev:            toInt(row["rev"]),
			RawJSON:        toString(row["raw_json"]),
		}
		items = append(items, item)
	}

	return AlertQueryResult{Total: total, Items: items}, nil
}

func (s *AlertStore) Summary() (AlertSummary, error) {
	rows, err := QuerySQLiteJSON(s.dbPath, `SELECT
COUNT(*) AS total,
SUM(CASE WHEN datetime(ingested_at) >= datetime('now', '-1 hour') THEN 1 ELSE 0 END) AS last_hour,
SUM(CASE WHEN datetime(ingested_at) >= datetime('now', '-24 hour') THEN 1 ELSE 0 END) AS last_24_hours,
COUNT(DISTINCT sid) AS unique_sids
FROM alerts;`)
	if err != nil {
		return AlertSummary{}, err
	}
	if len(rows) == 0 {
		return AlertSummary{}, nil
	}
	row := rows[0]
	return AlertSummary{
		Total:       toInt(row["total"]),
		LastHour:    toInt(row["last_hour"]),
		Last24Hours: toInt(row["last_24_hours"]),
		UniqueSIDs:  toInt(row["unique_sids"]),
	}, nil
}

func buildAlertWhere(query AlertQuery) string {
	var clauses []string
	if query.BeforeID > 0 {
		clauses = append(clauses, fmt.Sprintf("id < %d", query.BeforeID))
	}
	if query.SID > 0 {
		clauses = append(clauses, fmt.Sprintf("sid = %d", query.SID))
	}
	if query.Action != "" {
		clauses = append(clauses, "action = "+SQLQuote(query.Action))
	}
	if query.Proto != "" {
		clauses = append(clauses, "proto = "+SQLQuote(strings.ToUpper(query.Proto)))
	}
	if query.Rule != "" {
		clauses = append(clauses, "rule LIKE "+SQLQuote("%"+query.Rule+"%"))
	}
	if query.Src != "" {
		clauses = append(clauses, "src_ap LIKE "+SQLQuote("%"+query.Src+"%"))
	}
	if query.Dst != "" {
		clauses = append(clauses, "dst_ap LIKE "+SQLQuote("%"+query.Dst+"%"))
	}
	if len(clauses) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(clauses, " AND ")
}

func ParseAlertJSON(line string) (AlertEvent, error) {
	var alert AlertEvent
	if err := json.Unmarshal([]byte(line), &alert); err != nil {
		return AlertEvent{}, err
	}
	alert.RawJSON = line
	parts := strings.Split(alert.Rule, ":")
	if len(parts) == 3 {
		alert.GID = ParseIntDefault(parts[0], 0)
		alert.SID = ParseIntDefault(parts[1], 0)
		alert.Rev = ParseIntDefault(parts[2], 0)
	}
	return alert, nil
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func toInt(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(v)
		return n
	default:
		return 0
	}
}
