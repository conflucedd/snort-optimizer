package alerts

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"snort-optimizer/sql/config"
	"snort-optimizer/types"
)

func TestListUsesConfigRunIDByDefault(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath: filepath.Join(dir, "snort.sqlite"),
		RunID:  7,
	}
	if err := InsertBatch(cfg, []types.Alert{
		{Timestamp: "07/07-20:00:36.492196", Proto: "TCP", GID: 1, SID: 222, Rev: 1, RawJSON: "{}"},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one alert for config run id, got %d", len(got))
	}
	if got[0].RunID != 7 {
		t.Fatalf("expected run id 7, got %d", got[0].RunID)
	}
}

func TestListFiltersByRuleIdentity(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath: filepath.Join(dir, "snort.sqlite"),
		RunID:  7,
	}
	alerts := []types.Alert{
		{Timestamp: "07/07-20:00:36.492196", Proto: "TCP", GID: 1, SID: 222, Rev: 1, RawJSON: "{}"},
		{Timestamp: "07/07-20:00:37.492196", Proto: "TCP", GID: 2, SID: 222, Rev: 1, RawJSON: "{}"},
		{Timestamp: "07/07-20:00:38.492196", Proto: "TCP", GID: 1, SID: 333, Rev: 1, RawJSON: "{}"},
	}
	if err := InsertBatch(cfg, alerts); err != nil {
		t.Fatal(err)
	}
	got, err := List(cfg, Query{GID: 1, SID: 222, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one alert for gid/sid/rev, got %d", len(got))
	}
	if got[0].GID != 1 || got[0].SID != 222 || got[0].Rev != 1 {
		t.Fatalf("unexpected alert identity %d:%d:%d", got[0].GID, got[0].SID, got[0].Rev)
	}
}

func TestTailerStartsExistingFileAtEndAndDrainsFinalLine(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{
		DBPath:    filepath.Join(dir, "snort.sqlite"),
		AlertPath: filepath.Join(dir, "alert_json.txt"),
	}
	logger := log.New(io.Discard, "", 0)
	oldLine := `{ "timestamp" : "07/07-20:00:35.492196", "pkt_num" : 1, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 390, "dir" : "C2S", "src_ap" : "192.168.10.9:1035", "dst_ap" : "192.168.10.3:389", "rule" : "1:111:1", "action" : "would_block" }` + "\n"
	newLine := `{ "timestamp" : "07/07-20:00:36.492196", "pkt_num" : 2, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 390, "dir" : "C2S", "src_ap" : "192.168.10.9:1035", "dst_ap" : "192.168.10.3:389", "rule" : "1:222:1", "action" : "would_block" }`
	if err := os.WriteFile(cfg.AlertPath, []byte(oldLine), 0644); err != nil {
		t.Fatal(err)
	}
	tailer, err := NewTailer(cfg, logger, true)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(cfg.AlertPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(newLine); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tailer.Tail(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := List(cfg, Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one imported alert, got %d", len(got))
	}
	if got[0].SID != 222 {
		t.Fatalf("expected new alert SID 222, got %d", got[0].SID)
	}
}
