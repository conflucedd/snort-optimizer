package schema

import (
	"snort-optimizer/sql/config"
	"snort-optimizer/sql/db"
)

func Ensure(cfg config.Config) error {
	script := `
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
	source_file TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_sid ON alerts (sid);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_source_file ON alerts (source_file);

CREATE TABLE IF NOT EXISTS profiler_metrics (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	run_id TEXT NOT NULL,
	section TEXT NOT NULL,
	module TEXT NOT NULL,
	metric TEXT NOT NULL,
	value REAL NOT NULL,
	percent REAL,
	unit TEXT,
	raw_line TEXT NOT NULL,
	source_file TEXT,
	created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_profiler_run_id ON profiler_metrics (run_id);
CREATE INDEX IF NOT EXISTS idx_profiler_section_module ON profiler_metrics (section, module);
CREATE INDEX IF NOT EXISTS idx_profiler_created_at ON profiler_metrics (created_at);

CREATE TABLE IF NOT EXISTS rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	sid INTEGER NOT NULL,
	gid INTEGER NOT NULL DEFAULT 1,
	rev INTEGER,
	action TEXT,
	proto TEXT,
	src_net TEXT,
	src_port TEXT,
	direction TEXT,
	dst_net TEXT,
	dst_port TEXT,
	msg TEXT,
	classtype TEXT,
	enabled INTEGER NOT NULL DEFAULT 1,
	source_file TEXT,
	raw_text TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_source_raw ON rules (source_file, raw_text);
CREATE INDEX IF NOT EXISTS idx_rules_sid ON rules (sid);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules (enabled);
`
	return db.RunScript(cfg.DBPath, []byte(script))
}
