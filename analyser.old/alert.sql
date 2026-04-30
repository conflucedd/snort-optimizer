CREATE TABLE rule_detection_metrics (
	gid INTEGER,
    sid INTEGER,
    rev INTEGER,

	

	timestamp TEXT,
    protocol TEXT,
    direction TEXT,
    source TEXT, -- with port
    target TEXT, -- with port

	PRIMARY KEY(gid, sid, rev)
);

