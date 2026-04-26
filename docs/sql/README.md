# SQL 包说明

`sql` 包负责把 Snort 的三类数据写入同一个 SQLite 数据库：

- `alerts`：逐行 JSON 的 Snort alert，支持普通导入和 tail 持续导入。
- `profiler_metrics`：从 `snort_output.txt` 解析出的统计项。
- `rules`：从规则目录中的 `.rules` 文件解析出的 Snort 规则。

## Package 调用

```go
cfg := sql.Config{
    DBPath:       "tmp/snort.sqlite",
    AlertPath:    "tmp/alert_json.txt",
    ProfilerPath: "tmp/snort_output.txt",
    RulesDir:      "tmp/config/rules",
}

_ = sql.Ensure(cfg)
_, _ = sql.ImportAlerts(cfg, nil)
_, _ = sql.ImportProfiler(cfg, "run-001", nil)
_, _ = sql.ImportRules(cfg, nil)

alerts, _ := sql.ListAlerts(cfg, sql.AlertQuery{SID: 15935, Limit: 20})
metrics, _ := sql.ListProfiler(cfg, sql.ProfilerQuery{Module: "detection"})
rules, _ := sql.ListRules(cfg, sql.RuleQuery{SID: 15935})
```

tail alert：

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
_ = sql.TailAlerts(ctx, cfg, nil)
```

## 命令行

```bash
go run ./sql/cmd init --db tmp/snort.sqlite
go run ./sql/cmd import-alerts --db tmp/snort.sqlite --alerts tmp/alert_json.txt
go run ./sql/cmd tail-alerts --db tmp/snort.sqlite --alerts tmp/alert_json.txt
go run ./sql/cmd import-profiler --db tmp/snort.sqlite --profiler tmp/snort_output.txt --run-id run-001
go run ./sql/cmd import-rules --db tmp/snort.sqlite --rules tmp/config/rules
```

查询接口输出 JSON：

```bash
go run ./sql/cmd query-alerts --db tmp/snort.sqlite --sid 15935 --limit 10
go run ./sql/cmd query-profiler --db tmp/snort.sqlite --module detection
go run ./sql/cmd query-rules --db tmp/snort.sqlite --msg DNS --enabled true
```

规则启停：

```bash
go run ./sql/cmd disable-rule --db tmp/snort.sqlite --id 1
go run ./sql/cmd enable-rule --db tmp/snort.sqlite --id 1
```
