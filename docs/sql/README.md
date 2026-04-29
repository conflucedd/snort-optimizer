# SQL 包说明

`sql` 包负责把 Snort 的三类数据写入同一个 SQLite 数据库：

- `alerts`：逐行 JSON 的 Snort alert，支持普通导入和 tail 持续导入。
- `profiler_metrics`：从 `snort_output.txt` 解析出的统计项。
- `rule_profiler_metrics`：从 `rule profile` 段解析出的规则性能统计。
- `module_profile_metrics`：从 `module profile` 段解析出的模块性能统计。
- `system_profiles`：wrap 运行期间采样出的平均 CPU 和 RSS 内存。
- `rules`：从规则目录中的 `.rules` 文件解析出的 Snort 规则。

## Package 调用

```go
cfg := sql.Config{
    DBPath:       "tmp/snort.sqlite",
    AlertPath:    "tmp/alert_json.txt",
    ProfilerPath: "tmp/snort_output.txt",
    RulesDir:      "tmp/config/rules",
    RawRulePath:   "tmp/config/rules",
    RunID:         0,
}

_ = sql.Ensure(cfg)
_, _ = sql.ImportAlerts(cfg, nil)
_, _ = sql.ImportProfiler(cfg, nil)
_, _ = sql.ImportRules(cfg, nil)

alerts, _ := sql.ListAlerts(cfg, sql.AlertQuery{SID: 15935, Limit: 20})
metrics, _ := sql.ListProfiler(cfg, sql.ProfilerQuery{Module: "detection"})
rules, _ := sql.ListRules(cfg, sql.RuleQuery{SID: 15935})
```

所有写入、查询和规则启停接口都从 `sql.Config.RunID` 读取运行编号；调用方不设置 `RunID` 时，Go 零值就是默认 `0`。`AlertQuery`、`ProfilerQuery` 和 `RuleQuery` 里的 `RunID` 可用于单次查询覆盖 `cfg.RunID`，一般调用只需要在 `Config` 里设置一次。

tail alert：

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
_ = sql.TailAlerts(ctx, cfg, nil)
```

## 命令行

```bash
go run ./sql/cmd init --db tmp/snort.sqlite
go run ./sql/cmd import-alerts --db tmp/snort.sqlite --alerts tmp/alert_json.txt --run-id 1
go run ./sql/cmd tail-alerts --db tmp/snort.sqlite --alerts tmp/alert_json.txt --run-id 1
go run ./sql/cmd import-profiler --db tmp/snort.sqlite --profiler tmp/snort_output.txt --run-id 1
go run ./sql/cmd import-rules --db tmp/snort.sqlite --raw-rule-path tmp/config/rules --run-id 1
```

查询接口输出 JSON：

```bash
go run ./sql/cmd query-alerts --db tmp/snort.sqlite --run-id 1 --gid 1 --sid 15935 --limit 10
go run ./sql/cmd query-profiler --db tmp/snort.sqlite --module detection --run-id 1
go run ./sql/cmd query-rules --db tmp/snort.sqlite --run-id 1 --gid 1 --sid 15935 --enabled true
```

规则启停：

```bash
go run ./sql/cmd disable-rule --db tmp/snort.sqlite --run-id 1 --gid 1 --sid 15935
go run ./sql/cmd enable-rule --db tmp/snort.sqlite --run-id 1 --gid 1 --sid 15935
```

`rules` 表以 `(run_id, gid, sid)` 为主键；同一个 round 内相同 `gid/sid` 的规则只保留一条记录，不允许同时存在不同 `rev`。`enable-rule` 和 `disable-rule` 会按 `run_id + gid + sid` 更新记录；不传 `--run-id` 时默认只作用于 `run_id = 0`。
