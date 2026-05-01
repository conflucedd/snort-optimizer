# analyser 简要说明

`analyser` 用于按轮运行 Snort 实例，基于已标注流量计算误报和漏报，再按策略裁剪规则。它同时运行三类 Snort 实例：

- `exp`：实验 pcap，启用 alert_json，用于计算 FP/FN 和每条规则的 `rule_FP`。
- `real`：真实业务 pcap，启用 profiler，用于判断规则成本。
- `base`：空 pcap，启用 profiler，用于记录加载基线。

## 命令行接口

入口：

```bash
go run ./analyser/cmd --pcap1 data/Tuesday.pcap --db1 data/Tuesday.db --pcap2 data/Monday.pcap --config config/snort.lua --raw-snort-sqlite config/snort.sqlite
```

常用参数：

- `--pcap1`：实验流量 pcap，用于告警和流标签匹配。
- `--db1`：`--pcap1` 对应的流标签 SQLite。
- `--pcap2`：真实业务流量 pcap，用于性能分析。
- `--config`：Snort Lua 配置文件。
- `--raw-snort-sqlite`：初始 Snort 规则库，读取 `run_id=0` 的规则。
- `--raw-rule-path`：无初始规则库时的规则文件或目录。
- `--workdir`：analyser 工作目录，默认 `analyser-work`。
- `--max-round`：ITER 最大迭代轮数。
- `--factor`：ITER 初始裁剪比例因子。
- `--max-miss-increase`：允许的漏报率最大增量。
- `--max-fp-increase`：允许的误报率最大增量。
- `--preserve-work-dbs`：保留已有工作目录，不在启动时删除。
- `--lua`：额外 Snort `--lua` 覆盖项，可重复。

所有参数使用双横线形式，例如 `--pcap1`。单横线参数会被拒绝。

## Go 接口

主要入口在 `snort-optimizer/analyser`：

```go
result, err := analyser.Run(ctx, types.Config{
    Pcap1:          "data/Tuesday.pcap",
    DB1:            "data/Tuesday.db",
    Pcap2:          "data/Monday.pcap",
    SnortConfig:    "config/snort.lua",
    RawSnortSQLite: "config/snort.sqlite",
})
```

需要自定义策略时使用 `Analyzer`：

```go
a, err := analyser.New(cfg)
a.ClearFunctions()
a.Register(myStrategy)
result, err := a.Run(ctx)
```

公共类型在 `snort-optimizer/analyser/types` 中，主要包括：

- `types.Config`：运行配置。
- `types.Result`：最终结果，包含最终 `run_id`、裁剪规则和每轮结果。
- `types.RunResult`：单轮提交或回滚结果。
- `types.Evaluation`：单轮 FP/FN 和性能指标。
- `types.RegisteredFunction`：策略函数注册结构。

## 流和告警匹配

匹配逻辑在 `analyser/sql` 中。告警按五元组和时间匹配到流：

- 使用源 IP、源端口、目的 IP、目的端口、协议。
- 正向和反向都算同一条流，即不看方向。
- 告警时间必须落在 `[flow.timestamp, flow.timestamp + flow_duration]` 范围内。
- `flow_duration` 按数据库中的微秒值计算。
- 同一条流收到多次告警，在总体 FP/FN 中只算一次。

总体统计：

- `FalsePositiveFlows`：被告警命中的 BENIGN 流数量。
- `DetectedMaliciousFlows`：被告警命中的非 BENIGN 流数量。
- `MissedFlows`：未被告警命中的非 BENIGN 流数量。
- `FalsePositiveRate = FalsePositiveFlows / TotalFlows`。
- `MissRate = MissedFlows / MaliciousFlows`。

## 输出和数据库

`analyser` 自己的结果库位于：

```text
<workdir>/analyser.db
```

主要表：

- `runs`：每轮运行结果、是否提交、FP/FN、性能指标。
- `trim_decisions`：每轮策略给出的裁剪决策。

`exp/snort.sqlite` 中额外维护：

- `rule_FP`：每轮 `run_id` 下每条规则的命中流统计和利用率。

`rule_FP` 的核心字段：

- `run_id`：对应轮次。
- `gid` / `sid` / `rev`：规则标识。
- `alerted_flows`：该规则告警命中的唯一流数量。
- `benign_alerted_flows`：命中的 BENIGN 流数量。
- `malicious_alerted_flows`：命中的非 BENIGN 流数量。
- `unmatched_alerts`：未匹配到流的告警数量。
- `fp_rate = benign_alerted_flows / alerted_flows`。
- `utilization = malicious_alerted_flows / alerted_flows`。

## 包结构

- `analyser`：入口和配置校验。
- `analyser/types`：公共类型。
- `analyser/safe`：SAFE 策略。
- `analyser/iter`：ITER 策略。
- `analyser/scheduler`：调度器。
- `analyser/sql`：analyser 专用数据库、流匹配和统计逻辑。
- `analyser/cmd`：命令行入口。
