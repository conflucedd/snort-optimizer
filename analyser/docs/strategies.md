# 策略函数接口

策略函数用于向调度器提交“建议裁剪哪些规则”。策略不直接修改数据库；调度器会汇总策略结果、复制规则到新 `run_id`、禁用规则、运行 Snort，并根据 FP/FN 阈值提交或回滚。

## 基础类型

所有策略使用 `snort-optimizer/analyser/types` 中的公共类型。

策略函数签名：

```go
type TrimFunction func(context.Context, types.FunctionInput) ([]types.TrimDecision, error)
```

注册结构：

```go
type RegisteredFunction struct {
    Name string
    Type types.FunctionType
    Fn   types.TrimFunction
}
```

策略类型：

- `types.SAFE`：保守策略。当前调度逻辑会直接提交 SAFE 结果。
- `types.ITER`：迭代策略。调度器会运行候选轮次，并按 FP/FN 增量决定提交或回滚。

## 输入

`types.FunctionInput`：

```go
type FunctionInput struct {
    ExpDBPath   string
    RealDBPath  string
    BaseDBPath  string
    Round       int
    SourceRunID int64
    Factor      float64
}
```

字段含义：

- `ExpDBPath`：实验实例的 `snort.sqlite`。
- `RealDBPath`：真实业务实例的 `snort.sqlite`。
- `BaseDBPath`：空 pcap 基线实例的 `snort.sqlite`。
- `Round`：当前轮次。SAFE 阶段为 `0`，ITER 从 `1` 开始。
- `SourceRunID`：当前已接受的规则版本。策略应该只分析这个 `run_id`。
- `Factor`：ITER 裁剪强度因子，回滚后会减半。

## 输出

策略返回 `[]types.TrimDecision`：

```go
type TrimDecision struct {
    types.RuleRef
    SourceFile string
    Msg        string
    Reason     string
    Metrics    map[string]float64
}
```

最少需要填：

- `GID`
- `SID`
- `Reason`

推荐同时填：

- `Rev`
- `SourceFile`
- `Msg`
- `Metrics`

调度器会自动补充：

- `Function`
- `Type`

如果多个策略返回同一条规则，调度器会合并理由、函数名和指标。

## 注册和调度

`analyser.New` 不注册默认策略。调用方需要显式调用 `Register` / `RegisterAll`，命令行入口会根据 `--strategy` 和 `--disable-strategy` 注册内置策略。

SAFE 策略会在 baseline 后统一执行并直接提交。ITER 策略按注册顺序逐个执行：每个 ITER 策略最多运行 `MaxRound` 轮，完成后才进入下一个 ITER 策略。每轮候选结果和上一轮已接受结果比较，超过漏报率或误报率阈值时回滚该轮。

## 当前策略

| 名称 | 文件 | 类型 | 逻辑 |
| --- | --- | --- | --- |
| `safe_source_file_browser` | `analyser/safe/source_file_browser.go` | SAFE | 裁剪 browser 和 file/browser 类规则。 |
| `safe_source_file_protocols` | `analyser/safe/source_file_protocols.go` | SAFE | 按服务器场景裁剪 legacy、网关或工业控制类不常用协议规则。 |
| `safe_inactive_systemd_services` | `analyser/safe/inactive_systemd_services.go` | SAFE | 读取 systemd active service/socket，裁剪未启用常见服务对应的规则。systemd 不可用时返回空结果。 |
| `safe_orphan_flowbits` | `analyser/safe/orphan_flowbits.go` | SAFE | 裁剪依赖 `flowbits:isset`、但当前启用规则中没有 `set`/`toggle` 提供者的规则。 |
| `iter_protocol_alert_overlap` | `analyser/iter/protocol_alert_overlap.go` | ITER | 对 protocol 类 source file，若告警覆盖集中在少量规则上，逐步裁剪低覆盖规则。 |
| `iter_high_fp_low_utilization` | `analyser/iter/high_fp_low_utilization.go` | ITER | 基于 `rule_FP` 裁剪高误报率、低恶意流利用率规则。 |
| `iter_low_yield_hot_rules` | `analyser/iter/low_yield_hot_rules.go` | ITER | 基于 profiler checks 和 `rule_FP` 裁剪被频繁检查但恶意检出低的规则。 |
| `iter_high_cost_rules` | `analyser/iter/high_cost_rules.go` | ITER | 按 `rule_profiler_metrics.time_us` 和 `rule_time_pct` 裁剪高性能成本规则。 |

## 新增策略约定

SAFE 策略放在：

```text
analyser/safe/<策略名>.go
```

ITER 策略放在：

```text
analyser/iter/<策略名>.go
```

文件名应描述策略，例如：

```text
high_fp_rules.go
low_utilization_rules.go
source_file_browser.go
```

每个策略文件建议提供两个函数：

```go
func MyStrategy() types.RegisteredFunction {
    return types.RegisteredFunction{
        Name: "iter_my_strategy",
        Type: types.ITER,
        Fn:   MyStrategyFunc,
    }
}

func MyStrategyFunc(ctx context.Context, input types.FunctionInput) ([]types.TrimDecision, error) {
    // query input.ExpDBPath / input.RealDBPath / input.BaseDBPath
    // only use input.SourceRunID
    return decisions, nil
}
```

注册位置示例：

```go
a.Register(iter.MyStrategy())
```

命名建议：

- SAFE 名称以 `safe_` 开头。
- ITER 名称以 `iter_` 开头。
- `Name` 必须稳定，因为会写入裁剪记录。

策略实现注意事项：

- 只读取当前 `SourceRunID`，不要跨轮次混用数据。
- 不要直接修改 `rules`、`alerts`、`rule_FP` 等表。
- 不要在策略内决定提交或回滚，提交逻辑属于调度器。
- 返回空切片表示本轮没有建议裁剪的规则。
- 查询数据库时使用 `QueryContext`，让 `ctx` 可以取消长查询。
