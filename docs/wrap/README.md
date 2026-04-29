# wrap 接口文档

`wrap` 负责启动、停止和管理 Snort 运行过程。它使用项目根目录的 `sql` 包维护统一 SQLite 数据库：

- 数据库路径：`SnortWorkingDir/snort.sqlite`
- 规则目录：`SnortWorkingDir/rules`
- 生成规则文件：`SnortWorkingDir/all.rules`
- 告警文件：`SnortWorkingDir/alert_json.txt`
- 输出文件：`SnortWorkingDir/snort_output.txt`

## Go Package

```go
import "snort-optimizer/wrap"
```

### Config

```go
type Config struct {
    Mode            string
    SnortWorkingDir string
    SnortConfigPath string
    SnortDBPath     string
    RawRulePath     string
    Interface       string
    PcapFile        string
    LuaOverrides    []string
    RunID           int64
    NeedOutput      bool
    NeedAlert       bool
    NeedProfiler    bool
}
```

- `Mode`：运行模式，取值为 `wrap.ModeInterface` 或 `wrap.ModePCAP`。
- `SnortWorkingDir`：Snort 工作目录；为空时使用当前目录。
- `SnortConfigPath`：必填，Snort Lua 配置文件路径。
- `SnortDBPath`：SQLite 数据库路径；为空时使用 `SnortWorkingDir/snort.sqlite`。
- `RawRulePath`：初始化规则表的 `.rules` 文件或目录；为空时使用 `SnortWorkingDir/rules`。
- `Interface`：`ModeInterface` 模式必填。
- `PcapFile`：`ModePCAP` 模式必填。
- `LuaOverrides`：额外传给 Snort 的 `--lua` 覆写项。
- `RunID`：写入 alert/rule/profiler/system profile 记录的运行编号，默认 `0`。非 0 时 `wrap` 只加载数据库中对应 `run_id` 的规则，不会从 `RawRulePath` 初始化；数据库不存在或对应规则不存在会直接报错。
- `NeedOutput`：为 `true` 时只把 Snort stdout/stderr 写入 `snort_output.txt`，不会自动导入性能统计。
- `NeedAlert`：为 `true` 时启用 `alert_json` 文件输出，并持续写入 `snort.sqlite` 的 `alerts` 表。
- `NeedProfiler`：为 `true` 时写入 `snort_output.txt`，Snort 结束后导入 rule/module profiler，并记录平均 CPU/RSS。

### Runner

```go
r, err := wrap.NewRunner(wrap.Config{
    Mode:            wrap.ModePCAP,
    SnortWorkingDir: "/tmp/snort-work",
    SnortConfigPath: "/path/to/snort.lua",
    PcapFile:        "/tmp/sample.pcap",
    NeedOutput:      true,
    NeedAlert:       true,
})
```

主要方法：

- `Start() error`：初始化数据库和规则，生成 `all.rules`，启动 Snort。
- `Stop() error`：停止 Snort 进程组，并停止告警 tail。
- `Restart() error`：先停止再启动。
- `Reset() error`：删除 `snort.sqlite` 及其 WAL/SHM 文件；下次启动会重新从 raw rules 初始化。
- `Status() Status`：返回运行状态和生效配置。
- `Config() Config`：返回生效配置。

## CLI

所有参数都使用 `--` 开头；单横线参数会被拒绝。

```sh
SNORT_DIR=/path/to/snort/bin-dir \
DAQ_DIR=/path/to/daq-dir \
go run ./wrap/cmd \
  --pcap /tmp/sample.pcap \
  --swd /tmp/snort-work \
  --config /path/to/snort.lua \
  --raw-rule-path /path/to/rules \
  --snort-db-path /tmp/snort-work/snort.sqlite \
  --run-id 1 \
  --need-output \
  --need-alert \
  --need-profiler \
  --lua 'search_engine = { search_method = "hyperscan" }'
```

参数：

- `--swd`：Snort 工作目录，默认当前目录。
- `--iface`：网卡模式使用的接口名。
- `--pcap`：pcap 模式使用的文件路径。
- `--config`：Snort Lua 配置文件路径。
- `--raw-rule-path`：初始化规则表的 `.rules` 文件或目录。
- `--snort-db-path`：SQLite 数据库路径。
- `--run-id`：运行编号，默认 `0`。
- `--lua`：额外 Lua 覆写项，可重复。
- `--need-output`：写入 `snort_output.txt`。
- `--need-alert`：启用告警文件并导入 `snort.sqlite`。
- `--need-profiler`：导入 rule/module profiler，并记录系统 CPU/RSS。

## 环境变量

- `SNORT_DIR`：必须指向包含可执行文件 `snort` 的目录。
- `DAQ_DIR`：必须指向 Snort 可用的 DAQ 目录。
