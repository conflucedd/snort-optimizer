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
    Interface       string
    PcapFile        string
    LuaOverrides    []string
    NeedOutput      bool
    NeedAlert       bool
}
```

- `Mode`：运行模式，取值为 `wrap.ModeInterface` 或 `wrap.ModePCAP`。
- `SnortWorkingDir`：必填，Snort 工作目录。
- `SnortConfigPath`：必填，Snort Lua 配置文件路径。
- `Interface`：`ModeInterface` 模式必填。
- `PcapFile`：`ModePCAP` 模式必填。
- `LuaOverrides`：额外传给 Snort 的 `--lua` 覆写项。
- `NeedOutput`：为 `true` 时只把 Snort stdout/stderr 写入 `snort_output.txt`，不会自动导入性能统计。
- `NeedAlert`：为 `true` 时启用 `alert_json` 文件输出，并持续写入 `snort.sqlite` 的 `alerts` 表。

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
- `Reset() error`：清空 `snort.sqlite` 中的 `rules` 表；下次启动会重新从 `rules` 目录导入。
- `EnableRule(ruleID int64) error`：按 rules 表主键启用规则。
- `DisableRule(ruleID int64) error`：按 rules 表主键禁用规则。
- `Status() Status`：返回运行状态和生效配置。
- `Config() Config`：返回生效配置。

## CLI

所有参数都使用 `--` 开头；单横线参数会被拒绝。

```sh
SNORT_DIR=/path/to/snort/bin-dir \
DAQ_DIR=/path/to/daq-dir \
go run ./wrap/cmd \
  --swd /tmp/snort-work \
  --mode pcap \
  --pcap /tmp/sample.pcap \
  --config /path/to/snort.lua \
  --need-output \
  --need-alert \
  --lua 'search_engine = { search_method = "hyperscan" }'
```

参数：

- `--swd`：Snort 工作目录。
- `--mode`：`interface` 或 `pcap`。
- `--iface`：网卡模式使用的接口名。
- `--pcap`：pcap 模式使用的文件路径。
- `--config`：Snort Lua 配置文件路径。
- `--lua`：额外 Lua 覆写项，可重复。
- `--need-output`：写入 `snort_output.txt`。
- `--need-alert`：启用告警文件并导入 `snort.sqlite`。

## 环境变量

- `SNORT_DIR`：必须指向包含可执行文件 `snort` 的目录。
- `DAQ_DIR`：必须指向 Snort 可用的 DAQ 目录。
