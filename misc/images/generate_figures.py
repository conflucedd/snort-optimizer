#!/usr/bin/env python3
from __future__ import annotations

import html
import sqlite3
import textwrap
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_ROOT = REPO_ROOT / "misc" / "images"
RESULT_ROOT = REPO_ROOT / "analyser" / "cmd" / "analyser_result"

DAYS = [
    ("Tuesday", "周二实验流量"),
    ("Wednesday", "周三实验流量"),
    ("Thursday", "周四实验流量"),
    ("Friday", "周五实验流量"),
]

STRATEGY_LABELS = {
    "safe_source_file_browser": "浏览器/文件类 SAFE",
    "safe_source_file_protocols": "不常用协议 SAFE",
    "safe_inactive_systemd_services": "未启用服务 SAFE",
    "safe_orphan_flowbits": "孤立 flowbits SAFE",
    "iter_protocol_alert_overlap": "协议覆盖 ITER",
    "iter_high_fp_low_utilization": "高误报低利用率 ITER",
    "iter_low_yield_hot_rules": "高频低收益 ITER",
    "iter_high_cost_rules": "高成本规则 ITER",
}

STRATEGY_ORDER = [
    "safe_source_file_browser",
    "safe_source_file_protocols",
    "safe_inactive_systemd_services",
    "safe_orphan_flowbits",
    "iter_protocol_alert_overlap",
    "iter_high_fp_low_utilization",
    "iter_low_yield_hot_rules",
    "iter_high_cost_rules",
]

PALETTE = {
    "orange": "#e69f00",
    "blue": "#0072b2",
    "green": "#009e73",
    "red": "#d55e00",
    "gray": "#7f7f7f",
    "slate": "#1f2937",
    "light": "#ffffff",
    "border": "#9ca3af",
    "grid": "#e5e7eb",
    "safe1": "#0072b2",
    "safe2": "#009e73",
    "safe3": "#56b4e9",
    "safe4": "#999999",
    "iter1": "#e69f00",
    "iter2": "#d55e00",
    "iter3": "#cc79a7",
    "iter4": "#6a3d9a",
}


def connect_ro(db_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)


def rows(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> list[dict]:
    conn.row_factory = sqlite3.Row
    return [dict(row) for row in conn.execute(sql, args).fetchall()]


def one(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> dict | None:
    conn.row_factory = sqlite3.Row
    row = conn.execute(sql, args).fetchone()
    return dict(row) if row else None


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def pct(value: float, digits: int = 2) -> str:
    return f"{value * 100:.{digits}f}%"


def pp(value: float, digits: int = 2) -> str:
    return f"{value * 100:+.{digits}f} 个百分点"


def num(value: float | int, digits: int = 0) -> str:
    if isinstance(value, float) and digits > 0:
        return f"{value:,.{digits}f}"
    return f"{value:,.0f}"


def ms_to_s(ms: float) -> float:
    return ms / 1000.0


def us_to_s(us: float) -> float:
    return us / 1_000_000.0


def ensure_dir(name: str) -> Path:
    path = OUT_ROOT / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def svg_doc(width: int, height: int, title: str, subtitle: str = "") -> list[str]:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<defs>",
        "<style>",
        "text { font-family: 'Noto Sans CJK SC', 'Source Han Sans SC', 'Microsoft YaHei', 'PingFang SC', 'SimHei', 'WenQuanYi Micro Hei', sans-serif; fill: #111827; }",
        ".title { font-size: 22px; font-weight: 700; }",
        ".subtitle { font-size: 13px; fill: #4b5563; }",
        ".axis { stroke: #6b7280; stroke-width: 1; }",
        ".grid { stroke: #e5e7eb; stroke-width: 1; }",
        ".label { font-size: 12px; fill: #374151; }",
        ".small { font-size: 11px; fill: #4b5563; }",
        ".value { font-size: 12px; font-weight: 600; }",
        ".panel-title { font-size: 15px; font-weight: 700; }",
        ".note { font-size: 12px; fill: #4b5563; }",
        "</style>",
        "</defs>",
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text class="title" x="40" y="42">{esc(title)}</text>',
    ]
    if subtitle:
        for i, part in enumerate(textwrap.wrap(subtitle, width=92)):
            parts.append(f'<text class="subtitle" x="40" y="{68 + i * 18}">{esc(part)}</text>')
    return parts


def svg_end(parts: list[str], path: Path) -> None:
    parts.append("</svg>")
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def line_points(values: list[float], x0: float, y0: float, w: float, h: float, y_max: float, y_min: float = 0.0) -> list[tuple[float, float]]:
    n = len(values)
    if n <= 1:
        return [(x0 + w / 2, y0 + h / 2)]
    span = max(y_max - y_min, 1e-9)
    out = []
    for i, value in enumerate(values):
        x = x0 + i * w / (n - 1)
        y = y0 + h - (value - y_min) / span * h
        out.append((x, y))
    return out


def polyline(points: list[tuple[float, float]], color: str, width: float = 2.5) -> str:
    value = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    return f'<polyline points="{value}" fill="none" stroke="{color}" stroke-width="{width}"/>'


def write_markdown_table(path: Path, title: str, headers: list[str], data: list[list[object]], note: str = "") -> None:
    lines = [f"# {title}", ""]
    if note:
        lines.extend([note, ""])
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for row in data:
        lines.append("| " + " | ".join(str(cell).replace("\n", "<br>") for cell in row) + " |")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def collect_data() -> dict:
    data: dict[str, dict] = {}
    for day, label in DAYS:
        root = RESULT_ROOT / f"{day}_result"
        analyser_db = root / "analyser.db"
        exp_db = root / "exp" / "snort.sqlite"
        real_db = root / "real" / "snort.sqlite"
        with connect_ro(analyser_db) as conn:
            run_rows = rows(
                conn,
                """
                select run_id, committed, rolled_back, factor, reason,
                       total_flows, benign_flows, malicious_flows, alerted_flows,
                       false_positive_flows, detected_malicious_flows, missed_flows,
                       unmatched_alert_flows, false_positive_rate, miss_rate,
                       real_rule_time_us, real_avg_cpu, real_avg_mem_mb,
                       base_load_ms, exp_runtime_ms, real_runtime_ms, created_at
                from runs
                order by run_id
                """,
            )
            decision_rows = rows(
                conn,
                """
                select run_id, gid, sid, rev, source_file, msg, reasons, functions,
                       type, metrics, committed, created_at
                from trim_decisions
                order by run_id, gid, sid
                """,
            )
        with connect_ro(exp_db) as conn:
            rule_counts = rows(
                conn,
                """
                select run_id, count(*) as total_rules, sum(enabled) as enabled_rules,
                       count(*) - sum(enabled) as disabled_rules
                from rules
                group by run_id
                order by run_id
                """,
            )
            alert_counts = rows(
                conn,
                """
                select run_id, count(*) as alerts
                from alerts
                group by run_id
                order by run_id
                """,
            )
            rule_fp_rows = rows(
                conn,
                """
                select run_id, gid, sid, rev, msg, source_file, alerted_flows,
                       benign_alerted_flows, malicious_alerted_flows, unmatched_alerts,
                       fp_rate, utilization
                from rule_FP
                order by run_id, fp_rate desc, alerted_flows desc
                """,
            )
        with connect_ro(real_db) as conn:
            top_cost_rows = rows(
                conn,
                """
                select run_id, gid, sid, rev, source_file, checks, matches, alerts,
                       time_us, avg_check, rule_time_pct
                from rule_profiler_metrics
                order by run_id, time_us desc
                """,
            )

        committed_runs = [r for r in run_rows if r["committed"] == 1 and r["rolled_back"] == 0]
        final_run_id = max(r["run_id"] for r in committed_runs)
        rules_by_run = {r["run_id"]: r for r in rule_counts}
        alerts_by_run = {r["run_id"]: r["alerts"] for r in alert_counts}
        run_by_id = {r["run_id"]: r for r in run_rows}

        data[day] = {
            "label": label,
            "root": root,
            "runs": run_rows,
            "decisions": decision_rows,
            "rule_counts": rule_counts,
            "rules_by_run": rules_by_run,
            "alert_counts": alert_counts,
            "alerts_by_run": alerts_by_run,
            "rule_fp": rule_fp_rows,
            "top_cost": top_cost_rows,
            "baseline": run_by_id[0],
            "final": run_by_id[final_run_id],
            "final_run_id": final_run_id,
        }
    return data


def strategy_counts(decisions: list[dict], committed: int | None = None) -> Counter:
    counter: Counter = Counter()
    for item in decisions:
        if committed is not None and item["committed"] != committed:
            continue
        names = [name.strip() for name in str(item["functions"]).split(",") if name.strip()]
        for name in names:
            counter[name] += 1
    return counter


def write_readme(path: Path, title: str, body: str) -> None:
    (path / "README.md").write_text(f"# {title}\n\n{body.strip()}\n", encoding="utf-8")


def generate_mermaid() -> None:
    mermaid_theme = """%%{init: {"theme": "base", "themeVariables": {"background": "#ffffff", "primaryColor": "#ffffff", "primaryBorderColor": "#111827", "primaryTextColor": "#111827", "lineColor": "#374151", "secondaryColor": "#ffffff", "tertiaryColor": "#ffffff", "fontFamily": "Microsoft YaHei, Noto Sans CJK SC, SimHei, sans-serif"}}}%%"""
    diagrams = {
        "01_system_architecture_mermaid": (
            "系统总体架构图",
            """
flowchart LR
    user[论文读者/运维用户] --> web[React 前端<br/>概览、规则优化、告警、配置、系统优化]
    web --> api[Go 后端 REST API<br/>server/api]
    api --> jobs[任务管理<br/>分析任务、性能测试、抓包任务]
    api --> store[(SQLite 配置库<br/>settings/jobs)]
    jobs --> analyser[规则裁剪分析器<br/>analyser]
    analyser --> scheduler[调度器<br/>baseline / SAFE / ITER]
    scheduler --> strategies[可插拔裁剪策略<br/>safe 与 iter]
    scheduler --> wrap[Snort 运行封装<br/>wrap]
    api --> wrap
    wrap --> snort[Snort 3<br/>PCAP/网卡检测]
    snort --> outputs[alert_json / profiler / stdout]
    outputs --> sql[解析与入库<br/>sql 模块]
    sql --> snortdb[(snort.sqlite<br/>rules/alerts/profiler/system_profiles)]
    analyser --> analyserdb[(analyser.db<br/>runs/trim_decisions)]
    analyser --> snortdb
    api --> snortdb
    api --> analyserdb
            """,
        ),
        "02_three_instance_model_mermaid": (
            "三实例评估模型图",
            """
flowchart TB
    cfg[同一组规则版本 run_id] --> exp[exp 实例<br/>实验 PCAP：Tuesday-Friday<br/>启用 alert_json]
    cfg --> real[real 实例<br/>真实/基准流量：Monday<br/>启用 rule profiler]
    cfg --> base[base 实例<br/>空 PCAP<br/>启用 profiler]

    labels[(实验流量标签 DB)] --> match[告警与流匹配]
    exp --> alerts[alerts 表<br/>gid/sid、五元组、时间]
    alerts --> match
    match --> effect[检测效果指标<br/>误报率、漏报率、rule_FP]

    real --> cost[性能画像<br/>规则耗时、checks、CPU、内存]
    base --> load[加载基线<br/>base_load_ms]

    effect --> scheduler[裁剪调度器]
    cost --> scheduler
    load --> scheduler
    scheduler --> decision[提交或回滚候选 run]
            """,
        ),
        "03_trim_scheduler_flow_mermaid": (
            "规则裁剪提交与回滚流程图",
            """
flowchart TD
    start([开始分析]) --> baseline[运行 baseline<br/>生成 run 0]
    baseline --> safe[执行全部 SAFE 策略<br/>静态/低风险裁剪]
    safe --> safeCommit[直接提交 SAFE run]
    safeCommit --> iterStart{还有 ITER 策略?}
    iterStart -- 否 --> final[输出最终 committed run]
    iterStart -- 是 --> choose[选择下一个 ITER 策略]
    choose --> round{达到 MaxRound?}
    round -- 是 --> iterStart
    round -- 否 --> clone[从当前 accepted run 克隆规则]
    clone --> trim[禁用候选规则<br/>生成 candidate run]
    trim --> run[运行 exp / real / base 三实例]
    run --> eval[计算误报率、漏报率和性能指标]
    eval --> judge{误报率增量和漏报率增量<br/>是否均未超过阈值?}
    judge -- 是 --> commit[提交 candidate run<br/>更新 accepted run]
    judge -- 否 --> rollback[回滚 candidate run<br/>factor 减半]
    commit --> round
    rollback --> round
            """,
        ),
        "04_core_data_model_mermaid": (
            "核心数据表关系图",
            """
flowchart LR
    runs[(runs<br/>每轮运行结果<br/>提交/回滚、误报率、漏报率、耗时)]
    decisions[(trim_decisions<br/>裁剪决策<br/>规则、策略、原因、指标)]
    rules[(rules<br/>规则版本表<br/>run_id + gid + sid)]
    alerts[(alerts<br/>告警记录<br/>五元组、时间、规则 ID)]
    profiler[(rule_profiler_metrics<br/>规则性能画像<br/>checks、time_us、rule_time_pct)]
    system[(system_profiles<br/>CPU、内存、FP/FN 汇总)]
    rulefp[(rule_FP<br/>规则级误报与利用率)]

    rules -- run_id/gid/sid --> decisions
    runs -- run_id --> decisions
    runs -- run_id --> rules
    rules -- gid/sid/rev --> alerts
    rules -- gid/sid/rev --> profiler
    alerts -- 五元组与时间窗口匹配 --> rulefp
    runs -- run_id --> system
    rulefp -- fp_rate/utilization --> decisions
    profiler -- time_us/checks --> decisions
            """,
        ),
        "12_core_class_diagram_mermaid": (
            "核心类与数据结构图",
            """
classDiagram
    direction LR
    class Analyzer {
        -Config cfg
        -RegisteredFunction list functions
        +Register(fn)
        +RegisterAll(functions)
        +Run(ctx) Result
    }
    class Scheduler {
        -Config cfg
        -RegisteredFunction list functions
        +Run(ctx) Result
        -execute(type,input) TrimDecision list
        -executeFunction(fn,input) TrimDecision list
        -evaluateCandidate(accepted,candidate) bool
    }
    class RegisteredFunction {
        +string Name
        +FunctionType Type
        +TrimFunction Fn
    }
    class FunctionInput {
        +string ExpDBPath
        +string RealDBPath
        +string BaseDBPath
        +int Round
        +int64 SourceRunID
        +float64 Factor
    }
    class TrimDecision {
        +int64 GID
        +int64 SID
        +int64 Rev
        +string SourceFile
        +string Msg
        +string Reason
        +map Metrics
    }
    class TrimmedRule {
        +int64 GID
        +int64 SID
        +int64 Rev
        +string list Reasons
        +string list Functions
        +FunctionType Type
        +map Metrics
    }
    class RunResult {
        +int64 RunID
        +bool Committed
        +bool RolledBack
        +float64 Factor
        +string Reason
        +Evaluation Evaluation
    }
    class Evaluation {
        +int64 FalsePositiveFlows
        +int64 MissedFlows
        +float64 FalsePositiveRate
        +float64 MissRate
        +int64 RealRuleTimeUS
        +float64 RealAvgCPU
        +float64 RealAvgMemMB
    }
    class Result {
        +string AnalyserDBPath
        +int64 FinalRunID
        +TrimmedRule list TrimmedRules
        +RunResult list Runs
    }
    class InstanceSet {
        +SnortInstance Exp
        +SnortInstance Real
        +SnortInstance Base
        +runAll(ctx,cfg,runID)
    }
    class SnortInstance {
        +string Name
        +string PcapPath
        +string WorkDir
        +string DBPath
        +bool NeedAlert
        +run(ctx,cfg,runID)
    }
    class Runner {
        -wrap.Config cfg
        -exec.Cmd cmd
        -RunInfo runInfo
        +Start()
        +Wait(ctx)
        +Stop()
        +StartupStats()
    }

    Analyzer o-- RegisteredFunction : 注册策略
    Analyzer --> Scheduler : 创建并运行
    Scheduler o-- RegisteredFunction : 保存策略列表
    Scheduler --> FunctionInput : 构造策略输入
    RegisteredFunction --> TrimDecision : Fn 返回
    Scheduler --> TrimmedRule : 聚合裁剪结果
    Scheduler --> RunResult : 写入每轮结果
    RunResult *-- Evaluation
    Result *-- RunResult
    Result *-- TrimmedRule
    Scheduler --> InstanceSet : 调度三实例
    InstanceSet *-- SnortInstance
    SnortInstance --> Runner : wrap.NewRunner
            """,
        ),
        "13_strategy_plugin_detail_mermaid": (
            "策略插件注册与调用图",
            """
flowchart LR
    subgraph contracts[接口契约]
        registered[RegisteredFunction<br/>Name: 稳定策略名<br/>Type: SAFE 或 ITER<br/>Fn: TrimFunction]
        input[FunctionInput<br/>ExpDBPath / RealDBPath / BaseDBPath<br/>Round / SourceRunID / Factor]
        output[TrimDecision<br/>GID / SID / Rev<br/>Reason / Metrics<br/>SourceFile / Msg]
    end

    subgraph factories[内置策略工厂]
        safe1[safe.SourceFileBrowser<br/>SAFE]
        safe2[safe.SourceFileProtocols<br/>SAFE]
        safe3[safe.InactiveSystemdServices<br/>SAFE]
        safe4[safe.OrphanFlowbits<br/>SAFE]
        iter1[iter.ProtocolAlertOverlap<br/>ITER]
        iter2[iter.HighFPLowUtilization<br/>ITER]
        iter3[iter.LowYieldHotRules<br/>ITER]
        iter4[iter.HighCostRules<br/>ITER]
    end

    subgraph registry[注册与筛选]
        cli[analyser/cmd<br/>--strategy / --disable-strategy]
        api[server/api/jobs.go<br/>AnalysisStartRequest]
        select[selectStrategies<br/>按名称启用或禁用]
        register[Analyzer.RegisterAll<br/>校验 Name / Type / Fn]
        funcs[Analyzer.functions<br/>RegisteredFunction 列表]
    end

    subgraph dispatcher[调度器调用]
        scheduler[Scheduler<br/>持有 functions]
        split[functionsByType<br/>SAFE / ITER 分组]
        safeCall[execute SAFE<br/>同一阶段批量调用]
        iterCall[executeFunction ITER<br/>逐策略、逐轮调用]
        enrich[AggregateAndEnrich<br/>过滤非启用规则<br/>补充 msg/source_file/rev<br/>合并重复 GID:SID]
        apply[CloneRulesForRun<br/>禁用候选规则<br/>提交或回滚由 Scheduler 决定]
    end

    safe1 --> registered
    safe2 --> registered
    safe3 --> registered
    safe4 --> registered
    iter1 --> registered
    iter2 --> registered
    iter3 --> registered
    iter4 --> registered
    registered --> select
    cli --> select
    api --> select
    select --> register
    register --> funcs
    funcs --> scheduler
    scheduler --> split
    split --> safeCall
    split --> iterCall
    input --> safeCall
    input --> iterCall
    safeCall --> output
    iterCall --> output
    output --> enrich
    enrich --> apply
            """,
        ),
    }
    for dirname, (title, source) in diagrams.items():
        path = ensure_dir(dirname)
        mmd = mermaid_theme + "\n" + textwrap.dedent(source).strip() + "\n"
        (path / "diagram.mmd").write_text(mmd, encoding="utf-8")
        (path / "diagram.md").write_text(f"# {title}\n\n```mermaid\n{mmd}```\n", encoding="utf-8")
        write_readme(path, title, "Mermaid 源文件为 `diagram.mmd`，Markdown 预览文件为 `diagram.md`。")


def generate_cross_dataset_summary(data: dict) -> None:
    path = ensure_dir("05_cross_dataset_summary")
    width, height = 1280, 860
    parts = svg_doc(
        width,
        height,
        "跨数据集优化前后核心指标对比",
        "Monday 作为真实/基准流量，Tuesday-Friday 作为实验流量；每组左侧为 baseline run 0，右侧为最终 committed run。",
    )
    panels = [
        ("启用规则数量", lambda d: (d["rules_by_run"][0]["enabled_rules"], d["rules_by_run"][d["final_run_id"]]["enabled_rules"]), "条", False),
        ("规则总耗时", lambda d: (us_to_s(d["baseline"]["real_rule_time_us"]), us_to_s(d["final"]["real_rule_time_us"])), "秒", True),
        ("真实基准流量运行时间", lambda d: (ms_to_s(d["baseline"]["real_runtime_ms"]), ms_to_s(d["final"]["real_runtime_ms"])), "秒", True),
        ("实验流量运行时间", lambda d: (ms_to_s(d["baseline"]["exp_runtime_ms"]), ms_to_s(d["final"]["exp_runtime_ms"])), "秒", True),
    ]
    x_start, y_start = 62, 116
    panel_w, panel_h = 560, 300
    x_gap, y_gap = 70, 70
    day_names = [label.split("实验")[0] for _, label in DAYS]
    for idx, (title, getter, unit, lower_is_better) in enumerate(panels):
        col = idx % 2
        row = idx // 2
        x0 = x_start + col * (panel_w + x_gap)
        y0 = y_start + row * (panel_h + y_gap)
        parts.append(f'<rect x="{x0}" y="{y0}" width="{panel_w}" height="{panel_h}" fill="#ffffff" stroke="{PALETTE["border"]}" stroke-width="1"/>')
        parts.append(f'<text class="panel-title" x="{x0 + 18}" y="{y0 + 30}">{esc(title)}</text>')
        vals = [getter(data[day]) for day, _ in DAYS]
        max_v = max(max(pair) for pair in vals) * 1.12
        plot_x, plot_y = x0 + 54, y0 + 56
        plot_w, plot_h = panel_w - 86, panel_h - 104
        parts.append(f'<line class="axis" x1="{plot_x}" y1="{plot_y + plot_h}" x2="{plot_x + plot_w}" y2="{plot_y + plot_h}"/>')
        for tick in range(5):
            y = plot_y + plot_h - tick * plot_h / 4
            parts.append(f'<line class="grid" x1="{plot_x}" y1="{y:.1f}" x2="{plot_x + plot_w}" y2="{y:.1f}"/>')
            label = max_v * tick / 4
            if max_v > 1000:
                label_text = num(label)
            else:
                label_text = f"{label:.0f}" if label >= 10 else f"{label:.1f}"
            parts.append(f'<text class="small" x="{plot_x - 8}" y="{y + 4:.1f}" text-anchor="end">{esc(label_text)}</text>')
        group_w = plot_w / len(vals)
        bar_w = min(38, group_w / 4)
        for i, (base, final) in enumerate(vals):
            cx = plot_x + i * group_w + group_w / 2
            for j, (value, color, name) in enumerate([(base, PALETTE["gray"], "优化前"), (final, PALETTE["orange"], "优化后")]):
                h = value / max_v * plot_h
                bx = cx + (j - 1) * bar_w * 1.15
                by = plot_y + plot_h - h
                parts.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_w}" height="{h:.1f}" fill="{color}"/>')
                if lower_is_better:
                    value_text = f"{value:.1f}"
                else:
                    value_text = num(value)
                parts.append(f'<text class="small" x="{bx + bar_w / 2:.1f}" y="{by - 5:.1f}" text-anchor="middle">{esc(value_text)}</text>')
            parts.append(f'<text class="label" x="{cx:.1f}" y="{plot_y + plot_h + 24:.1f}" text-anchor="middle">{esc(day_names[i])}</text>')
        parts.append(f'<rect x="{x0 + panel_w - 150}" y="{y0 + 18}" width="12" height="12" fill="{PALETTE["gray"]}"/>')
        parts.append(f'<text class="small" x="{x0 + panel_w - 132}" y="{y0 + 29}">优化前</text>')
        parts.append(f'<rect x="{x0 + panel_w - 82}" y="{y0 + 18}" width="12" height="12" fill="{PALETTE["orange"]}"/>')
        parts.append(f'<text class="small" x="{x0 + panel_w - 64}" y="{y0 + 29}">优化后</text>')
        parts.append(f'<text class="note" x="{x0 + 18}" y="{y0 + panel_h - 16}">单位：{esc(unit)}</text>')
    svg_end(parts, path / "chart.svg")

    table = []
    for day, label in DAYS:
        d = data[day]
        baseline = d["baseline"]
        final = d["final"]
        rules0 = d["rules_by_run"][0]["enabled_rules"]
        rules1 = d["rules_by_run"][d["final_run_id"]]["enabled_rules"]
        table.append(
            [
                label,
                d["final_run_id"],
                f"{num(rules0)} -> {num(rules1)}",
                pct((rules0 - rules1) / rules0),
                f"{us_to_s(baseline['real_rule_time_us']):.2f} -> {us_to_s(final['real_rule_time_us']):.2f}",
                pct((baseline["real_rule_time_us"] - final["real_rule_time_us"]) / baseline["real_rule_time_us"]),
                f"{ms_to_s(baseline['real_runtime_ms']):.2f} -> {ms_to_s(final['real_runtime_ms']):.2f}",
                pct((baseline["real_runtime_ms"] - final["real_runtime_ms"]) / baseline["real_runtime_ms"]),
                f"{pct(baseline['false_positive_rate'])} -> {pct(final['false_positive_rate'])}",
                pp(final["false_positive_rate"] - baseline["false_positive_rate"]),
                f"{pct(baseline['miss_rate'])} -> {pct(final['miss_rate'])}",
                pp(final["miss_rate"] - baseline["miss_rate"]),
            ]
        )
    write_markdown_table(
        path / "summary.md",
        "跨数据集优化汇总表",
        ["数据集", "最终 run", "启用规则", "裁剪比例", "规则耗时/s", "规则耗时下降", "真实流量耗时/s", "真实耗时下降", "误报率", "误报率变化", "漏报率", "漏报率变化"],
        table,
        "优化前为 run 0，优化后为该数据集的最大 committed run。",
    )
    write_readme(path, "跨数据集优化前后核心指标对比", "`chart.svg` 为中文统计图，`summary.md` 为可直接放入论文的结果表。")


def generate_fp_miss_trend(data: dict) -> None:
    path = ensure_dir("06_fp_miss_by_round")
    width, height = 1280, 860
    parts = svg_doc(
        width,
        height,
        "各轮误报率与漏报率变化趋势",
        "橙线表示误报率，蓝线表示漏报率；红色空心点表示该轮被回滚，体现阈值约束机制。",
    )
    panel_w, panel_h = 560, 300
    x_start, y_start, x_gap, y_gap = 70, 116, 70, 70
    for idx, (day, label) in enumerate(DAYS):
        d = data[day]
        runs = d["runs"]
        col, row = idx % 2, idx // 2
        x0 = x_start + col * (panel_w + x_gap)
        y0 = y_start + row * (panel_h + y_gap)
        parts.append(f'<rect x="{x0}" y="{y0}" width="{panel_w}" height="{panel_h}" fill="#ffffff" stroke="{PALETTE["border"]}" stroke-width="1"/>')
        parts.append(f'<text class="panel-title" x="{x0 + 18}" y="{y0 + 30}">{esc(label)}</text>')
        plot_x, plot_y = x0 + 56, y0 + 56
        plot_w, plot_h = panel_w - 86, panel_h - 102
        values_fp = [r["false_positive_rate"] * 100 for r in runs]
        values_miss = [r["miss_rate"] * 100 for r in runs]
        ymax = 100.0
        for tick in range(5):
            y = plot_y + plot_h - tick * plot_h / 4
            parts.append(f'<line class="grid" x1="{plot_x}" y1="{y:.1f}" x2="{plot_x + plot_w}" y2="{y:.1f}"/>')
            parts.append(f'<text class="small" x="{plot_x - 8}" y="{y + 4:.1f}" text-anchor="end">{ymax * tick / 4:.1f}%</text>')
        parts.append(f'<line class="axis" x1="{plot_x}" y1="{plot_y + plot_h}" x2="{plot_x + plot_w}" y2="{plot_y + plot_h}"/>')
        parts.append(polyline(line_points(values_fp, plot_x, plot_y, plot_w, plot_h, ymax), PALETTE["orange"]))
        parts.append(polyline(line_points(values_miss, plot_x, plot_y, plot_w, plot_h, ymax), PALETTE["blue"]))
        for r, (xf, yf), (_, ym) in zip(runs, line_points(values_fp, plot_x, plot_y, plot_w, plot_h, ymax), line_points(values_miss, plot_x, plot_y, plot_w, plot_h, ymax)):
            if r["rolled_back"]:
                parts.append(f'<circle cx="{xf:.1f}" cy="{yf:.1f}" r="5" fill="#fff" stroke="{PALETTE["red"]}" stroke-width="2"/>')
                parts.append(f'<circle cx="{xf:.1f}" cy="{ym:.1f}" r="5" fill="#fff" stroke="{PALETTE["red"]}" stroke-width="2"/>')
        for run_id in [0, 4, 8, 12, 16]:
            x = plot_x + run_id * plot_w / 16
            parts.append(f'<text class="small" x="{x:.1f}" y="{plot_y + plot_h + 22:.1f}" text-anchor="middle">{run_id}</text>')
        parts.append(f'<text class="small" x="{plot_x + plot_w / 2:.1f}" y="{plot_y + plot_h + 42:.1f}" text-anchor="middle">run_id</text>')
        parts.append(f'<rect x="{x0 + panel_w - 170}" y="{y0 + 18}" width="12" height="12" fill="{PALETTE["orange"]}"/>')
        parts.append(f'<text class="small" x="{x0 + panel_w - 152}" y="{y0 + 29}">误报率</text>')
        parts.append(f'<rect x="{x0 + panel_w - 96}" y="{y0 + 18}" width="12" height="12" fill="{PALETTE["blue"]}"/>')
        parts.append(f'<text class="small" x="{x0 + panel_w - 78}" y="{y0 + 29}">漏报率</text>')
    svg_end(parts, path / "chart.svg")

    rows_out = []
    for day, label in DAYS:
        for r in data[day]["runs"]:
            rows_out.append(
                [
                    label,
                    r["run_id"],
                    "提交" if r["committed"] else "回滚",
                    f"{r['factor']:.2f}",
                    pct(r["false_positive_rate"], 4),
                    pct(r["miss_rate"], 4),
                    r["reason"],
                ]
            )
    write_markdown_table(
        path / "run_effect_metrics.md",
        "各轮误报率与漏报率明细",
        ["数据集", "run", "状态", "factor", "误报率", "漏报率", "原因"],
        rows_out,
    )
    write_readme(path, "各轮误报率与漏报率变化趋势", "`chart.svg` 展示各轮检测效果变化，`run_effect_metrics.md` 保存明细数据。")


def generate_rule_time_trend(data: dict) -> None:
    path = ensure_dir("07_rule_time_by_round")
    width, height = 1280, 860
    parts = svg_doc(
        width,
        height,
        "各轮规则匹配耗时变化趋势",
        "规则总耗时来自 real 实例的 profiler 汇总，单位为秒；红色空心点表示该候选轮次被回滚。",
    )
    panel_w, panel_h = 560, 300
    x_start, y_start, x_gap, y_gap = 70, 116, 70, 70
    for idx, (day, label) in enumerate(DAYS):
        d = data[day]
        runs = d["runs"]
        col, row = idx % 2, idx // 2
        x0 = x_start + col * (panel_w + x_gap)
        y0 = y_start + row * (panel_h + y_gap)
        parts.append(f'<rect x="{x0}" y="{y0}" width="{panel_w}" height="{panel_h}" fill="#ffffff" stroke="{PALETTE["border"]}" stroke-width="1"/>')
        parts.append(f'<text class="panel-title" x="{x0 + 18}" y="{y0 + 30}">{esc(label)}</text>')
        plot_x, plot_y = x0 + 64, y0 + 56
        plot_w, plot_h = panel_w - 96, panel_h - 102
        values = [us_to_s(r["real_rule_time_us"]) for r in runs]
        ymax = max(values) * 1.12
        for tick in range(5):
            y = plot_y + plot_h - tick * plot_h / 4
            parts.append(f'<line class="grid" x1="{plot_x}" y1="{y:.1f}" x2="{plot_x + plot_w}" y2="{y:.1f}"/>')
            parts.append(f'<text class="small" x="{plot_x - 8}" y="{y + 4:.1f}" text-anchor="end">{ymax * tick / 4:.1f}</text>')
        parts.append(f'<line class="axis" x1="{plot_x}" y1="{plot_y + plot_h}" x2="{plot_x + plot_w}" y2="{plot_y + plot_h}"/>')
        pts = line_points(values, plot_x, plot_y, plot_w, plot_h, ymax)
        parts.append(polyline(pts, PALETTE["green"], 2.8))
        for r, (x, y) in zip(runs, pts):
            color = PALETTE["red"] if r["rolled_back"] else PALETTE["green"]
            fill = "#fff" if r["rolled_back"] else color
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4.5" fill="{fill}" stroke="{color}" stroke-width="2"/>')
        for run_id in [0, 4, 8, 12, 16]:
            x = plot_x + run_id * plot_w / 16
            parts.append(f'<text class="small" x="{x:.1f}" y="{plot_y + plot_h + 22:.1f}" text-anchor="middle">{run_id}</text>')
        parts.append(f'<text class="small" x="{plot_x + plot_w / 2:.1f}" y="{plot_y + plot_h + 42:.1f}" text-anchor="middle">run_id</text>')
        b = us_to_s(d["baseline"]["real_rule_time_us"])
        f = us_to_s(d["final"]["real_rule_time_us"])
        drop = (b - f) / b
        parts.append(f'<text class="value" x="{x0 + panel_w - 190}" y="{y0 + 30}">最终下降 {esc(pct(drop))}</text>')
    svg_end(parts, path / "chart.svg")

    rows_out = []
    for day, label in DAYS:
        for r in data[day]["runs"]:
            rows_out.append(
                [
                    label,
                    r["run_id"],
                    "提交" if r["committed"] else "回滚",
                    f"{us_to_s(r['real_rule_time_us']):.3f}",
                    f"{ms_to_s(r['real_runtime_ms']):.3f}",
                    f"{r['real_avg_cpu']:.2f}%",
                    f"{r['real_avg_mem_mb']:.2f}",
                ]
            )
    write_markdown_table(
        path / "run_performance_metrics.md",
        "各轮性能指标明细",
        ["数据集", "run", "状态", "规则耗时/s", "真实流量运行时间/s", "CPU 均值", "内存均值/MB"],
        rows_out,
    )
    write_readme(path, "各轮规则匹配耗时变化趋势", "`chart.svg` 展示 profiler 规则耗时下降过程，`run_performance_metrics.md` 保存明细数据。")


def generate_rule_count_reduction(data: dict) -> None:
    path = ensure_dir("08_rule_count_reduction")
    width, height = 1180, 620
    parts = svg_doc(
        width,
        height,
        "最终规则集启用与裁剪数量",
        "总规则数保持 47068 条；橙色部分为最终规则集中被裁剪/禁用的规则。",
    )
    plot_x, plot_y = 210, 120
    plot_w, row_h = 850, 72
    max_total = max(data[day]["rules_by_run"][0]["total_rules"] for day, _ in DAYS)
    for idx, (day, label) in enumerate(DAYS):
        d = data[day]
        final_rules = d["rules_by_run"][d["final_run_id"]]
        enabled = final_rules["enabled_rules"]
        disabled = final_rules["disabled_rules"]
        total = final_rules["total_rules"]
        y = plot_y + idx * row_h
        parts.append(f'<text class="label" x="{plot_x - 18}" y="{y + 28}" text-anchor="end">{esc(label)}</text>')
        enabled_w = enabled / max_total * plot_w
        disabled_w = disabled / max_total * plot_w
        parts.append(f'<rect x="{plot_x}" y="{y}" width="{plot_w}" height="34" fill="#ffffff" stroke="{PALETTE["border"]}" stroke-width="1"/>')
        parts.append(f'<rect x="{plot_x}" y="{y}" width="{enabled_w:.1f}" height="34" fill="{PALETTE["green"]}"/>')
        parts.append(f'<rect x="{plot_x + enabled_w:.1f}" y="{y}" width="{disabled_w:.1f}" height="34" fill="{PALETTE["orange"]}"/>')
        parts.append(f'<text class="value" x="{plot_x + 10}" y="{y + 23}">启用 {num(enabled)}</text>')
        parts.append(f'<text class="value" x="{plot_x + enabled_w + disabled_w - 10:.1f}" y="{y + 23}" text-anchor="end">裁剪 {num(disabled)}</text>')
        parts.append(f'<text class="small" x="{plot_x + plot_w + 18}" y="{y + 22}">裁剪比例 {pct(disabled / total)}</text>')
    legend_y = plot_y + len(DAYS) * row_h + 22
    parts.append(f'<rect x="{plot_x}" y="{legend_y}" width="14" height="14" fill="{PALETTE["green"]}"/>')
    parts.append(f'<text class="small" x="{plot_x + 22}" y="{legend_y + 12}">最终启用规则</text>')
    parts.append(f'<rect x="{plot_x + 130}" y="{legend_y}" width="14" height="14" fill="{PALETTE["orange"]}"/>')
    parts.append(f'<text class="small" x="{plot_x + 152}" y="{legend_y + 12}">最终裁剪规则</text>')
    svg_end(parts, path / "chart.svg")

    rows_out = []
    for day, label in DAYS:
        d = data[day]
        r0 = d["rules_by_run"][0]
        rf = d["rules_by_run"][d["final_run_id"]]
        rows_out.append([label, r0["total_rules"], r0["enabled_rules"], d["final_run_id"], rf["enabled_rules"], rf["disabled_rules"], pct(rf["disabled_rules"] / rf["total_rules"])])
    write_markdown_table(
        path / "rule_counts.md",
        "规则数量变化明细",
        ["数据集", "总规则数", "优化前启用", "最终 run", "最终启用", "最终裁剪", "裁剪比例"],
        rows_out,
    )
    write_readme(path, "最终规则集启用与裁剪数量", "`chart.svg` 展示最终规则数量结构，`rule_counts.md` 保存明细数据。")


def generate_strategy_contribution(data: dict) -> None:
    path = ensure_dir("09_strategy_contribution")
    width, height = 1380, 720
    parts = svg_doc(
        width,
        height,
        "各裁剪策略的提交贡献",
        "统计 committed=1 的 trim_decisions。SAFE 策略贡献主要来自静态低风险裁剪，ITER 策略体现基于反馈评估的逐轮优化。",
    )
    strategy_colors = {
        "safe_source_file_browser": PALETTE["safe1"],
        "safe_source_file_protocols": PALETTE["safe2"],
        "safe_inactive_systemd_services": PALETTE["safe3"],
        "safe_orphan_flowbits": PALETTE["safe4"],
        "iter_protocol_alert_overlap": PALETTE["iter1"],
        "iter_high_fp_low_utilization": PALETTE["iter2"],
        "iter_low_yield_hot_rules": PALETTE["iter3"],
        "iter_high_cost_rules": PALETTE["iter4"],
    }
    plot_x, plot_y = 210, 122
    plot_w, row_h = 900, 78
    counts_by_day = {day: strategy_counts(data[day]["decisions"], committed=1) for day, _ in DAYS}
    max_total = max(sum(c.values()) for c in counts_by_day.values())
    for idx, (day, label) in enumerate(DAYS):
        counter = counts_by_day[day]
        total = sum(counter.values())
        y = plot_y + idx * row_h
        parts.append(f'<text class="label" x="{plot_x - 18}" y="{y + 30}" text-anchor="end">{esc(label)}</text>')
        x = plot_x
        for strategy in STRATEGY_ORDER:
            count = counter[strategy]
            if count == 0:
                continue
            w = count / max_total * plot_w
            parts.append(f'<rect x="{x:.1f}" y="{y}" width="{w:.1f}" height="36" fill="{strategy_colors[strategy]}"/>')
            if w > 44:
                parts.append(f'<text class="small" x="{x + w / 2:.1f}" y="{y + 24}" text-anchor="middle" style="fill:#ffffff">{num(count)}</text>')
            x += w
        parts.append(f'<text class="small" x="{plot_x + plot_w + 20}" y="{y + 24}">合计 {num(total)}</text>')
    lx, ly = plot_x, plot_y + len(DAYS) * row_h + 30
    for i, strategy in enumerate(STRATEGY_ORDER):
        if all(counts_by_day[day][strategy] == 0 for day, _ in DAYS):
            continue
        cx = lx + (i % 4) * 285
        cy = ly + (i // 4) * 28
        parts.append(f'<rect x="{cx}" y="{cy}" width="14" height="14" fill="{strategy_colors[strategy]}"/>')
        parts.append(f'<text class="small" x="{cx + 22}" y="{cy + 12}">{esc(STRATEGY_LABELS[strategy])}</text>')
    svg_end(parts, path / "chart.svg")

    rows_out = []
    for day, label in DAYS:
        counter = counts_by_day[day]
        rollback_counter = strategy_counts(data[day]["decisions"], committed=0)
        for strategy in STRATEGY_ORDER:
            if counter[strategy] == 0 and rollback_counter[strategy] == 0:
                continue
            rows_out.append([label, STRATEGY_LABELS[strategy], counter[strategy], rollback_counter[strategy]])
    write_markdown_table(
        path / "strategy_contribution.md",
        "各策略裁剪贡献明细",
        ["数据集", "策略", "提交裁剪数", "回滚裁剪数"],
        rows_out,
    )
    write_readme(path, "各裁剪策略的提交贡献", "`chart.svg` 展示各策略提交贡献，`strategy_contribution.md` 保存提交与回滚数量。")


def generate_commit_rollback_timeline(data: dict) -> None:
    path = ensure_dir("10_commit_rollback_timeline")
    width, height = 1280, 620
    parts = svg_doc(
        width,
        height,
        "各数据集提交与回滚轮次",
        "绿色实心点为提交轮次，红色空心点为回滚轮次。回滚通常来自漏报率增量超过阈值，随后 factor 减小。",
    )
    x0, y0 = 130, 136
    plot_w, row_h = 1010, 86
    for run_id in range(17):
        x = x0 + run_id * plot_w / 16
        parts.append(f'<line class="grid" x1="{x:.1f}" y1="{y0 - 20}" x2="{x:.1f}" y2="{y0 + row_h * 3 + 28}"/>')
        parts.append(f'<text class="small" x="{x:.1f}" y="{y0 - 34}" text-anchor="middle">{run_id}</text>')
    for idx, (day, label) in enumerate(DAYS):
        y = y0 + idx * row_h
        parts.append(f'<text class="label" x="{x0 - 18}" y="{y + 5}" text-anchor="end">{esc(label)}</text>')
        parts.append(f'<line class="axis" x1="{x0}" y1="{y}" x2="{x0 + plot_w}" y2="{y}"/>')
        for r in data[day]["runs"]:
            x = x0 + r["run_id"] * plot_w / 16
            if r["rolled_back"]:
                parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9" fill="#fff" stroke="{PALETTE["red"]}" stroke-width="2.5"/>')
                parts.append(f'<text class="small" x="{x:.1f}" y="{y + 28:.1f}" text-anchor="middle">{r["factor"]:.1f}</text>')
            else:
                parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{PALETTE["green"]}" stroke="{PALETTE["green"]}" stroke-width="2"/>')
    legend_y = y0 + row_h * 4 + 14
    parts.append(f'<circle cx="{x0}" cy="{legend_y}" r="8" fill="{PALETTE["green"]}" stroke="{PALETTE["green"]}" stroke-width="2"/>')
    parts.append(f'<text class="small" x="{x0 + 18}" y="{legend_y + 5}">提交</text>')
    parts.append(f'<circle cx="{x0 + 78}" cy="{legend_y}" r="9" fill="#fff" stroke="{PALETTE["red"]}" stroke-width="2.5"/>')
    parts.append(f'<text class="small" x="{x0 + 98}" y="{legend_y + 5}">回滚，点下方为 factor</text>')
    svg_end(parts, path / "chart.svg")

    rows_out = []
    for day, label in DAYS:
        for r in data[day]["runs"]:
            if r["rolled_back"] or r["run_id"] in (0, data[day]["final_run_id"]):
                rows_out.append([label, r["run_id"], "回滚" if r["rolled_back"] else "提交", f"{r['factor']:.2f}", r["reason"]])
    write_markdown_table(
        path / "rollback_key_runs.md",
        "关键提交与回滚轮次",
        ["数据集", "run", "状态", "factor", "原因"],
        rows_out,
    )
    write_readme(path, "各数据集提交与回滚轮次", "`chart.svg` 展示轮次状态，`rollback_key_runs.md` 保存关键轮次说明。")


def compact_reason(value: str, max_len: int = 80) -> str:
    value = " ".join(str(value or "").split())
    return value if len(value) <= max_len else value[: max_len - 1] + "…"


def generate_top_rule_tables(data: dict) -> None:
    path = ensure_dir("11_top_trimmed_rules")
    records_by_strategy: dict[str, dict[tuple[int, int, int], dict]] = defaultdict(dict)
    day_order = {label.replace("实验流量", ""): index for index, (_, label) in enumerate(DAYS)}
    for day, label in DAYS:
        for item in data[day]["decisions"]:
            if item["committed"] != 1:
                continue
            strategies = [name.strip() for name in item["functions"].split(",") if name.strip()]
            for strategy in strategies:
                key = (item["gid"], item["sid"], item["rev"])
                record = records_by_strategy[strategy].setdefault(
                    key,
                    {
                        "gid": item["gid"],
                        "sid": item["sid"],
                        "rev": item["rev"],
                        "msg": item["msg"] or "",
                        "source_file": item["source_file"] or "",
                        "reasons": set(),
                        "days": set(),
                    },
                )
                record["days"].add(label.replace("实验流量", ""))
                record["reasons"].add(item["reasons"])

    lines = ["# 典型裁剪规则表", "", "每个策略列出最多 5 条在多个数据集中出现优先的 committed 规则。", ""]
    for strategy in STRATEGY_ORDER:
        records = list(records_by_strategy.get(strategy, {}).values())
        if not records:
            continue
        records.sort(key=lambda r: (-len(r["days"]), r["source_file"], r["sid"]))
        lines.append(f"## {STRATEGY_LABELS[strategy]}")
        lines.append("")
        lines.append("| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for record in records[:5]:
            reason_sample = compact_reason(sorted(record["reasons"])[0], 110)
            day_names = sorted(record["days"], key=lambda name: day_order.get(name, 99))
            lines.append(
                "| "
                + " | ".join(
                    [
                        f"{record['gid']}:{record['sid']} rev {record['rev']}",
                        "、".join(day_names),
                        record["source_file"],
                        compact_reason(record["msg"], 110),
                        reason_sample,
                    ]
                )
                + " |"
            )
        lines.append("")
    (path / "top_trimmed_rules.md").write_text("\n".join(lines), encoding="utf-8")

    # Extra table: top false-positive rules in baseline, useful for explaining high-FP strategy.
    fp_lines = ["# baseline 高误报规则示例", "", "| 数据集 | 规则 | fp_rate | utilization | alerted_flows | msg |", "| --- | --- | --- | --- | --- | --- |"]
    for day, label in DAYS:
        baseline_rows = [r for r in data[day]["rule_fp"] if r["run_id"] == 0 and r["alerted_flows"] > 0]
        baseline_rows.sort(key=lambda r: (-r["fp_rate"], r["utilization"], -r["alerted_flows"]))
        for r in baseline_rows[:5]:
            fp_lines.append(
                f"| {label} | {r['gid']}:{r['sid']} | {pct(r['fp_rate'])} | {pct(r['utilization'])} | {num(r['alerted_flows'])} | {compact_reason(r['msg'], 100)} |"
            )
    (path / "baseline_high_fp_rules.md").write_text("\n".join(fp_lines) + "\n", encoding="utf-8")
    write_readme(path, "典型裁剪规则表", "`top_trimmed_rules.md` 按策略列出典型裁剪规则，`baseline_high_fp_rules.md` 列出 baseline 高误报规则示例。")


def generate_index(data: dict) -> None:
    entries = [
        ("01_system_architecture_mermaid", "系统总体架构图", "Mermaid"),
        ("02_three_instance_model_mermaid", "三实例评估模型图", "Mermaid"),
        ("03_trim_scheduler_flow_mermaid", "规则裁剪提交与回滚流程图", "Mermaid"),
        ("04_core_data_model_mermaid", "核心数据表关系图", "Mermaid"),
        ("05_cross_dataset_summary", "跨数据集优化前后核心指标对比", "SVG + Markdown"),
        ("06_fp_miss_by_round", "各轮误报率与漏报率变化趋势", "SVG + Markdown"),
        ("07_rule_time_by_round", "各轮规则匹配耗时变化趋势", "SVG + Markdown"),
        ("08_rule_count_reduction", "最终规则集启用与裁剪数量", "SVG + Markdown"),
        ("09_strategy_contribution", "各裁剪策略的提交贡献", "SVG + Markdown"),
        ("10_commit_rollback_timeline", "各数据集提交与回滚轮次", "SVG + Markdown"),
        ("11_top_trimmed_rules", "典型裁剪规则表", "Markdown"),
        ("12_core_class_diagram_mermaid", "核心类与数据结构图", "Mermaid"),
        ("13_strategy_plugin_detail_mermaid", "策略插件注册与调用图", "Mermaid"),
    ]
    lines = ["# Snort 性能优化论文图表", "", "所有图片标题、坐标轴、图例和说明均使用中文；SVG 采用白色背景、直角边框和低饱和论文风格配色。", ""]
    lines.append("| 目录 | 图表 | 文件类型 |")
    lines.append("| --- | --- | --- |")
    for dirname, title, kind in entries:
        lines.append(f"| `{dirname}` | {title} | {kind} |")
    lines.append("")
    lines.append("## 数据来源")
    lines.append("")
    for day, label in DAYS:
        final = data[day]["final_run_id"]
        lines.append(f"- {label}：`analyser/cmd/analyser_result/{day}_result`，最终 committed run 为 `{final}`。")
    lines.append("- Monday 作为 real 实例的真实/基准流量，用于规则性能画像。")
    lines.append("")
    lines.append("## 重新生成")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 misc/images/generate_figures.py")
    lines.append("```")
    lines.append("")
    (OUT_ROOT / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    data = collect_data()
    generate_mermaid()
    generate_cross_dataset_summary(data)
    generate_fp_miss_trend(data)
    generate_rule_time_trend(data)
    generate_rule_count_reduction(data)
    generate_strategy_contribution(data)
    generate_commit_rollback_timeline(data)
    generate_top_rule_tables(data)
    generate_index(data)
    print(f"generated figures under {OUT_ROOT}")


if __name__ == "__main__":
    main()
