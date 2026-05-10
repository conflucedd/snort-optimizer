# Snort 性能优化论文图表

所有坐标轴、图例和说明均使用中文；SVG 采用白色背景、直角边框和低饱和论文风格配色。

| 目录 | 图表 | 文件类型 |
| --- | --- | --- |
| `01_system_architecture_mermaid` | 系统总体架构图 | Mermaid |
| `02_three_instance_model_mermaid` | 三实例评估模型图 | Mermaid |
| `03_trim_scheduler_flow_mermaid` | 规则裁剪提交与回滚流程图 | Mermaid |
| `04_core_data_model_mermaid` | 核心数据表关系图 | Mermaid |
| `05_cross_dataset_summary` | 跨数据集优化前后核心指标对比 | SVG + Markdown |
| `06_fp_miss_by_round` | 各轮误报率与漏报率变化趋势 | SVG + Markdown |
| `07_rule_time_by_round` | 各轮规则匹配耗时变化趋势 | SVG + Markdown |
| `08_rule_count_reduction` | 最终规则集启用与裁剪数量 | SVG + Markdown |
| `09_strategy_contribution` | 各裁剪策略的提交贡献 | SVG + Markdown |
| `10_commit_rollback_timeline` | 各数据集提交与回滚轮次 | SVG + Markdown |
| `11_top_trimmed_rules` | 典型裁剪规则表 | Markdown |
| `12_core_class_diagram_mermaid` | 核心类与数据结构图 | Mermaid |
| `13_strategy_plugin_detail_mermaid` | 策略插件注册与调用图 | Mermaid |

## 数据来源

- 周二实验流量：`analyser/cmd/analyser_result/Tuesday_result`，最终 committed run 为 `15`。
- 周三实验流量：`analyser/cmd/analyser_result/Wednesday_result`，最终 committed run 为 `12`。
- 周四实验流量：`analyser/cmd/analyser_result/Thursday_result`，最终 committed run 为 `16`。
- 周五实验流量：`analyser/cmd/analyser_result/Friday_result`，最终 committed run 为 `16`。
- Monday 作为 real 实例的真实/基准流量，用于规则性能画像。

## 重新生成

```bash
python3 misc/images/generate_figures.py
```
