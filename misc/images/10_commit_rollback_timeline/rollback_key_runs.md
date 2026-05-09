# 关键提交与回滚轮次

| 数据集 | run | 状态 | factor | 原因 |
| --- | --- | --- | --- | --- |
| 周二实验流量 | 0 | 提交 | 0.80 | baseline run |
| 周二实验流量 | 13 | 回滚 | 0.80 | iter_high_cost_rules: rollback: miss_rate_delta 0.369908 exceeds 0.010000 |
| 周二实验流量 | 14 | 回滚 | 0.40 | iter_high_cost_rules: rollback: miss_rate_delta 0.369908 exceeds 0.010000 |
| 周二实验流量 | 15 | 提交 | 0.20 | iter_high_cost_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000009 |
| 周二实验流量 | 16 | 回滚 | 0.20 | iter_high_cost_rules: rollback: miss_rate_delta 0.369908 exceeds 0.010000 |
| 周三实验流量 | 0 | 提交 | 0.80 | baseline run |
| 周三实验流量 | 12 | 提交 | 0.80 | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000004 |
| 周三实验流量 | 13 | 回滚 | 0.80 | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周三实验流量 | 14 | 回滚 | 0.40 | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周三实验流量 | 15 | 回滚 | 0.20 | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周三实验流量 | 16 | 回滚 | 0.10 | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周四实验流量 | 0 | 提交 | 0.80 | baseline run |
| 周四实验流量 | 16 | 提交 | 0.80 | iter_high_cost_rules: commit: miss_rate_delta 0.000027 false_positive_rate_delta -0.000006 |
| 周五实验流量 | 0 | 提交 | 0.80 | baseline run |
| 周五实验流量 | 16 | 提交 | 0.80 | iter_high_cost_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000004 |
