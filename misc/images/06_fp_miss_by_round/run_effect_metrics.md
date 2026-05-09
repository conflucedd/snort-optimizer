# 各轮误报率与漏报率明细

| 数据集 | run | 状态 | factor | 误报率 | 漏报率 | 原因 |
| --- | --- | --- | --- | --- | --- | --- |
| 周二实验流量 | 0 | 提交 | 0.80 | 9.4406% | 0.3012% | baseline run |
| 周二实验流量 | 1 | 提交 | 1.00 | 9.4219% | 0.3012% | SAFE functions are committed directly |
| 周二实验流量 | 2 | 提交 | 0.80 | 9.4223% | 0.3012% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000003 |
| 周二实验流量 | 3 | 提交 | 0.80 | 9.4682% | 0.3012% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000460 |
| 周二实验流量 | 4 | 提交 | 0.80 | 9.4496% | 0.3012% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000186 |
| 周二实验流量 | 5 | 提交 | 0.80 | 0.4989% | 0.3012% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.089506 |
| 周二实验流量 | 6 | 提交 | 0.80 | 0.2471% | 0.3012% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.002518 |
| 周二实验流量 | 7 | 提交 | 0.80 | 0.1972% | 0.3012% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000500 |
| 周二实验流量 | 8 | 提交 | 0.80 | 0.1764% | 0.3012% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000208 |
| 周二实验流量 | 9 | 提交 | 0.80 | 0.1764% | 0.3012% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000000 |
| 周二实验流量 | 10 | 提交 | 0.80 | 0.1754% | 0.3012% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000009 |
| 周二实验流量 | 11 | 提交 | 0.80 | 0.1745% | 0.3012% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000009 |
| 周二实验流量 | 12 | 提交 | 0.80 | 0.1742% | 0.3012% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000003 |
| 周二实验流量 | 13 | 回滚 | 0.80 | 0.0202% | 37.2920% | iter_high_cost_rules: rollback: miss_rate_delta 0.369908 exceeds 0.010000 |
| 周二实验流量 | 14 | 回滚 | 0.40 | 0.0205% | 37.2920% | iter_high_cost_rules: rollback: miss_rate_delta 0.369908 exceeds 0.010000 |
| 周二实验流量 | 15 | 提交 | 0.20 | 0.1732% | 0.3012% | iter_high_cost_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000009 |
| 周二实验流量 | 16 | 回滚 | 0.20 | 0.0205% | 37.2920% | iter_high_cost_rules: rollback: miss_rate_delta 0.369908 exceeds 0.010000 |
| 周三实验流量 | 0 | 提交 | 0.80 | 6.5568% | 22.6852% | baseline run |
| 周三实验流量 | 1 | 提交 | 1.00 | 6.5395% | 22.6852% | SAFE functions are committed directly |
| 周三实验流量 | 2 | 提交 | 0.80 | 6.5458% | 22.6852% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000062 |
| 周三实验流量 | 3 | 提交 | 0.80 | 6.5432% | 22.6852% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000026 |
| 周三实验流量 | 4 | 提交 | 0.80 | 6.5307% | 22.6852% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000125 |
| 周三实验流量 | 5 | 提交 | 0.80 | 0.2050% | 22.6852% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.063257 |
| 周三实验流量 | 6 | 提交 | 0.80 | 0.0608% | 22.6852% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.001442 |
| 周三实验流量 | 7 | 提交 | 0.80 | 0.0399% | 22.6852% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000209 |
| 周三实验流量 | 8 | 提交 | 0.80 | 0.0312% | 22.6852% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000087 |
| 周三实验流量 | 9 | 提交 | 0.80 | 0.0314% | 22.6852% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000002 |
| 周三实验流量 | 10 | 提交 | 0.80 | 0.0314% | 22.6852% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000000 |
| 周三实验流量 | 11 | 提交 | 0.80 | 0.0310% | 22.6852% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000004 |
| 周三实验流量 | 12 | 提交 | 0.80 | 0.0306% | 22.6852% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000004 |
| 周三实验流量 | 13 | 回滚 | 0.80 | 0.0224% | 60.4160% | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周三实验流量 | 14 | 回滚 | 0.40 | 0.0234% | 60.4160% | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周三实验流量 | 15 | 回滚 | 0.20 | 0.0234% | 60.4160% | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周三实验流量 | 16 | 回滚 | 0.10 | 0.0232% | 60.4160% | iter_high_cost_rules: rollback: miss_rate_delta 0.377307 exceeds 0.010000 |
| 周四实验流量 | 0 | 提交 | 0.80 | 8.3455% | 98.6537% | baseline run |
| 周四实验流量 | 1 | 提交 | 1.00 | 8.3333% | 98.8499% | SAFE functions are committed directly |
| 周四实验流量 | 2 | 提交 | 0.80 | 8.3259% | 98.8499% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000075 |
| 周四实验流量 | 3 | 提交 | 0.80 | 8.3311% | 98.8499% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000052 |
| 周四实验流量 | 4 | 提交 | 0.80 | 8.2996% | 98.8499% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000315 |
| 周四实验流量 | 5 | 提交 | 0.80 | 0.6916% | 98.8499% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.076081 |
| 周四实验流量 | 6 | 提交 | 0.80 | 0.5982% | 98.8499% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000934 |
| 周四实验流量 | 7 | 提交 | 0.80 | 0.5684% | 98.8499% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000298 |
| 周四实验流量 | 8 | 提交 | 0.80 | 0.5557% | 98.8499% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000127 |
| 周四实验流量 | 9 | 提交 | 0.80 | 0.5554% | 98.8499% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000003 |
| 周四实验流量 | 10 | 提交 | 0.80 | 0.5554% | 98.8499% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000000 |
| 周四实验流量 | 11 | 提交 | 0.80 | 0.5543% | 98.8499% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000011 |
| 周四实验流量 | 12 | 提交 | 0.80 | 0.5538% | 98.8499% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000006 |
| 周四实验流量 | 13 | 提交 | 0.80 | 0.1207% | 99.2463% | iter_high_cost_rules: commit: miss_rate_delta 0.003965 false_positive_rate_delta -0.004331 |
| 周四实验流量 | 14 | 提交 | 0.80 | 0.1199% | 99.3234% | iter_high_cost_rules: commit: miss_rate_delta 0.000771 false_positive_rate_delta -0.000008 |
| 周四实验流量 | 15 | 提交 | 0.80 | 0.0188% | 99.6956% | iter_high_cost_rules: commit: miss_rate_delta 0.003721 false_positive_rate_delta -0.001011 |
| 周四实验流量 | 16 | 提交 | 0.80 | 0.0182% | 99.6983% | iter_high_cost_rules: commit: miss_rate_delta 0.000027 false_positive_rate_delta -0.000006 |
| 周五实验流量 | 0 | 提交 | 0.80 | 6.1822% | 99.5753% | baseline run |
| 周五实验流量 | 1 | 提交 | 1.00 | 6.1703% | 99.6977% | SAFE functions are committed directly |
| 周五实验流量 | 2 | 提交 | 0.80 | 6.1690% | 99.6977% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000013 |
| 周五实验流量 | 3 | 提交 | 0.80 | 6.1678% | 99.6977% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000013 |
| 周五实验流量 | 4 | 提交 | 0.80 | 6.1533% | 99.6977% | iter_protocol_alert_overlap: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000144 |
| 周五实验流量 | 5 | 提交 | 0.80 | 0.1961% | 99.6977% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.059572 |
| 周五实验流量 | 6 | 提交 | 0.80 | 0.1156% | 99.6977% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000805 |
| 周五实验流量 | 7 | 提交 | 0.80 | 0.0889% | 99.6977% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000267 |
| 周五实验流量 | 8 | 提交 | 0.80 | 0.0789% | 99.6977% | iter_high_fp_low_utilization: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000100 |
| 周五实验流量 | 9 | 提交 | 0.80 | 0.0783% | 99.6977% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000005 |
| 周五实验流量 | 10 | 提交 | 0.80 | 0.0773% | 99.6977% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000011 |
| 周五实验流量 | 11 | 提交 | 0.80 | 0.0771% | 99.6977% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000002 |
| 周五实验流量 | 12 | 提交 | 0.80 | 0.0771% | 99.6977% | iter_low_yield_hot_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta 0.000000 |
| 周五实验流量 | 13 | 提交 | 0.80 | 0.0727% | 99.9649% | iter_high_cost_rules: commit: miss_rate_delta 0.002672 false_positive_rate_delta -0.000044 |
| 周五实验流量 | 14 | 提交 | 0.80 | 0.0718% | 99.9649% | iter_high_cost_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000009 |
| 周五实验流量 | 15 | 提交 | 0.80 | 0.0099% | 99.9792% | iter_high_cost_rules: commit: miss_rate_delta 0.000143 false_positive_rate_delta -0.000619 |
| 周五实验流量 | 16 | 提交 | 0.80 | 0.0095% | 99.9792% | iter_high_cost_rules: commit: miss_rate_delta 0.000000 false_positive_rate_delta -0.000004 |
