# baseline 高误报规则示例

| 数据集 | 规则 | fp_rate | utilization | alerted_flows | msg |
| --- | --- | --- | --- | --- | --- |
| 周二实验流量 | 1:254 | 100.00% | 0.00% | 18,777 | PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority |
| 周二实验流量 | 1:15935 | 100.00% | 0.00% | 2,750 | PROTOCOL-DNS dns response for rfc1918 192.168/16 address detected |
| 周二实验流量 | 1:27938 | 100.00% | 0.00% | 2,371 | PROTOCOL-DNS IPv6 host name enumeration |
| 周二实验流量 | 1:29957 | 100.00% | 0.00% | 1,548 | SERVER-OTHER Kolibri HTTP Server uri buffer overflow attempt |
| 周二实验流量 | 1:41807 | 100.00% | 0.00% | 968 | POLICY-OTHER SSLv3 Client Hello attempt |
| 周三实验流量 | 1:254 | 100.00% | 0.00% | 18,637 | PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority |
| 周三实验流量 | 1:27938 | 100.00% | 0.00% | 5,548 | PROTOCOL-DNS IPv6 host name enumeration |
| 周三实验流量 | 1:15935 | 100.00% | 0.00% | 2,357 | PROTOCOL-DNS dns response for rfc1918 192.168/16 address detected |
| 周三实验流量 | 1:41807 | 100.00% | 0.00% | 1,209 | POLICY-OTHER SSLv3 Client Hello attempt |
| 周三实验流量 | 1:29957 | 100.00% | 0.00% | 1,162 | SERVER-OTHER Kolibri HTTP Server uri buffer overflow attempt |
| 周四实验流量 | 1:254 | 100.00% | 0.00% | 17,150 | PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority |
| 周四实验流量 | 1:27938 | 100.00% | 0.00% | 5,450 | PROTOCOL-DNS IPv6 host name enumeration |
| 周四实验流量 | 1:15935 | 100.00% | 0.00% | 1,713 | PROTOCOL-DNS dns response for rfc1918 192.168/16 address detected |
| 周四实验流量 | 1:29957 | 100.00% | 0.00% | 1,275 | SERVER-OTHER Kolibri HTTP Server uri buffer overflow attempt |
| 周四实验流量 | 1:57756 | 100.00% | 0.00% | 730 | MALWARE-CNC DNS Fast Flux attempt |
| 周五实验流量 | 1:254 | 100.00% | 0.00% | 17,504 | PROTOCOL-DNS SPOOF query response with TTL of 1 min. and no authority |
| 周五实验流量 | 1:27938 | 100.00% | 0.00% | 7,819 | PROTOCOL-DNS IPv6 host name enumeration |
| 周五实验流量 | 1:15935 | 100.00% | 0.00% | 2,398 | PROTOCOL-DNS dns response for rfc1918 192.168/16 address detected |
| 周五实验流量 | 1:29957 | 100.00% | 0.00% | 1,270 | SERVER-OTHER Kolibri HTTP Server uri buffer overflow attempt |
| 周五实验流量 | 1:41807 | 100.00% | 0.00% | 1,011 | POLICY-OTHER SSLv3 Client Hello attempt |
