# 典型裁剪规则表

每个策略列出最多 5 条在多个数据集中出现优先的 committed 规则。

## 浏览器/文件类 SAFE

| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |
| --- | --- | --- | --- | --- |
| 1:16667 rev 13 | 周二、周三、周四、周五 | snort3-browser-chrome.rules | BROWSER-CHROME Google Chrome GURL cross origin bypass attempt | source_file "snort3-browser-chrome.rules" is in file/browser rule category |
| 1:16668 rev 12 | 周二、周三、周四、周五 | snort3-browser-chrome.rules | BROWSER-CHROME Google Chrome GURL cross origin bypass attempt | source_file "snort3-browser-chrome.rules" is in file/browser rule category |
| 1:16795 rev 5 | 周二、周三、周四、周五 | snort3-browser-chrome.rules | BROWSER-CHROME Google Chrome FTP handling out-of-bounds array index denial of service attempt | source_file "snort3-browser-chrome.rules" is in file/browser rule category |
| 1:19005 rev 9 | 周二、周三、周四、周五 | snort3-browser-chrome.rules | BROWSER-CHROME Apple Safari/Google Chrome Webkit memory corruption attempt | source_file "snort3-browser-chrome.rules" is in file/browser rule category |
| 1:19216 rev 15 | 周二、周三、周四、周五 | snort3-browser-chrome.rules | BROWSER-CHROME Google Chrome Uninitialized bug_report Pointer Code Execution | source_file "snort3-browser-chrome.rules" is in file/browser rule category |

## 不常用协议 SAFE

| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |
| --- | --- | --- | --- | --- |
| 1:529 rev 16 | 周二、周三、周四、周五 | snort3-netbios.rules | NETBIOS DCERPC NCACN-IP-TCP srvsvc NetrShareEnum null policy handle attempt | source_file "snort3-netbios.rules" is disabled by server profile: netbios is normally a LAN/gateway exposure,… |
| 1:534 rev 9 | 周二、周三、周四、周五 | snort3-netbios.rules | NETBIOS SMB CD.. | source_file "snort3-netbios.rules" is disabled by server profile: netbios is normally a LAN/gateway exposure,… |
| 1:535 rev 9 | 周二、周三、周四、周五 | snort3-netbios.rules | NETBIOS SMB CD... | source_file "snort3-netbios.rules" is disabled by server profile: netbios is normally a LAN/gateway exposure,… |
| 1:2103 rev 17 | 周二、周三、周四、周五 | snort3-netbios.rules | NETBIOS SMB Trans2 OPEN2 unicode maximum param count overflow attempt | source_file "snort3-netbios.rules" is disabled by server profile: netbios is normally a LAN/gateway exposure,… |
| 1:2190 rev 6 | 周二、周三、周四、周五 | snort3-netbios.rules | NETBIOS DCERPC invalid bind attempt | source_file "snort3-netbios.rules" is disabled by server profile: netbios is normally a LAN/gateway exposure,… |

## 协议覆盖 ITER

| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |
| --- | --- | --- | --- | --- |
| 1:14777 rev 5 | 周二、周三、周四、周五 | snort3-protocol-dns.rules | PROTOCOL-DNS single byte encoded name response | protocol group "snort3-protocol-dns.rules" has concentrated alert coverage; trimming lower-coverage rule outs… |
| 1:57878 rev 1 | 周二、周三、周四、周五 | snort3-protocol-dns.rules | PROTOCOL-DNS Microsoft Threat Management Gateway heap buffer overflow attempt | protocol group "snort3-protocol-dns.rules" has concentrated alert coverage; trimming lower-coverage rule outs… |
| 1:24304 rev 3 | 周三、周四、周五 | snort3-protocol-dns.rules | PROTOCOL-DNS dead alive6 DNS attempt | protocol group "snort3-protocol-dns.rules" has concentrated alert coverage; trimming lower-coverage rule outs… |
| 1:17484 rev 10 | 周二 | snort3-protocol-dns.rules | PROTOCOL-DNS squid proxy dns PTR record response denial of service attempt | protocol group "snort3-protocol-dns.rules" has concentrated alert coverage; trimming lower-coverage rule outs… |

## 高误报低利用率 ITER

| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |
| --- | --- | --- | --- | --- |
| 1:1201 rev 13 | 周二、周三、周四、周五 | snort3-indicator-compromise.rules | INDICATOR-COMPROMISE 403 Forbidden | high rule false-positive rate and low malicious utilization: rule_fp_rate=1.0000 utilization=0.0000 benign_al… |
| 1:15167 rev 13 | 周二、周三、周四、周五 | snort3-indicator-compromise.rules | INDICATOR-COMPROMISE Suspicious .cn dns query | high rule false-positive rate and low malicious utilization: rule_fp_rate=1.0000 utilization=0.0000 benign_al… |
| 1:15168 rev 14 | 周二、周三、周四、周五 | snort3-indicator-compromise.rules | INDICATOR-COMPROMISE Suspicious .ru dns query | high rule false-positive rate and low malicious utilization: rule_fp_rate=1.0000 utilization=0.0000 benign_al… |
| 1:28190 rev 4 | 周二、周三、周四、周五 | snort3-indicator-compromise.rules | INDICATOR-COMPROMISE Suspicious .cc dns query | high rule false-positive rate and low malicious utilization: rule_fp_rate=1.0000 utilization=0.0000 benign_al… |
| 1:44416 rev 4 | 周二、周三、周四、周五 | snort3-indicator-compromise.rules | INDICATOR-COMPROMISE png file attachment without matching file magic | high rule false-positive rate and low malicious utilization: rule_fp_rate=1.0000 utilization=0.0000 benign_al… |

## 高频低收益 ITER

| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |
| --- | --- | --- | --- | --- |
| 1:7861 rev 6 | 周二、周三、周四、周五 | snort3-app-detect.rules | APP-DETECT Google Desktop activity | frequently checked rule has low malicious yield: checks=101978 matches=0 alerts=0 malicious_flows=0 utilizati… |
| 1:27669 rev 5 | 周二、周三、周四、周五 | snort3-app-detect.rules | APP-DETECT Heyoka outbound communication attempt | frequently checked rule has low malicious yield: checks=646603 matches=0 alerts=0 malicious_flows=0 utilizati… |
| 1:27700 rev 4 | 周二、周三、周四、周五 | snort3-app-detect.rules | APP-DETECT NSTX DNS tunnel outbound connection attempt | frequently checked rule has low malicious yield: checks=26752 matches=0 alerts=0 malicious_flows=0 utilizatio… |
| 1:25802 rev 6 | 周二、周三、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Stamp exploit kit encoded portable executable request | frequently checked rule has low malicious yield: checks=2657961 matches=0 alerts=0 malicious_flows=0 utilizat… |
| 1:27144 rev 3 | 周二、周三、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Private exploit kit outbound traffic | frequently checked rule has low malicious yield: checks=15276 matches=0 alerts=0 malicious_flows=0 utilizatio… |

## 高成本规则 ITER

| 规则 | 出现数据集 | source_file | msg | 裁剪原因 |
| --- | --- | --- | --- | --- |
| 1:23619 rev 7 | 周二、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Blackhole exploit kit landing page with specific structure - prototype catch broken | high real-traffic rule profiler cost: rank=43 time_us=17288 pct=0.0080 checks=4002 matches=0 alerts=0 |
| 1:38552 rev 2 | 周二、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Angler landing page detected | high real-traffic rule profiler cost: rank=56 time_us=13871 pct=0.0065 checks=4894 matches=0 alerts=0 |
| 1:40034 rev 1 | 周二、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Exploit kit embedded iframe redirection attempt | high real-traffic rule profiler cost: rank=33 time_us=18458 pct=0.0087 checks=3682 matches=0 alerts=0 |
| 1:41908 rev 1 | 周二、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Exploit kit Pseudo-Darkleech Gate redirection attempt | high real-traffic rule profiler cost: rank=51 time_us=16120 pct=0.0076 checks=5340 matches=0 alerts=0 |
| 1:42018 rev 1 | 周二、周四、周五 | snort3-exploit-kit.rules | EXPLOIT-KIT Exploit Kit EITest Gate redirection attempt detected | high real-traffic rule profiler cost: rank=11 time_us=43685 pct=0.0201 checks=5792 matches=0 alerts=0 |
