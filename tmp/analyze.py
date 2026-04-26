#!/usr/bin/env python3
"""Analyze alert_json.txt (alerts) and output_and_profiler.txt (Snort perf stats)."""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ALERT_FILE = Path("alert_json.txt")
PERF_FILE = Path("output_and_profiler.txt")


def parse_alerts():
    """Parse JSON-lines alert file."""
    alerts = []
    with open(ALERT_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            alerts.append(json.loads(line))
    return alerts


def analyze_alerts(alerts):
    print("=" * 70)
    print("ALERT JSON ANALYSIS")
    print("=" * 70)
    print(f"Total alerts: {len(alerts):,}")
    print()

    # --- Actions breakdown ---
    action_counts = Counter(a["action"] for a in alerts)
    print("--- Actions Breakdown ---")
    for action, count in action_counts.most_common():
        print(f"  {action}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Protocol breakdown ---
    proto_counts = Counter(a["proto"] for a in alerts)
    print("--- Protocol Breakdown ---")
    for proto, count in proto_counts.most_common():
        print(f"  {proto}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Direction breakdown ---
    dir_counts = Counter(a["dir"] for a in alerts)
    print("--- Direction Breakdown ---")
    for d, count in dir_counts.most_common():
        print(f"  {d}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Packet generation type ---
    gen_counts = Counter(a["pkt_gen"] for a in alerts)
    print("--- Packet Generation Type ---")
    for g, count in gen_counts.most_common():
        print(f"  {g}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Top rules by alert count ---
    print("--- Top 20 Most Active Rules ---")
    rule_counts = Counter(a["rule"] for a in alerts)
    for rule, count in rule_counts.most_common(20):
        print(f"  {rule}: {count:,} ({100*count/len(alerts):.2f}%)")
    print()

    # --- Packet length distribution ---
    lens = [a["pkt_len"] for a in alerts]
    lens.sort()
    print("--- Packet Length Distribution ---")
    print(f"  Min: {min(lens)}")
    print(f"  Max: {max(lens)}")
    print(f"  Mean: {sum(lens)/len(lens):.1f}")
    print(f"  Median: {lens[len(lens)//2]}")
    print(f"  P99: {lens[int(len(lens)*0.99)]}")

    # Bucket sizes
    buckets = [("0-64", 0), ("65-128", 0), ("129-256", 0), ("257-512", 0), ("513-1024", 0), ("1025-1500", 0), (">1500", 0)]
    len_buckets = defaultdict(int)
    for l in lens:
        if l <= 64:       len_buckets["0-64"] += 1
        elif l <= 128:    len_buckets["65-128"] += 1
        elif l <= 256:    len_buckets["129-256"] += 1
        elif l <= 512:    len_buckets["257-512"] += 1
        elif l <= 1024:   len_buckets["513-1024"] += 1
        elif l <= 1500:   len_buckets["1025-1500"] += 1
        else:             len_buckets[">1500"] += 1
    for bucket, count in len_buckets.items():
        print(f"  {bucket}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Top source IPs ---
    print("--- Top 20 Source IPs ---")
    src_counts = Counter(a["src_ap"].rsplit(":", 1)[0] for a in alerts)
    for ip, count in src_counts.most_common(20):
        print(f"  {ip}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Top destination IPs ---
    print("--- Top 20 Destination IPs ---")
    dst_counts = Counter(a["dst_ap"].rsplit(":", 1)[0] for a in alerts)
    for ip, count in dst_counts.most_common(20):
        print(f"  {ip}: {count:,} ({100*count/len(alerts):.1f}%)")
    print()

    # --- Unique rules fired ---
    print(f"Unique rules fired: {len(rule_counts):,}")
    print()

    # --- Source/Destination port analysis ---
    src_ports = Counter(int(a["src_ap"].rsplit(":", 1)[1]) for a in alerts)
    dst_ports = Counter(int(a["dst_ap"].rsplit(":", 1)[1]) for a in alerts)
    print("--- Top 10 Source Ports ---")
    for p, c in src_ports.most_common(10):
        print(f"  {p}: {c:,}")
    print("--- Top 10 Destination Ports ---")
    for p, c in dst_ports.most_common(10):
        print(f"  {p}: {c:,}")
    print()


def parse_profiler():
    """Parse Snort output_and_profiler.txt for key stats."""
    with open(PERF_FILE) as f:
        text = f.read()

    print("=" * 70)
    print("S N O R T   P E R F O R M A N C E   S T A T I S T I C S")
    print("=" * 70)

    # --- Summary timing ---
    timing_match = re.search(
        r"runtime:\s+(\S+)\s+seconds:\s+([\d.]+)\s+pkts/sec:\s+([\d,]+)\s+Mbits/sec:\s+([\d,]+)",
        text,
    )
    if timing_match:
        runtime, seconds, pps, mbps = timing_match.groups()
        print(f"\n--- Timing ---")
        print(f"  Runtime: {runtime} ({seconds}s)")
        print(f"  Throughput: {pps} pkts/sec, {mbps} Mbits/sec")

    # --- Packet stats ---
    pkt_match = re.search(
        r"received:\s+([\d,]+)\s+analyzed:\s+([\d,]+)\s+allow:\s+([\d,]+)\s+rx_bytes:\s+([\d,]+)",
        text,
    )
    if pkt_match:
        recv, analyzed, allow, rx_bytes = [m.replace(",", "") for m in pkt_match.groups()]
        print(f"\n--- DAQ Packet Statistics ---")
        print(f"  Received: {int(recv):,}")
        print(f"  Analyzed: {int(analyzed):,}")
        print(f"  Allowed: {int(allow):,}")
        print(f"  Total bytes: {int(rx_bytes):,}")
        print(f"  Avg pkt size: {int(rx_bytes)//int(recv)} bytes")

    # --- Codec ---
    codec_match = re.search(
        r"total:\s+(\d+)\s+\(([\d.]+)%\)\s+discards:\s+(\d+)\s+\(([\d.]+)%\)",
        text,
    )
    if codec_match:
        total, _, discards, _ = codec_match.groups()
        print(f"\n--- Codec ---")
        print(f"  Total frames: {int(total):,}")
        print(f"  Discards: {int(discards):,}")

    # --- Detection stats ---
    det_sections = re.findall(
        r"(?m)^(?:detection|ac_bnfa|http_inspect|stream_tcp|file_id|ssl|port_scan)\s*$",
        text,
    )
    print(f"\n--- Module Statistics ---")

    def get_section(section_name):
        """Extract key-value pairs under a section header."""
        pat = re.compile(
            rf"(?m)^{re.escape(section_name)}\s*\n(.+?)(?=\n\S|\Z)", re.DOTALL
        )
        m = pat.search(text)
        if not m:
            return {}
        block = m.group(1)
        result = {}
        for line in block.strip().split("\n"):
            kv = re.match(r"\s{4,}(\w[\w_]*):\s+([\d,]+)", line)
            if kv:
                result[kv.group(1)] = int(kv.group(2).replace(",", ""))
        return result

    # Detection
    det = get_section("detection")
    if det:
        print("  Detection:")
        for k, v in det.items():
            print(f"    {k}: {v:,}")

    # AC BNFA
    ac = get_section("ac_bnfa")
    if ac:
        print("  AC_BNFA (pattern matcher):")
        for k, v in ac.items():
            print(f"    {k}: {v:,}")

    # http_inspect
    http = get_section("http_inspect")
    if http:
        print("  HTTP Inspect:")
        for k, v in http.items():
            print(f"    {k}: {v:,}")

    # stream_tcp
    stcp = get_section("stream_tcp")
    if stcp:
        print("  Stream TCP:")
        important = ["sessions", "segs_queued", "segs_released", "rebuilt_packets", "gaps"]
        for k in important:
            if k in stcp:
                print(f"    {k}: {stcp[k]:,}")

    # file_id
    fi = get_section("file_id")
    if fi:
        print(f"  File ID: {fi.get('total_files', 0):,} files, {fi.get('total_file_data', 0):,} bytes")

    # --- Module profile (top 10) ---
    print(f"\n--- Top 10 Modules by CPU Time ---")
    mod_lines = re.findall(
        r"^\s+\d+\s+(\w[\w_]*)\s+\d+\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)",
        text,
        re.MULTILINE,
    )
    for name, checks, time_us, avg in mod_lines[:10]:
        checks = int(checks.replace(",", ""))
        time_ms = int(time_us.replace(",", "")) / 1000
        print(f"  {name:<20} checks={checks:>8,}  time={time_ms:>10.1f}ms")

    # --- Rule profile (top 10) ---
    print(f"\n--- Top 10 Rules by CPU Time ---")
    rule_lines = re.findall(
        r"^\s*\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)",
        text,
        re.MULTILINE,
    )
    total_rule_time = 0
    parsed_rules = []
    for cols in rule_lines:
        gid, sid, rev, checks, matches, alerts, time_us = cols
        time_us = int(time_us.replace(",", ""))
        total_rule_time += time_us
        checks = int(checks.replace(",", ""))
        matches = int(matches.replace(",", ""))
        alerts = int(alerts.replace(",", ""))
        parsed_rules.append(
            (gid, sid, rev, checks, matches, alerts, time_us)
        )

    parsed_rules.sort(key=lambda r: r[6], reverse=True)
    for gid, sid, rev, checks, matches, alerts, time_us in parsed_rules[:10]:
        time_ms = time_us / 1000
        print(f"  {gid}:{sid}:{rev}  checks={checks:>8,}  matches={matches:>7,}  alerts={alerts:>7,}  time={time_ms:>8.1f}ms")

    if parsed_rules:
        print(f"\n  Total rule eval time: {total_rule_time/1000:.1f}ms ({total_rule_time/59_462_499*100:.1f}% of total)")

    # --- Search engine stats ---
    se_match = re.search(
        r"non_qualified_events:\s+([\d,]+)\s+qualified_events:\s+([\d,]+)", text
    )
    if se_match:
        nq, q = se_match.groups()
        print(f"\n--- Search Engine ---")
        print(f"  Non-qualified events: {int(nq.replace(',','')):,}")
        print(f"  Qualified events:     {int(q.replace(',','')):,}")
        print(f"  Qualification ratio:  {int(q.replace(',',''))/int(nq.replace(',',''))*100:.2f}% of total alerts considered")
        print(f"  Alerts generated:     {det.get('alerts', 0):,}")


def main():
    alerts = parse_alerts()
    analyze_alerts(alerts)
    parse_profiler()


if __name__ == "__main__":
    main()
