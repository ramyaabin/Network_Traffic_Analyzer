

import csv
import json
import os
from collections import Counter
from datetime import datetime

# Import the shared Monitor instance from the team's backend
from backend import MON


# ──────────────────────────────────────────────
# Protocol constants
# ──────────────────────────────────────────────

ALL_PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "HTTPS", "OTHER"]

SUSPICIOUS_PORTS      = {22, 23, 3389, 4444, 1337, 6667, 31337}
HIGH_TRAFFIC_THRESHOLD = 200   # packets from a single source in one session
ICMP_FLOOD_THRESHOLD   = 50    # ICMP packets from one source


# ──────────────────────────────────────────────
# Packet counting
# ──────────────────────────────────────────────

def count_total_packets():
    """Return total number of packets captured so far."""
    return len(MON.packets)


def count_packets_by_protocol():
    """
    Return a dict mapping protocol name to packet count.
    Example: {'TCP': 410, 'HTTPS': 320, 'UDP': 180, ...}
    """
    counter = Counter(pkt["protocol"] for pkt in MON.packets)
    return dict(counter.most_common())


# ──────────────────────────────────────────────
# Protocol usage percentage
# ──────────────────────────────────────────────

def protocol_usage_percentages():
    """
    Return protocol usage as percentages rounded to 2 decimal places.
    Example: {'TCP': 32.88, 'HTTPS': 25.66, 'UDP': 14.43, ...}
    """
    counts = count_packets_by_protocol()
    total  = sum(counts.values())
    if total == 0:
        return {}
    return {proto: round((cnt / total) * 100, 2) for proto, cnt in counts.items()}


# ──────────────────────────────────────────────
# Active IP addresses
# ──────────────────────────────────────────────

def top_source_ips(limit=10):
    """Return the top N most active source IPs as (ip, count) tuples."""
    counter = Counter(pkt["src_ip"] for pkt in MON.packets)
    return counter.most_common(limit)


def top_destination_ips(limit=10):
    """Return the top N most contacted destination IPs as (ip, count) tuples."""
    counter = Counter(pkt["dst_ip"] for pkt in MON.packets)
    return counter.most_common(limit)


# ──────────────────────────────────────────────
# Traffic summaries
# ──────────────────────────────────────────────

def total_bandwidth_bytes():
    """Return total bytes transferred across all captured packets."""
    return sum(pkt["size"] for pkt in MON.packets)


def average_packet_size():
    """Return average packet size in bytes, rounded to 2 decimal places."""
    packets = MON.packets
    if not packets:
        return 0.0
    return round(sum(pkt["size"] for pkt in packets) / len(packets), 2)


def traffic_summary():
    """Return a comprehensive traffic summary dictionary."""
    total       = count_total_packets()
    protocols   = count_packets_by_protocol()
    percentages = protocol_usage_percentages()
    total_bytes = total_bandwidth_bytes()
    avg_size    = average_packet_size()
    src_ips     = top_source_ips(limit=5)
    dst_ips     = top_destination_ips(limit=5)

    return {
        "total_packets":             total,
        "total_bytes":               total_bytes,
        "average_packet_size_bytes": avg_size,
        "protocol_counts":           protocols,
        "protocol_percentages":      percentages,
        "top_source_ips":            src_ips,
        "top_destination_ips":       dst_ips,
        "generated_at":              datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ──────────────────────────────────────────────
# Anomaly / unusual traffic detection
# ──────────────────────────────────────────────

def detect_high_traffic_sources(threshold=HIGH_TRAFFIC_THRESHOLD):
    """
    Flag source IPs that sent more than threshold packets.
    Possible DoS attempt or aggressive network scanner.
    """
    counter = Counter(pkt["src_ip"] for pkt in MON.packets)
    return [(ip, cnt) for ip, cnt in counter.items() if cnt > threshold]


def detect_suspicious_ports():
    """Return packets directed at known suspicious destination ports."""
    results = []
    for pkt in MON.packets:
        port = pkt.get("dst_port")
        if port and port in SUSPICIOUS_PORTS:
            results.append(pkt)
    return results


def detect_icmp_flood(threshold=ICMP_FLOOD_THRESHOLD):
    """
    Detect potential ICMP flood attack.
    High ICMP volume from one source = possible ping-flood or DoS.
    """
    counter = Counter(
        pkt["src_ip"] for pkt in MON.packets if pkt["protocol"] == "ICMP"
    )
    return [(ip, cnt) for ip, cnt in counter.items() if cnt > threshold]


def detect_threat_alerts():
    """Return all packets flagged by the capture module as non-Normal threats."""
    return [pkt for pkt in MON.packets if pkt.get("threat", "Normal") != "Normal"]


def run_anomaly_detection():
    """Run all anomaly checks and return a structured alert report."""
    high_traffic = detect_high_traffic_sources()
    suspicious   = detect_suspicious_ports()
    icmp_flood   = detect_icmp_flood()
    threats      = detect_threat_alerts()

    alerts = []

    for ip, count in high_traffic:
        alerts.append({
            "type":     "HIGH_TRAFFIC",
            "severity": "WARNING",
            "detail":   f"Source IP {ip} sent {count} packets (threshold: {HIGH_TRAFFIC_THRESHOLD})"
        })

    for pkt in suspicious:
        alerts.append({
            "type":     "SUSPICIOUS_PORT",
            "severity": "WARNING",
            "detail":   (
                f"Packet from {pkt['src_ip']} to {pkt['dst_ip']}:{pkt['dst_port']} "
                f"({pkt['protocol']}) at {pkt['timestamp']}"
            )
        })

    for ip, count in icmp_flood:
        alerts.append({
            "type":     "ICMP_FLOOD",
            "severity": "HIGH",
            "detail":   f"Possible ICMP flood from {ip} — {count} ICMP packets detected"
        })

    for pkt in threats:
        alerts.append({
            "type":     "THREAT_DETECTED",
            "severity": "HIGH",
            "detail":   (
                f"{pkt['threat']} — {pkt['protocol']} from {pkt['src_ip']} "
                f"at {pkt['timestamp']}"
            )
        })

    return {
        "total_alerts": len(alerts),
        "alerts":       alerts,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ──────────────────────────────────────────────
# Report export
# ──────────────────────────────────────────────

def export_summary_to_csv(output_path="traffic_analysis_report.csv"):
    """Export per-packet data to a CSV file for offline analysis."""
    packets = MON.packets

    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Timestamp", "Source IP", "Destination IP",
            "Protocol", "Src Port", "Dst Port",
            "Packet Size (bytes)", "Flags", "TTL", "Threat"
        ])
        for pkt in packets:
            writer.writerow([
                pkt.get("timestamp", ""),
                pkt.get("src_ip",    ""),
                pkt.get("dst_ip",    ""),
                pkt.get("protocol",  ""),
                pkt.get("src_port",  ""),
                pkt.get("dst_port",  ""),
                pkt.get("size",      0),
                pkt.get("flags",     ""),
                pkt.get("ttl",       ""),
                pkt.get("threat",    "Normal"),
            ])

    print(f"[+] CSV report saved to: {output_path}  ({len(packets)} rows)")
    return output_path


def export_summary_to_json(output_path="traffic_summary.json"):
    """Export a full traffic summary and anomaly report to JSON."""
    summary   = traffic_summary()
    anomalies = run_anomaly_detection()
    report    = {"summary": summary, "anomaly_report": anomalies}

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[+] JSON report saved to: {output_path}")
    return output_path


# ──────────────────────────────────────────────
# Console report
# ──────────────────────────────────────────────

def print_traffic_report():
    """Print a human-readable traffic analysis report to the console."""
    summary   = traffic_summary()
    anomalies = run_anomaly_detection()

    print("=" * 60)
    print("   NETWORK TRAFFIC ANALYSIS REPORT")
    print(f"   Generated: {summary['generated_at']}")
    print("=" * 60)

    print(f"\n[OVERVIEW]")
    print(f"  Total Packets Captured : {summary['total_packets']}")
    print(f"  Total Bandwidth        : {summary['total_bytes']:,} bytes")
    print(f"  Average Packet Size    : {summary['average_packet_size_bytes']} bytes")

    print(f"\n[PROTOCOL DISTRIBUTION]")
    for proto, pct in summary["protocol_percentages"].items():
        count = summary["protocol_counts"][proto]
        bar   = "=" * int(pct // 5)
        print(f"  {proto:<8} {bar:<20} {pct:>6.2f}%  ({count} pkts)")

    print(f"\n[TOP SOURCE IPs]")
    for ip, count in summary["top_source_ips"]:
        print(f"  {ip:<20} {count} packets")

    print(f"\n[TOP DESTINATION IPs]")
    for ip, count in summary["top_destination_ips"]:
        print(f"  {ip:<20} {count} packets")

    print(f"\n[ANOMALY DETECTION]  {anomalies['total_alerts']} alert(s) found")
    if anomalies["alerts"]:
        for alert in anomalies["alerts"]:
            print(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")
    else:
        print("  No anomalies detected.")

    print("=" * 60)


# ──────────────────────────────────────────────
# Static tests
# ──────────────────────────────────────────────

def run_static_tests():
    """
    Automated static tests to verify module correctness.
    Returns a list of (test_id, test_name, passed, detail) tuples.
    """
    results = []

    # TC-001: Total packet count is non-negative
    total = count_total_packets()
    results.append((
        "TC-001", "Total packet count is non-negative",
        total >= 0, f"Packet count = {total}"
    ))

    # TC-002: Protocol percentages sum to ~100%
    pcts    = protocol_usage_percentages()
    pct_sum = round(sum(pcts.values()), 1)
    results.append((
        "TC-002", "Protocol percentages sum to ~100%",
        abs(pct_sum - 100) < 0.6 or pct_sum == 0,
        f"Sum = {pct_sum}%"
    ))

    # TC-003: Average packet size within valid Ethernet range (0–65535 bytes)
    avg = average_packet_size()
    results.append((
        "TC-003", "Average packet size in valid range (0–65535 bytes)",
        0 <= avg <= 65535, f"Average = {avg} bytes"
    ))

    # TC-004: top_source_ips() returns a list
    top_src = top_source_ips(limit=5)
    results.append((
        "TC-004", "top_source_ips() returns a list",
        isinstance(top_src, list), f"{len(top_src)} entries returned"
    ))

    # TC-005: Anomaly detection returns required keys
    anomalies = run_anomaly_detection()
    has_keys  = "total_alerts" in anomalies and "alerts" in anomalies
    results.append((
        "TC-005", "run_anomaly_detection() returns correct structure",
        has_keys, f"Keys present: {list(anomalies.keys())}"
    ))

    # TC-006: CSV export creates a file
    csv_path   = "test_export_temp.csv"
    export_summary_to_csv(csv_path)
    file_exists = os.path.isfile(csv_path)
    results.append((
        "TC-006", "export_summary_to_csv() creates a file",
        file_exists, f"File path: {csv_path}"
    ))
    if file_exists:
        os.remove(csv_path)

    # TC-007: JSON export creates a file
    json_path   = "test_summary_temp.json"
    export_summary_to_json(json_path)
    json_exists = os.path.isfile(json_path)
    results.append((
        "TC-007", "export_summary_to_json() creates a file",
        json_exists, f"File path: {json_path}"
    ))
    if json_exists:
        os.remove(json_path)

    return results


def print_static_test_results():
    """Run and print static test results in a readable format."""
    print("\n[STATIC TEST RESULTS]")
    print("-" * 60)
    results = run_static_tests()
    passed  = sum(1 for _, _, ok, _ in results if ok)
    for tid, name, ok, detail in results:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {tid}: {name}")
        print(f"         Detail: {detail}")
    print("-" * 60)
    print(f"  {passed}/{len(results)} tests passed")
    print("-" * 60)


# ──────────────────────────────────────────────
# Entry point (standalone testing only)
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import time
    print("[*] Starting capture for 5 seconds to collect test data...")
    MON.start()
    time.sleep(5)
    MON.stop()

    print_traffic_report()
    print_static_test_results()
    export_summary_to_csv("traffic_analysis_report.csv")
    export_summary_to_json("traffic_summary.json")
