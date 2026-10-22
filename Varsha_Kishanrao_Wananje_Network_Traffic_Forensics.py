#!/usr/bin/env python3
"""
Network Traffic Forensics Toolkit
Author: Varsha Kishanrao Wananje

Offline PCAP/PCAPNG analysis for defensive security investigations.
Reads an existing capture, extracts packet/flow/DNS summaries, applies
transparent heuristic detections, and exports CSV/JSON/PNG artifacts.

Use only with captures you own or are authorized to examine.
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
except ImportError:
    print("Missing dependency: scapy. Install dependencies with: pip install -r requirements.txt", file=sys.stderr)
    raise

LOG = logging.getLogger("pcap_forensics")


@dataclass
class PacketRecord:
    packet_no: int
    timestamp: float
    timestamp_utc: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    transport: str
    packet_length: int
    tcp_flags: str
    dns_query: str
    dns_qr: Optional[int]


@dataclass
class Finding:
    severity: str
    rule_id: str
    title: str
    source_ip: str
    destination: str
    evidence_count: int
    description: str
    recommendation: str


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def extract_packet(pkt: Any, packet_no: int) -> PacketRecord:
    """Extract a normalized, privacy-conscious packet summary."""
    src_ip = dst_ip = ""
    src_port = dst_port = None
    transport = "OTHER"
    tcp_flags = ""
    dns_query = ""
    dns_qr = None

    if IP in pkt:
        src_ip, dst_ip = str(pkt[IP].src), str(pkt[IP].dst)
    elif IPv6 in pkt:
        src_ip, dst_ip = str(pkt[IPv6].src), str(pkt[IPv6].dst)

    if TCP in pkt:
        transport = "TCP"
        src_port, dst_port = safe_int(pkt[TCP].sport), safe_int(pkt[TCP].dport)
        try:
            tcp_flags = str(pkt[TCP].flags)
        except Exception:
            tcp_flags = ""
    elif UDP in pkt:
        transport = "UDP"
        src_port, dst_port = safe_int(pkt[UDP].sport), safe_int(pkt[UDP].dport)
    elif ICMP in pkt:
        transport = "ICMP"
    elif src_ip or dst_ip:
        transport = "IP"

    if DNS in pkt:
        try:
            dns_qr = safe_int(pkt[DNS].qr)
            if DNSQR in pkt:
                raw = pkt[DNSQR].qname
                if isinstance(raw, bytes):
                    dns_query = raw.decode("utf-8", errors="replace").rstrip(".")
                else:
                    dns_query = str(raw).rstrip(".")
        except Exception:
            pass

    ts = float(getattr(pkt, "time", 0.0))
    try:
        length = int(len(pkt))
    except Exception:
        length = 0

    return PacketRecord(
        packet_no=packet_no,
        timestamp=ts,
        timestamp_utc=utc_iso(ts) if ts else "",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        transport=transport,
        packet_length=length,
        tcp_flags=tcp_flags,
        dns_query=dns_query,
        dns_qr=dns_qr,
    )


def canonical_flow_key(row: PacketRecord) -> Tuple[str, int, str, int, str]:
    """Bidirectional flow key so both directions aggregate together."""
    a = (row.src_ip, row.src_port or 0)
    b = (row.dst_ip, row.dst_port or 0)
    left, right = sorted((a, b))
    return (left[0], left[1], right[0], right[1], row.transport)


def analyze_capture(
    capture_path: Path,
    output_dir: Path,
    max_packets: Optional[int] = None,
    port_sweep_threshold: int = 15,
    syn_threshold: int = 25,
    connection_threshold: int = 30,
    dns_length_threshold: int = 50,
) -> Dict[str, Any]:
    if not capture_path.exists() or not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")
    if capture_path.stat().st_size == 0:
        raise ValueError("Capture file is empty.")

    output_dir.mkdir(parents=True, exist_ok=True)
    packets: List[PacketRecord] = []
    malformed_count = 0
    LOG.info("Reading capture: %s", capture_path)

    # PcapReader streams packets rather than loading a potentially huge capture at once.
    with PcapReader(str(capture_path)) as reader:
        for i, pkt in enumerate(reader, start=1):
            if max_packets is not None and i > max_packets:
                break
            try:
                packets.append(extract_packet(pkt, i))
            except Exception as exc:
                malformed_count += 1
                LOG.debug("Skipping packet %d: %s", i, exc)

    if not packets:
        raise ValueError("No packets could be parsed from the capture.")

    # Flow and endpoint aggregates.
    flows: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}
    source_dest_ports: Dict[str, set] = defaultdict(set)
    source_destinations: Dict[str, set] = defaultdict(set)
    source_syn_counts: Counter = Counter()
    source_connection_counts: Counter = Counter()
    source_bytes: Counter = Counter()
    source_packets: Counter = Counter()
    protocol_counts: Counter = Counter()
    port_counts: Counter = Counter()
    dns_queries: Counter = Counter()
    dns_by_source: Dict[str, Counter] = defaultdict(Counter)
    packet_lengths: List[int] = []

    for row in packets:
        protocol_counts[row.transport] += 1
        packet_lengths.append(row.packet_length)
        if row.src_ip:
            source_packets[row.src_ip] += 1
            source_bytes[row.src_ip] += row.packet_length
        if row.dst_port is not None:
            port_counts[f"{row.transport}/{row.dst_port}"] += 1
        if row.src_ip and row.dst_ip and row.dst_port is not None:
            source_dest_ports[row.src_ip].add(row.dst_port)
            source_destinations[row.src_ip].add(row.dst_ip)

        # TCP SYN set without ACK bit is a heuristic indicator, not proof of a scan.
        if row.transport == "TCP" and "S" in row.tcp_flags and "A" not in row.tcp_flags and row.src_ip:
            source_syn_counts[row.src_ip] += 1
        if row.src_ip and row.dst_ip and row.transport in ("TCP", "UDP"):
            source_connection_counts[row.src_ip] += 1

        key = canonical_flow_key(row)
        if key not in flows:
            flows[key] = {
                "endpoint_a_ip": key[0], "endpoint_a_port": key[1],
                "endpoint_b_ip": key[2], "endpoint_b_port": key[3],
                "transport": key[4], "packets": 0, "bytes": 0,
                "first_seen": row.timestamp, "last_seen": row.timestamp,
            }
        flow = flows[key]
        flow["packets"] += 1
        flow["bytes"] += row.packet_length
        flow["first_seen"] = min(flow["first_seen"], row.timestamp)
        flow["last_seen"] = max(flow["last_seen"], row.timestamp)

        if row.dns_query:
            dns_queries[row.dns_query] += 1
            if row.src_ip:
                dns_by_source[row.src_ip][row.dns_query] += 1

    findings: List[Finding] = []

    for src, ports in source_dest_ports.items():
        if len(ports) >= port_sweep_threshold:
            findings.append(Finding(
                "HIGH", "NET-001", "Possible multi-port sweep", src, "multiple destinations/ports",
                len(ports),
                f"Source contacted {len(ports)} distinct destination ports in the capture.",
                "Validate against approved scanners and asset inventory; inspect time ordering and destination context."
            ))

    for src, count in source_syn_counts.items():
        if count >= syn_threshold:
            findings.append(Finding(
                "MEDIUM", "NET-002", "High count of TCP SYN-only packets", src, "multiple endpoints",
                count,
                f"Observed {count} TCP packets with SYN set and ACK not set.",
                "Correlate with TCP responses and time windows; legitimate connection bursts can trigger this heuristic."
            ))

    for src, count in source_connection_counts.items():
        if count >= connection_threshold:
            findings.append(Finding(
                "LOW", "NET-003", "High connection-attempt volume", src, "multiple endpoints",
                count,
                f"Observed {count} TCP/UDP packets with source address {src}; this is a coarse volume indicator.",
                "Review destination diversity, rates, and known application behavior before escalation."
            ))

    for src, queries in dns_by_source.items():
        long_queries = [(q, n) for q, n in queries.items() if len(q) >= dns_length_threshold]
        if long_queries:
            max_len = max(len(q) for q, _ in long_queries)
            findings.append(Finding(
                "MEDIUM", "DNS-001", "Unusually long DNS query name", src, "DNS",
                sum(n for _, n in long_queries),
                f"Found {len(long_queries)} distinct DNS query names at or above {dns_length_threshold} characters; longest was {max_len}.",
                "Inspect full query names, label lengths, entropy, frequency, and resolver context. Length alone is not proof of tunneling."
            ))

        unique_queries = len(queries)
        if unique_queries >= 50:
            findings.append(Finding(
                "LOW", "DNS-002", "High DNS query-name diversity", src, "DNS",
                unique_queries,
                f"Source issued {unique_queries} distinct DNS query names in the capture.",
                "Check for browser/application behavior, telemetry, malware indicators, and query timing."
            ))

    # Export packet records.
    packet_csv = output_dir / "packets.csv"
    packet_fields = list(asdict(packets[0]).keys())
    with packet_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=packet_fields)
        writer.writeheader()
        writer.writerows(asdict(p) for p in packets)

    flow_rows = []
    for flow in flows.values():
        flow_rows.append({
            **flow,
            "first_seen_utc": utc_iso(flow["first_seen"]),
            "last_seen_utc": utc_iso(flow["last_seen"]),
            "duration_seconds": round(max(0.0, flow["last_seen"] - flow["first_seen"]), 6),
        })
    flow_csv = output_dir / "flows.csv"
    flow_fields = list(flow_rows[0].keys()) if flow_rows else []
    with flow_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=flow_fields)
        writer.writeheader()
        writer.writerows(flow_rows)

    findings_json = output_dir / "findings.json"
    with findings_json.open("w", encoding="utf-8") as handle:
        json.dump([asdict(f) for f in findings], handle, indent=2)

    top_talkers = [
        {"ip": ip, "packets": count, "bytes": int(source_bytes[ip])}
        for ip, count in source_packets.most_common(20)
    ]
    summary = {
        "project": "Network Traffic Forensics Toolkit",
        "capture_file": capture_path.name,
        "analysis_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "packets_parsed": len(packets),
        "malformed_or_skipped_packets": malformed_count,
        "unique_flows": len(flows),
        "unique_source_ips": len(source_packets),
        "protocol_counts": dict(protocol_counts),
        "top_destination_ports": [
            {"port": k, "packets": v} for k, v in port_counts.most_common(15)
        ],
        "top_talkers": top_talkers,
        "packet_length_bytes": {
            "min": min(packet_lengths),
            "max": max(packet_lengths),
            "mean": round(statistics.mean(packet_lengths), 2),
            "median": round(statistics.median(packet_lengths), 2),
        },
        "dns_unique_query_names": len(dns_queries),
        "findings_count": len(findings),
        "findings_by_severity": dict(Counter(f.severity for f in findings)),
        "detection_thresholds": {
            "port_sweep_distinct_destination_ports": port_sweep_threshold,
            "syn_only_packets": syn_threshold,
            "tcp_udp_packets_per_source": connection_threshold,
            "dns_query_name_length": dns_length_threshold,
        },
        "limitations": [
            "Heuristic findings are leads for investigation, not proof of malicious activity.",
            "Encrypted payload contents are not decoded.",
            "Packet loss, capture point, asymmetric routing, NAT, and sampling can affect results.",
            "The coarse connection-volume rule counts packets rather than reconstructed sessions.",
        ],
        "artifacts": ["packets.csv", "flows.csv", "findings.json", "summary.json", "protocol_distribution.png", "top_talkers.png"],
    }
    summary_path = output_dir / "summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    # Graphs are optional; core CSV/JSON output still succeeds if matplotlib is unavailable.
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        if protocol_counts:
            labels, values = zip(*protocol_counts.most_common())
            plt.figure(figsize=(9, 5))
            plt.bar(labels, values)
            plt.title("Protocol Distribution")
            plt.xlabel("Protocol")
            plt.ylabel("Packet count")
            plt.tight_layout()
            plt.savefig(output_dir / "protocol_distribution.png", dpi=150)
            plt.close()

        if top_talkers:
            talkers = top_talkers[:10]
            plt.figure(figsize=(10, 6))
            plt.barh([x["ip"] for x in reversed(talkers)], [x["packets"] for x in reversed(talkers)])
            plt.title("Top Source IPs by Packet Count")
            plt.xlabel("Packets")
            plt.ylabel("Source IP")
            plt.tight_layout()
            plt.savefig(output_dir / "top_talkers.png", dpi=150)
            plt.close()
    except ImportError:
        LOG.warning("matplotlib is not installed; skipping plots.")

    # Human-readable report
    report_path = output_dir / "investigation_report.md"
    report_lines = [
        "# Network Traffic Forensics Report", "",
        f"- **Capture:** `{capture_path.name}`",
        f"- **Analysis time (UTC):** {summary['analysis_timestamp_utc']}",
        f"- **Packets parsed:** {summary['packets_parsed']}",
        f"- **Unique bidirectional flows:** {summary['unique_flows']}",
        f"- **Unique source IPs:** {summary['unique_source_ips']}",
        f"- **Findings:** {summary['findings_count']}", "",
        "## Protocol distribution", "",
    ]
    report_lines += [f"- {proto}: {count}" for proto, count in protocol_counts.most_common()]
    report_lines += ["", "## Findings", ""]
    if findings:
        for f in findings:
            report_lines += [
                f"### [{f.severity}] {f.rule_id}: {f.title}",
                f"- Source: `{f.source_ip}`",
                f"- Destination/context: {f.destination}",
                f"- Evidence count: {f.evidence_count}",
                f"- Observation: {f.description}",
                f"- Recommended follow-up: {f.recommendation}", "",
            ]
    else:
        report_lines.append("No configured heuristic thresholds were triggered. This does not prove the capture is benign.")
    report_lines += [
        "", "## Important interpretation notes", "",
        "- Findings are heuristic and require analyst validation.",
        "- Absence of alerts is not evidence that a capture is safe.",
        "- Analysis is limited to fields visible in the packet capture.",
    ]
    report_path.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    LOG.info("Analysis complete: %d packets, %d flows, %d findings", len(packets), len(flows), len(findings))
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline PCAP/PCAPNG network forensics and heuristic detection toolkit."
    )
    parser.add_argument("capture", help="Path to a .pcap or .pcapng file")
    parser.add_argument("-o", "--output", default="forensics_output", help="Output directory (default: forensics_output)")
    parser.add_argument("--max-packets", type=int, default=None, help="Analyze at most N packets (useful for large captures)")
    parser.add_argument("--port-sweep-threshold", type=int, default=15, help="Distinct destination ports per source to flag")
    parser.add_argument("--syn-threshold", type=int, default=25, help="SYN-only packets per source to flag")
    parser.add_argument("--connection-threshold", type=int, default=30, help="TCP/UDP packet volume per source to flag")
    parser.add_argument("--dns-length-threshold", type=int, default=50, help="DNS query name length to flag")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if args.max_packets is not None and args.max_packets < 1:
        parser.error("--max-packets must be greater than zero")
    for name in ("port_sweep_threshold", "syn_threshold", "connection_threshold", "dns_length_threshold"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be greater than zero")
    try:
        summary = analyze_capture(
            Path(args.capture),
            Path(args.output),
            max_packets=args.max_packets,
            port_sweep_threshold=args.port_sweep_threshold,
            syn_threshold=args.syn_threshold,
            connection_threshold=args.connection_threshold,
            dns_length_threshold=args.dns_length_threshold,
        )
    except (FileNotFoundError, ValueError, OSError) as exc:
        LOG.error("%s", exc)
        return 2
    print(json.dumps({
        "status": "success",
        "packets_parsed": summary["packets_parsed"],
        "unique_flows": summary["unique_flows"],
        "findings_count": summary["findings_count"],
        "output_directory": str(Path(args.output).resolve()),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
