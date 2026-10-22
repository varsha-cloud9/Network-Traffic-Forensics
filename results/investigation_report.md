# Network Traffic Forensics Report

- **Capture:** `SkypeIRC.cap`
- **Analysis time (UTC):** 2026-10-22T11:08:21.744698+00:00
- **Packets parsed:** 2263
- **Unique bidirectional flows:** 225
- **Unique source IPs:** 148
- **Findings:** 11

## Protocol distribution

- TCP: 1150
- UDP: 1072
- ICMP: 23
- OTHER: 16
- IP: 2

## Findings

### [HIGH] NET-001: Possible multi-port sweep
- Source: `192.168.1.2`
- Destination/context: multiple destinations/ports
- Evidence count: 173
- Observation: Source contacted 173 distinct destination ports in the capture.
- Recommended follow-up: Validate against approved scanners and asset inventory; inspect time ordering and destination context.

### [MEDIUM] NET-002: High count of TCP SYN-only packets
- Source: `192.168.1.2`
- Destination/context: multiple endpoints
- Evidence count: 106
- Observation: Observed 106 TCP packets with SYN set and ACK not set.
- Recommended follow-up: Correlate with TCP responses and time windows; legitimate connection bursts can trigger this heuristic.

### [LOW] NET-003: High connection-attempt volume
- Source: `192.168.1.2`
- Destination/context: multiple endpoints
- Evidence count: 1174
- Observation: Observed 1174 TCP/UDP packets with source address 192.168.1.2; this is a coarse volume indicator.
- Recommended follow-up: Review destination diversity, rates, and known application behavior before escalation.

### [LOW] NET-003: High connection-attempt volume
- Source: `212.204.214.114`
- Destination/context: multiple endpoints
- Evidence count: 141
- Observation: Observed 141 TCP/UDP packets with source address 212.204.214.114; this is a coarse volume indicator.
- Recommended follow-up: Review destination diversity, rates, and known application behavior before escalation.

### [LOW] NET-003: High connection-attempt volume
- Source: `192.168.1.1`
- Destination/context: multiple endpoints
- Evidence count: 353
- Observation: Observed 353 TCP/UDP packets with source address 192.168.1.1; this is a coarse volume indicator.
- Recommended follow-up: Review destination diversity, rates, and known application behavior before escalation.

### [LOW] NET-003: High connection-attempt volume
- Source: `71.10.179.129`
- Destination/context: multiple endpoints
- Evidence count: 43
- Observation: Observed 43 TCP/UDP packets with source address 71.10.179.129; this is a coarse volume indicator.
- Recommended follow-up: Review destination diversity, rates, and known application behavior before escalation.

### [LOW] NET-003: High connection-attempt volume
- Source: `172.200.160.242`
- Destination/context: multiple endpoints
- Evidence count: 41
- Observation: Observed 41 TCP/UDP packets with source address 172.200.160.242; this is a coarse volume indicator.
- Recommended follow-up: Review destination diversity, rates, and known application behavior before escalation.

### [MEDIUM] DNS-001: Unusually long DNS query name
- Source: `192.168.1.2`
- Destination/context: DNS
- Evidence count: 5
- Observation: Found 5 distinct DNS query names at or above 50 characters; longest was 56.
- Recommended follow-up: Inspect full query names, label lengths, entropy, frequency, and resolver context. Length alone is not proof of tunneling.

### [LOW] DNS-002: High DNS query-name diversity
- Source: `192.168.1.2`
- Destination/context: DNS
- Evidence count: 345
- Observation: Source issued 345 distinct DNS query names in the capture.
- Recommended follow-up: Check for browser/application behavior, telemetry, malware indicators, and query timing.

### [MEDIUM] DNS-001: Unusually long DNS query name
- Source: `192.168.1.1`
- Destination/context: DNS
- Evidence count: 5
- Observation: Found 5 distinct DNS query names at or above 50 characters; longest was 56.
- Recommended follow-up: Inspect full query names, label lengths, entropy, frequency, and resolver context. Length alone is not proof of tunneling.

### [LOW] DNS-002: High DNS query-name diversity
- Source: `192.168.1.1`
- Destination/context: DNS
- Evidence count: 345
- Observation: Source issued 345 distinct DNS query names in the capture.
- Recommended follow-up: Check for browser/application behavior, telemetry, malware indicators, and query timing.


## Important interpretation notes

- Findings are heuristic and require analyst validation.
- Absence of alerts is not evidence that a capture is safe.
- Analysis is limited to fields visible in the packet capture.
