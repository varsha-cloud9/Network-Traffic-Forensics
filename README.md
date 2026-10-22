# Network Traffic Forensics Toolkit

**Author:** Varsha Kishanrao Wananje  
**Project type:** Cybersecurity / Network Forensics  
**Mode:** Offline PCAP/PCAPNG analysis

## Project description

This project is a defensive Python tool for examining packet captures (`.pcap` and `.pcapng`). It summarizes packet and protocol distributions, aggregates bidirectional flows, reports frequent endpoints and ports, examines visible DNS query names, and applies transparent heuristic rules to identify traffic that deserves analyst review.

The tool does **not** claim that a heuristic finding proves an attack. Results must be correlated with the environment, capture point, timing, and other evidence.

## Features

- Streaming packet reading using Scapy's `PcapReader`
- IPv4/IPv6, TCP, UDP, ICMP, port, packet-size, and timestamp extraction
- Bidirectional flow aggregation
- CSV packet and flow tables
- JSON findings and summary
- Heuristic indicators:
  - many destination ports contacted by one source
  - high count of TCP SYN-only packets
  - high coarse TCP/UDP packet volume
  - unusually long DNS query names
  - high DNS query-name diversity
- PNG protocol and top-talker charts when Matplotlib is installed
- Markdown investigation report
- Configurable thresholds and packet limit

## Dataset / sample capture links

Use a capture you are authorized to analyze. Useful public sources:

1. **Wireshark sample captures:** https://www.wireshark.org/resources  
   Small captures are useful for validating protocol parsing and understanding packet formats. Review the individual sample description and any applicable terms.
2. **Wireshark SampleCaptures wiki:** https://wiki.wireshark.org/SampleCaptures
3. **CIC-IDS2017 dataset (Canadian Institute for Cybersecurity):** https://www.unb.ca/cic/datasets/ids-2017.html  
   This is a larger intrusion-detection research dataset with labeled traffic and PCAP files. It may require substantial disk space and time; check the current download options, licensing, and dataset documentation before downloading. The complete dataset is not required to run the tool.

This repository intentionally does not bundle PCAP files. Captures can contain personal data, internal addresses, hostnames, and other sensitive information.
### Dataset used for testing

- **Capture filename:** `SkypeIRC.cap`
- **Analysis type:** Offline PCAP/PCAPNG analysis
- **Packets parsed:** 2,263
- **Unique bidirectional flows:** 225
- **Heuristic findings:** 11

These figures are from a successful test run using `SkypeIRC.cap` with the default detection thresholds. They describe this particular capture and are not measurements of general detection accuracy. The capture file is not bundled with this README; it must be available locally to reproduce the test.

## Requirements

- Python 3.10 or newer recommended
- pip
- Dependencies listed in `requirements.txt`
- A `.pcap` or `.pcapng` file for analysis
- Optional: Wireshark for independently inspecting a capture

## Setup

### Windows (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```bash
python Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py sample.pcap
```

Choose an output directory:

### Run with the project test capture

Place `SkypeIRC.cap` in the same directory as the Python script, or provide the appropriate path to the capture file.

On Windows, run:

```powershell
python Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py SkypeIRC.cap --output results
```

The tool creates the `results` directory and writes the packet and flow CSV files, JSON summaries, investigation report, and charts when Matplotlib is available.

```bash
python Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py sample.pcap --output results
```

Analyze only the first 10,000 packets:

```bash
python Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py sample.pcap --max-packets 10000 --output results_10k
```

Tune thresholds:

```bash
python Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py sample.pcap \
  --port-sweep-threshold 12 \
  --syn-threshold 20 \
  --connection-threshold 40 \
  --dns-length-threshold 45 \
  --output results_custom
```

See all options:

```bash
python Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py --help
```

## Output files

The output directory contains:

| File | Purpose |
|---|---|
| `packets.csv` | One row per parsed packet with normalized fields |
| `flows.csv` | Bidirectional endpoint/port/protocol aggregates |
| `findings.json` | Machine-readable heuristic findings |
| `summary.json` | Counts, top talkers, thresholds, limitations |
| `investigation_report.md` | Human-readable investigation report |
| `protocol_distribution.png` | Protocol count chart (if Matplotlib works) |
| `top_talkers.png` | Top source IPs by packet count (if Matplotlib works) |

## Testing and expected behavior

1. Run `python ... --help` to verify CLI setup.
2. Run against a valid public sample capture.
3. Confirm the output directory contains packet/flow CSVs, JSON, and Markdown.
4. Compare packet totals and selected protocol details against Wireshark or `tshark`.
5. Run against a missing file and an empty file; the program should return an error rather than fabricate output.

No performance or detection accuracy numbers are claimed in this report because they depend on the capture and have not been measured in advance. For a formal evaluation, record the capture name, packet count, known labels, threshold settings, runtime, and analyst-validated true/false positives.

## Troubleshooting

- **Scapy missing:** Run `python -m pip install -r requirements.txt`.
- **Capture file not found:** Check the filename and path to the `.pcap` or `.pcapng` file.
- **Empty or unreadable capture:** Try a valid capture file and check that it contains packets supported by the reader.
- **Charts not generated:** Confirm that Matplotlib is installed. The script is designed to continue without charts if Matplotlib cannot be imported.
- **No findings reported:** This means the configured heuristic thresholds were not triggered; it does not prove that the traffic is benign.

## Detection logic and limitations

- **Port sweep:** counts distinct destination ports contacted by a source across the entire analyzed capture. It does not currently enforce a time window, and may flag scanners or legitimate service discovery.
- **SYN-only volume:** counts TCP packets with SYN set and ACK not set. Retransmissions and legitimate bursts may trigger it.
- **Connection volume:** a deliberately coarse packet-count indicator, not a count of TCP sessions.
- **DNS length/diversity:** long or numerous query names can be legitimate. DNS tunneling cannot be confirmed by length alone.
- Encrypted application payloads are not decrypted.
- Capture loss, NAT, asymmetric routing, truncation, timestamps, offloading, and capture location can influence findings.
- Flow aggregation is endpoint/port/protocol based and does not reconstruct TCP sessions or application transactions.

## Ethical and legal use

Analyze only traffic you own or have explicit permission to inspect. Treat packet captures and generated reports as potentially sensitive. Redact internal addresses and identifiers before sharing outputs. This is an educational triage aid, not a replacement for a validated IDS/IPS or professional forensic process.

## Project files

- `Varsha_Kishanrao_Wananje_Network_Traffic_Forensics.py` — source code
- `requirements.txt` — Python dependencies
- `Varsha_Kishanrao_Wananje_ProjectReport.docx` — project report
- `README.md` — this file
