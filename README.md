# SE-Miniproject-Pocket-Packet-Sniffer

A compact, portable network traffic monitoring device built around a Raspberry Pi. It captures live packets from a chosen interface, analyses them with [Zeek](https://zeek.org), and shows a simple, readable summary and basic suspicious-activity alerts through a lightweight Python interface. Sessions are stored locally and can be exported for deeper analysis (e.g. in Wireshark).

> PES University, Bangalore — Software Engineering Mini-Project (Jackfruit Phase-1), **Group 4**

## Team (Group 4)

| Name | USN | SRN / PRN |
|------|-----|-----------|
| Ankita S | PES1UG24CS066 | PES1202402282 |
| Anusha Gupta | PES1UG24CS073 | PES1202402250 |
| Charan M | PES1UG24CS125 | PES1202400244 |
| Vaghasiya Akshar Arvindbhai | PES1UG25CS852 | PES1202503586 |

## Why this project?

Inspecting live traffic usually means setting up a laptop with Wireshark or tcpdump, which is inconvenient for quick checks in a lab, a small audit, or IoT/embedded debugging. Pocket Packet Sniffer lets a student or junior network technician carry a small device to a network point, start a capture, and get an immediate readable summary of what is happening on that segment.

**Intended users:** networking and cybersecurity students, teaching assistants running lab sessions, and junior network administrators.

## Features

| # | Feature | Owner | What it does |
|---|---------|-------|--------------|
| 1 | Live Capture & Session Control | Ankita S | Select an interface, start/stop a capture, set an optional duration or protocol filter, write a `.pcap`, stream packets to Zeek |
| 2 | Real-Time Traffic Summary Dashboard | Anusha Gupta | Live protocol breakdown, top talkers and connection counts from Zeek logs |
| 3 | Anomaly & Suspicious-Activity Alerting | Charan M | Flags predefined suspicious patterns (e.g. port scans) with timestamp, source, reason and priority |
| 4 | Session History, Storage & Export | Vaghasiya Akshar Arvindbhai | Local session index, browsing, and export of `.pcap` and/or Zeek logs |

## How it works

```
Network interface -> Capture (.pcap) -> Zeek (conn/dns/http/notice logs)
                  -> Summary + Alerts (Python) -> Session storage / export
```

1. The Raspberry Pi captures traffic from one network interface (an ESP32 may be used as an auxiliary component if the final hardware design requires it).
2. Zeek parses protocols and writes structured logs; its detection scripts flag anomalies.
3. A Python application reads the logs in real time and renders a simplified summary and alert list.
4. Raw captures and Zeek logs are saved locally and can be exported.

## Architecture

A layered design with adjacent-layer-only calls:

**Presentation (Python UI) -> Controllers -> Services -> Engines & Data**

- **Services:** `CaptureService`, `LogReader` (Zeek integration), `SummaryService`, `AlertService`, `SessionStore`
- **Cross-cutting:** `Validator` (input checks) and `Logger`
- **Engines & data:** libpcap/NIC, Zeek, `.pcap` and Zeek log files, SQLite session index

Details, sequence diagrams and interface signatures are in the Architecture and Design Specification (SAD).

## Tech stack

- Python 3 (control application and UI)
- Zeek (standard and extended detection scripts)
- libpcap-based capture (e.g. tcpdump)
- SQLite (session index)
- Raspberry Pi (optional ESP32)
- Testing / CI: pytest, pytest-cov, tcpreplay, nmap, Bandit, SonarQube, Jenkins, Docker, GitHub

## Getting started

> The project is currently in the design phase; commands below describe the intended workflow and will be finalised during implementation.

**Prerequisites**

- Raspberry Pi (or equivalent Linux single-board computer) with a supported network interface
- Python 3 and Zeek installed
- Permission to capture packets on the interface
- Use only on networks you own or are authorised to monitor

**Typical session**

1. Launch the application and select a network interface.
2. Optionally set a capture duration and/or a protocol filter.
3. Start the capture and watch the live dashboard.
4. Enable alerting to see flagged events.
5. Stop the capture, then browse past sessions and export a `.pcap` or Zeek logs.

## Testing

Each module is testable independently using pre-recorded `.pcap` files, with no live network hardware required. The plan covers unit, integration, system, performance, usability and security tests (see the Test Plan).

Key targets:

- Dashboard refreshes within 2 seconds (NFR-01)
- 5 Mbps replayed traffic with at most 1% packet loss (NFR-02)
- Interface disconnect handled with user notification within 5 seconds (NFR-03)
- A new user finds the top talker within 5 minutes (NFR-05)

## Security and privacy

- Captured data is stored locally by default; nothing is transmitted off the device (SEC-01)
- Session files are readable only by the owning user (SEC-02)
- All user input is validated and never passed unsanitised to a shell (SEC-03)
- Passive operation only; no probe packets are injected (SEC-04)
- Exports are written only to the chosen destination with sanitised names (SEC-05)

## Scope

**In scope:** one interface at a time; Zeek-based parsing; protocol breakdown, top talkers and connection counts; alerts for patterns supported by Zeek; local storage and export.

**Out of scope:** replacing Wireshark, a SIEM or an enterprise monitoring platform; unrestricted deep packet inspection; multi-device correlation; custom signatures beyond Zeek's default/extended scripts.

## Future scope

- Multiple simultaneous capture interfaces
- More targeted Zeek detection scripts
- Onboard LCD for standalone use
- Lightweight remote dashboard over the local network
- Trend analysis across stored sessions

## Documentation

- Synopsis / Project Proposal
- Software Requirements Specification (SRS) v2.0
- Software Test Plan (STP) v1.0
- Software Architecture and Design Specification (SAD) v1.0



## Responsible use

Capture traffic only on networks you own or have explicit permission to monitor. Captured data may contain sensitive information; handle and share exported sessions accordingly.
