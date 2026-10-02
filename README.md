# CyberTrace — Network Security Analysis & Detection Platform

<p align="center">
  <strong>PCAP Analysis · Network Detection · Live Monitoring · IOC Extraction · Security Reporting</strong>
</p>

<p align="center">
  A network security analysis platform for investigating network traffic,
  detecting suspicious behavior, extracting indicators of compromise,
  and generating structured security reports.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/FastAPI-0.x-009688?style=flat-square&logo=fastapi&logoColor=white">
  <img src="https://img.shields.io/badge/SQLite-3-003B57?style=flat-square&logo=sqlite&logoColor=white">
  <img src="https://img.shields.io/badge/Scapy-Network%20Analysis-1F2937?style=flat-square">
  <img src="https://img.shields.io/badge/License-Educational-6B7280?style=flat-square">
</p>

---

## Demo

![CyberTrace Demo](docs/demo/cybertrace-demo.gif)

CyberTrace provides a unified workflow for offline PCAP analysis and live network monitoring.

The platform processes network traffic through a common analysis pipeline:

```text
PCAP / Live Traffic
        ↓
   Normalization
        ↓
   Flow Assembly
        ↓
 Feature Extraction
        ↓
 Detection Engine
        ↓
     Findings
        ↓
 Alert & Risk Engine
        ↓
 IOC Extraction
        ↓
     Timeline
        ↓
 Investigation & Reporting
```

---

## Overview

CyberTrace is a network security analysis platform designed to transform network traffic into structured security information.

It supports two primary input sources:

* PCAP / PCAPNG files
* Live network interfaces

Instead of storing raw packets in the application database, CyberTrace processes traffic into investigation-oriented data such as:

* Network flows
* Hosts
* Connections
* Protocol statistics
* Security findings
* Alerts
* Indicators of compromise
* Timeline events

The system separates **detection confidence** from **alert severity**, allowing evidence strength and potential impact to be represented independently.

---

## Core Capabilities

### PCAP Analysis

CyberTrace can analyze `.pcap` and `.pcapng` network captures and extract information including:

* Packet and byte counts
* Source and destination IP addresses
* MAC addresses
* Ports
* TCP / UDP traffic
* ARP traffic
* ICMP traffic
* DNS activity
* HTTP activity
* TLS traffic
* Network flows
* TCP connections

![PCAP Analysis](docs/screenshots/pcap-analysis.png)

---

### Detection Engine

The detection engine evaluates normalized network behavior using specialized detection components.

Current detection areas include:

| Detection           | Purpose                                                |
| ------------------- | ------------------------------------------------------ |
| ARP Mapping Anomaly | Identifies suspicious IP–MAC mapping changes           |
| Port Scan           | Detects suspicious multi-port connection attempts      |
| Network Scan        | Identifies broader scanning behavior                   |
| SYN Burst / Anomaly | Detects unusual concentrations of TCP SYN traffic      |
| Beaconing           | Identifies repeated connections with regular timing    |
| DNS Anomaly         | Detects unusual DNS behavior                           |
| ICMP Anomaly        | Identifies unusual ICMP activity                       |
| HTTP Anomaly        | Detects suspicious HTTP characteristics                |
| Cleartext Protocol  | Identifies potentially sensitive unencrypted protocols |
| Volume Outlier      | Detects unusually large traffic volumes                |
| Custom Rules        | Supports configurable detection rules                  |

---

## Confidence & Severity

CyberTrace intentionally separates **confidence** from **severity**.

### Confidence

Confidence represents how strongly the observed evidence supports a detector's hypothesis.

```text
0.0 ─────────────────────────────── 1.0
Weak evidence                 Strong evidence
```

### Severity

Severity represents the potential impact associated with an alert.

```text
INFO
LOW
MEDIUM
HIGH
CRITICAL
```

This separation prevents detection confidence from being treated as the same concept as security impact.

---

## Alert Investigation

Each alert can provide contextual information including:

* Event type
* Severity
* Confidence
* First observed time
* Last observed time
* Source IP
* Source MAC
* Destination IP
* Destination port
* Protocol
* Detection rule
* Explanation
* Evidence
* Recommended action

![Alert Detail](docs/screenshots/alert-detail.png)

---

## Real Traffic Analysis

CyberTrace has been tested against a real network traffic capture.

Example analysis:

```text
Packets:   73,779
Flows:        641
Hosts:         42
Protocols:      4
Alerts:         7
IOCs:         131
```

One observed pattern involved repeated HTTPS connections:

```text
10.9.11.135 → 104.21.43.143:443
```

Seven connections were observed with approximately 48-second intervals.

The behavior was independently inspected at packet level and compared with CyberTrace's detection output.

This provides a workflow from network-level evidence to higher-level security findings.

---

## Investigation Workflow

```text
Network Traffic
      ↓
Normalization
      ↓
Flow Construction
      ↓
Feature Extraction
      ↓
Detection
      ↓
Finding
      ↓
Alert Correlation
      ↓
IOC Extraction
      ↓
Timeline
      ↓
Investigation
      ↓
Report
```

---

## Host Analysis

CyberTrace provides host-oriented investigation views.

For each observed host, the platform can display:

* IP address
* MAC address
* Packet activity
* Protocols
* Connections
* Ports
* Domains
* Related alerts
* Timeline events

![Host Analysis](docs/screenshots/host-analysis.png)

---

## IOC Extraction

CyberTrace extracts investigation-relevant indicators from analyzed network traffic.

Supported IOC categories include:

* IP addresses
* MAC addresses
* Domains
* Ports
* URIs
* User-Agent values
* Timestamps

![IOC Analysis](docs/screenshots/iocs.png)

---

## Timeline

Security-relevant events are organized chronologically to support investigation and correlation.

The timeline can contain:

* Network activity
* Detection events
* Alerts
* IOC observations
* First/last seen timestamps

![Timeline](docs/screenshots/timeline.png)

---

## Live Network Monitoring

CyberTrace also supports live network monitoring through a selected network interface.

The monitoring interface provides real-time visibility into:

* Packets
* TCP traffic
* UDP traffic
* DNS traffic
* ARP traffic
* ICMP traffic
* Active connections
* Security events

![Live Monitoring](docs/screenshots/live-monitoring.png)

The live monitoring pipeline follows the same analysis concepts used for offline PCAP processing.

---

## Traffic Visualization

PCAP analysis includes visualizations generated from the observed capture data.

Available visualizations include:

* Traffic over time
* Packets per second
* Protocol distribution
* Byte / traffic volume

The visualizations are generated from analyzed traffic rather than predefined or synthetic datasets.

---

## Reporting

CyberTrace supports structured analysis reporting.

### JSON Reports

JSON reports provide machine-readable analysis results suitable for further processing or integration.

### PDF Reports

PDF reports provide a structured representation of the investigation, including relevant findings, alerts, IOCs, timeline information, and traffic statistics.

![Reports](docs/screenshots/reports.png)

---

## Performance

Initial benchmark measurements were performed using generated PCAP datasets.

| Dataset | Packets | Processing Time | Approx. Throughput |
| ------- | ------: | --------------: | -----------------: |
| 10 MB   |   8,336 |        20.605 s |    404.6 packets/s |
| 50 MB   |  41,677 |       103.618 s |    402.2 packets/s |
| 100 MB  |  83,353 |       246.831 s |    337.7 packets/s |

These measurements reflect the development environment and should not be interpreted as hardware-independent performance guarantees.

---

## Testing

CyberTrace includes automated tests covering major application components, including:

* Packet normalization
* Flow assembly
* Feature extraction
* Detection rules
* IOC extraction
* Risk and severity handling
* Timeline generation
* Database persistence
* API behavior
* PCAP / PCAPNG processing
* Rule management
* Context and intelligence components

Additional controlled security scenarios are being prepared for:

1. Normal traffic
2. ARP spoofing / MITM
3. Port scanning
4. SYN anomaly
5. DNS anomaly
6. Live monitoring

Detailed validation reports will be added as the corresponding test scenarios are completed.

---

## Security & Ethical Use

CyberTrace is intended for authorized and educational network security analysis.

Appropriate use cases include:

* Authorized network analysis
* Security education
* Controlled laboratory environments
* Defensive security research
* Analysis of authorized PCAP files

CyberTrace does not perform:

* Packet injection
* Host exploitation
* Credential collection
* Unauthorized network access
* Automated offensive actions

All testing should be performed against systems and network traffic for which the operator has explicit authorization.

---

## Technology Stack

### Backend

* Python
* FastAPI
* SQLAlchemy
* SQLite
* Scapy

### Frontend

* HTML5
* CSS3
* JavaScript
* WebSocket

### Network Analysis

* PCAP / PCAPNG
* Flow analysis
* TCP
* UDP
* ARP
* ICMP
* DNS
* HTTP
* TLS

### Reporting

* JSON
* PDF

### Testing

* Python `unittest`
* PCAP fixtures
* Performance benchmarks

---

## Interface

CyberTrace provides a security-focused web interface with:

* Dark mode
* Light mode
* English
* Turkish
* Arabic
* RTL support
* Responsive layouts
* Contextual technical explanations
* Interactive traffic visualizations

### Dashboard

![Dashboard](docs/screenshots/dashboard.png)

### Settings

![Settings](docs/screenshots/settings1.png)

![Settings](docs/screenshots/settings2.png)

---

## Project Structure

```text
CyberTrace/
│
├── app/
│   ├── api/
│   ├── alerts/
│   ├── context/
│   ├── core/
│   ├── detection/
│   ├── features/
│   ├── ingestion/
│   ├── intel/
│   ├── ioc/
│   ├── notify/
│   ├── persistence/
│   ├── reporting/
│   ├── risk/
│   └── services/
│
├── web/
│   ├── index.html
│   ├── css/
│   ├── js/
│   └── locales/
│
├── tests/
│   ├── unit/
│   ├── fixtures/
│   └── performance/
│
├── docs/
│   ├── demo/
│   │   └── cybertrace-demo.gif
│   └── screenshots/
│
├── data/
├── README.md
├── requirements.txt
└── .gitignore
```

---

## Project Status

CyberTrace is under active development.

Implemented areas include:

* PCAP analysis
* PCAPNG support
* Network flow construction
* Feature extraction
* Detection engine
* Alert correlation
* Confidence and severity handling
* IOC extraction
* Timeline generation
* SQLite persistence
* JSON/PDF reporting
* Live monitoring
* WebSocket updates
* Rule management
* Custom rules
* Multi-language interface
* Dark/light theme
* Investigation-oriented web interface

Further validation and refinement are ongoing.

---

## Roadmap

Planned improvements include:

* Expanded detection coverage
* Additional PCAP validation scenarios
* Extended performance benchmarking
* Improved live traffic validation
* GeoIP enrichment
* Threat intelligence integrations
* Additional custom detection rules
* Expanded investigation workflows
* Further reporting improvements

---

## Screenshots

Additional interface views:

### Dashboard

![Dashboard](docs/screenshots/dashboard.png)

### PCAP Analysis

![PCAP Analysis](docs/screenshots/pcap-analysis.png)

### Alert Investigation

![Alert Detail](docs/screenshots/alert-detail.png)

### Host Analysis

![Host Analysis](docs/screenshots/host-analysis.png)

### IOC Investigation

![IOC Analysis](docs/screenshots/iocs.png)

### Live Monitoring

![Live Monitoring](docs/screenshots/live-monitoring.png)

### Timeline

![Timeline](docs/screenshots/timeline.png)

### Reports

![Reports](docs/screenshots/reports.png)

---

## Author

**Zeynep Ulucan**

Forensic Informatics Engineering
Fırat University

Cybersecurity · Network Security · Digital Forensics · Data Analysis

---

## License

This project is developed for educational, research, and authorized defensive security purposes.

Refer to the repository license for applicable usage and distribution terms.
