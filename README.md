# CyberTrace

CyberTrace is a network security monitoring and threat analysis platform for authorized, educational use. It reads PCAP and PCAPNG files, and it can monitor a local interface when packet capture is permitted. Both paths normalize packets and use the same detection engine.

The database stores sessions, flow summaries, protocol events, findings, alerts, indicators, timeline entries, and report records. Raw packets are not stored. Uploaded capture files are deleted after analysis.

Severity and confidence are separate. A detector sets confidence from the evidence. A fixed policy sets severity for that detector. Alerts keep both values.

CyberTrace does not inject packets, exploit hosts, or collect credentials. Cleartext Telnet and FTP are recognized by port, not by reading session contents.

## Run

Python 3.11 or newer.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

On macOS or Linux, activate with `source .venv/bin/activate`.

Open `http://127.0.0.1:8000/`.

Live capture on Windows needs Npcap and permission to open an interface. If that is unavailable, the Live Monitoring page explains it. PCAP analysis does not need Npcap.

Optional environment variables:

| Variable | Purpose |
|---|---|
| `CYBERTRACE_DATABASE_URL` | SQLAlchemy database URL |
| `CYBERTRACE_DATA_DIR` | Directory for SQLite, uploads, and reports |
| `CYBERTRACE_MAX_UPLOAD_BYTES` | Upload size limit |
| `CYBERTRACE_MAX_PACKETS` | Packets read from one file |
| `CYBERTRACE_LIVE_MAX_PACKETS` | Packets kept during a live capture |
| `CYBERTRACE_LIVE_MAX_DURATION` | Longest live capture, in seconds |

## Tests

```bash
python -m unittest discover -s tests -t . -v
```

## API

- `GET /health`
- `POST /api/analyses/pcap`
- `GET /api/analyses` and `GET /api/analyses/{id}`
- `GET /api/analyses/{id}/flows`
- `GET /api/analyses/{id}/hosts`
- `GET /api/analyses/{id}/alerts`
- `GET /api/analyses/{id}/iocs`
- `GET /api/analyses/{id}/timeline`
- `GET /api/analyses/{id}/reports/json`
- `GET /api/analyses/{id}/reports/pdf`
- `GET /api/interfaces`
- `POST /api/live/start`
- `POST /api/live/stop`
- `WS /ws/live/{id}`
