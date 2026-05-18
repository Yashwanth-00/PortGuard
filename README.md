# PortGuard 🛡️

**Host-Based Network Security Monitor** — Real-time port monitoring, threat detection, and alerting for Linux systems.

---

## Features

| Feature | Description |
|---|---|
| 🔍 Real-Time Port Monitoring | Continuously scans system ports using `psutil` |
| ⚡ Threat Detection Engine | Classifies threats by severity: INFO → CRITICAL |
| 🗄️ Malicious Port Database | 30+ known dangerous ports with signatures |
| 📋 Logging System | Structured logs in `logs/portguard.log` |
| 🔔 Alert System | Console + desktop + optional email alerts |
| 🌐 Web Dashboard | Flask-powered real-time monitoring UI |
| ⚙️ systemd Service | Runs as a background Linux service |

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run CLI Monitor
```bash
python main.py
```

### 3. Run with Web Dashboard
```bash
python main.py --dashboard
# Then open http://localhost:5000
```

### 4. Custom scan interval
python main.py --interval 10 --dashboard --port 8080
```

---

## Project Structure

```
PortGuard/
├── core/
│   ├── port_scanner.py      # Port discovery via psutil
│   └── monitor_engine.py    # Background scan loop + event system
│
├── detection/
│   ├── threat_engine.py     # Threat classification engine
│   └── malicious_ports.json # Known malicious port signatures
│
├── alerts/
│   └── notifier.py          # Console / email / desktop alerts
│
├── dashboard/
│   ├── app.py               # Flask REST API + web server
│   └── templates/
│       └── index.html       # Cybersecurity-themed dashboard UI
│
├── logs/
│   └── portguard.log        # Runtime logs (auto-created)
│
├── services/
│   └── portguard.service    # systemd unit file
│
├── main.py                  # Entry point
├── requirements.txt
└── README.md
```

---

## Threat Categories

| Category | Severity | Description |
|---|---|---|
| `MALICIOUS_PORT` | HIGH–CRITICAL | Matches known dangerous port signatures |
| `SUSPICIOUS_EPHEMERAL_PORT` | MEDIUM | Ephemeral port (>49152) actively listening |
| `UNEXPECTED_PROCESS` | HIGH | Wrong process on a well-known port |
| `PORT_SCAN_PATTERN` | CRITICAL | Multiple malicious ports triggered in <60s |

---

## Known Malicious Ports (sample)

| Port | Service | Risk |
|---|---|---|
| 4444 | Metasploit Listener | CRITICAL |
| 31337 | Back Orifice Backdoor | CRITICAL |
| 6667 | IRC Botnet C2 | CRITICAL |
| 1337 | Trojan/Backdoor | CRITICAL |
| 3389 | RDP (ransomware target) | CRITICAL |
| 445 | SMB (EternalBlue) | CRITICAL |
| 23 | Telnet | CRITICAL |

---

## Installing as a System Service

```bash
# Copy to /opt
sudo cp -r . /opt/portguard

# Install service
sudo cp services/portguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable portguard
sudo systemctl start portguard

# Check status
sudo systemctl status portguard

# View logs
journalctl -u portguard -f
```

---

## Email Alerts (Optional)

Set environment variables before running:

```bash
export PG_EMAIL_TO="admin@example.com"
export PG_EMAIL_FROM="portguard@example.com"
export PG_SMTP_HOST="smtp.gmail.com"
export PG_SMTP_USER="your@gmail.com"
export PG_SMTP_PASS="app-password"
```

---

## CLI Options

```
usage: main.py [-h] [--interval INTERVAL] [--dashboard] [--port PORT] [--no-desktop]

options:
  --interval INT    Scan interval in seconds (default: 5)
  --dashboard       Start the web dashboard
  --port INT        Dashboard port (default: 5000)
  --no-desktop      Disable desktop notifications
```

---

## Requirements

- Python 3.8+
- Linux (tested on Ubuntu 20.04+)
- Root/sudo recommended for full port visibility
- `psutil`, `flask`

---

## License

MIT License — Built for educational and professional portfolio use.
