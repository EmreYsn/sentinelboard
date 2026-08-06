# 🛡️ SentinelBoard

**Lightweight, open-source SIEM platform built from scratch.**

SentinelBoard collects, normalizes, and correlates security logs from multiple sources in real time. It combines rule-based detection (Sigma-compatible) with ML-powered anomaly detection to surface threats that static rules miss.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Django](https://img.shields.io/badge/Django-5.x-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-In%20Development-orange)

---

## 🏗️ Architecture

```
Log Sources (auth.log, syslog, nginx, journalctl)
        │
        ▼
   ┌─────────┐
   │Collector │  ← Python agents (tail & forward)
   └────┬─────┘
        ▼
   ┌─────────┐
   │  Redis   │  ← Message queue (buffer & decouple)
   └────┬─────┘
        ▼
   ┌──────────┐
   │  Parser  │  ← Raw string → normalized JSON
   └────┬─────┘
        ├──────────────┬────────────────┐
        ▼              ▼                ▼
   ┌────────┐   ┌───────────┐   ┌───────────┐
   │PostgreSQL│   │Correlation│   │ ML Module │
   │(storage)│   │  Engine   │   │ (anomaly) │
   └────┬────┘   └─────┬─────┘   └─────┬─────┘
        │              │               │
        ▼              ▼               ▼
   ┌──────────────────────────────────────┐
   │   Django Dashboard + Alert System    │
   │   (WebSocket, Telegram, Email)       │
   └──────────────────────────────────────┘
```

## ✨ Features

- **Multi-source log collection** — auth.log, syslog, nginx access/error, journalctl
- **Real-time log normalization** — heterogeneous formats → unified JSON schema
- **Sigma-compatible correlation engine** — write detection rules in YAML
- **ML anomaly detection** — baseline learning + statistical deviation scoring
- **Live dashboard** — WebSocket-powered real-time log stream and alert timeline
- **Alert notifications** — Telegram bot and email alerts with severity levels

## 🛠️ Tech Stack

| Component       | Technology            | Why                                      |
|-----------------|-----------------------|------------------------------------------|
| Log Collection  | Python + watchdog     | Lightweight, easy to extend per source   |
| Message Queue   | Redis Streams         | Fast, built-in pub/sub, no JVM overhead  |
| Parsing         | Python + regex/grok   | Flexible pattern matching per source     |
| Storage         | PostgreSQL            | Reliable, great JSON support, familiar   |
| Correlation     | Python + YAML rules   | Sigma compatibility, human-readable      |
| ML Detection    | scikit-learn / PyTorch| Proven libraries, good for tabular data  |
| Backend         | Django + DRF          | Rapid development, ORM, auth built-in    |
| Frontend        | React (or Vue)        | Component-based, WebSocket support       |
| Alerts          | Telegram Bot API      | Instant mobile notifications             |

## 📁 Project Structure

```
sentinelboard/
├── collector/        # Log collection agents
├── parser/           # Log parsing & normalization
│   └── parsers/      # Per-source parser modules
├── engine/           # Correlation engine
│   └── rules/        # Sigma/YAML detection rules
├── ml/               # ML anomaly detection module
│   └── models/       # Trained model artifacts
├── dashboard/        # Django web application
├── alerts/           # Notification system
├── config/           # Global configuration
├── tests/            # Test suite
└── docs/             # Documentation
```

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/EmreYsn/sentinelboard.git
cd sentinelboard

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and edit environment variables
cp .env.example .env

# Start Redis and PostgreSQL (Docker)
docker-compose up -d

# Run database migrations
cd dashboard && python manage.py migrate

# Start the collector
python -m collector.main

# Start the dashboard
python dashboard/manage.py runserver
```

## 📊 Detection Rules (Sigma Format)

```yaml
title: SSH Brute Force Detection
status: active
level: high
detection:
  selection:
    event_type: auth_failure
    service: sshd
  condition: selection | count(src_ip) > 10
  timeframe: 5m
response:
  alert: true
  severity: high
  message: "Possible SSH brute force from {src_ip}"
```

## 🗺️ Roadmap

- [x] Week 1: Architecture design & project setup
- [ ] Week 2: Log collectors (auth, syslog, nginx)
- [ ] Week 3: Parser & normalization engine
- [ ] Week 4: Database schema & storage layer
- [ ] Week 5: Correlation engine + Sigma rules
- [ ] Week 6: Dashboard UI
- [ ] Week 7: Alert system (Telegram/email)
- [ ] Week 8: ML anomaly detection module
- [ ] Week 9-10: Testing, docs, production deploy

## 📝 License

MIT License — see [LICENSE](LICENSE) for details.

## 👤 Author

**Yasin Emre** — Cybersecurity & Digital Forensics
- Portfolio: [ysnemre.com](https://ysnemre.com)
- GitHub: [@EmreYsn](https://github.com/EmreYsn)
