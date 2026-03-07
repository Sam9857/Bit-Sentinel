# 🛡️ ipwnedyou
## AI-Based Cyber Threat Detection & Prevention System

> *"We detect before you connect."*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-orange?style=flat-square)](https://scikit-learn.org)
[![Phases](https://img.shields.io/badge/Phases-1--5%20Complete-brightgreen?style=flat-square)]()

---

## 📌 Project Overview

**BitSentinel** is a full-stack, real-time cybersecurity dashboard that ingests server
log files or live IP data, runs them through a multi-layer AI threat detection pipeline,
and lets you block malicious actors with a single click — inside a dark cyberpunk UI.

No cloud dependency. No external database. Runs on any machine in under 60 seconds.

---

## ✨ Feature Matrix

| Category | Feature |
|---|---|
| **Detection** | Log file scanner (.log / .txt / .csv) |
| **Detection** | SQL Injection, XSS, Path Traversal regex detection |
| **Detection** | Brute Force + High-Frequency / DDoS flagging |
| **AI** | Composite risk score 0–100 (Green / Yellow / Red) |
| **Prevention** | Auto-block engine with configurable threshold |
| **Prevention** | Manual IP blacklist with metadata (reason, score, timestamp) |
| **Prevention** | IP whitelist — trusted IPs never auto-blocked |
| **Prevention** | Sliding-window rate limiter per IP |
| **Real-time** | Server-Sent Events (SSE) live dashboard push |
| **Real-time** | Danger alert overlay on critical detections |
| **Dashboard** | Live threat trend chart, activity timeline, IP detail modal |
| **Dashboard** | JSON report export, threat history |
| **UI** | Particle network, glitch logo, multi-dot cursor trail |
| **UI** | CRT scan line, button ripple, card entrance animations |
| **UI** | Boot terminal, theme intensity slider, keyboard shortcuts |
| **Config** | Live config panel (threshold, rate limit, brute-force limit) |
| **Config** | Auto-block simulation / dry-run testing |

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x |
| AI | NumPy, Pandas |
| Streaming | Flask Server-Sent Events (SSE) |
| Frontend | HTML5, CSS3, Vanilla JavaScript ES2020 |
| Storage | JSON flat files (zero-dependency persistence) |
| Deployment | Gunicorn (production) / Flask dev server |

---

## 📂 Project Structure

```
ipwnedyou/
├── app.py                     # Flask entry point — registers all blueprints
├── data_watcher.py            # Read-only helpers for SSE stream
├── requirements.txt
├── README.md
├── SETUP.md                   # Step-by-step setup guide
├── .gitignore
│
├── data/
│   ├── blacklist.json         # Blocked IPs (with metadata)
│   ├── whitelist.json         # Trusted IPs
│   ├── threats.json           # Persisted threat history
│   └── config.json            # Prevention system configuration
│
├── models/
│   ├── anomaly_model.py       # IsolationForest wrapper (singleton)
│   ├── threat_detector.py     # Regex pattern + behaviour analysis
│   └── prevention_engine.py   # Auto-block, whitelist, blacklist engine
│
├── routes/
│   ├── api_routes.py          # Core REST API (/api/*)
│   ├── prevention_routes.py   # Prevention REST API (/api/prevention/*)
│   └── stream_routes.py       # SSE streams + IP detail (/stream/* /api/ip/*)
│
├── utils/
│   ├── log_parser.py          # Multi-format log parser + IP aggregation
│   ├── risk_scoring.py        # Weighted composite risk scorer (0–100)
│   └── rate_limiter.py        # In-memory sliding window rate limiter
│
├── static/
│   ├── css/style.css          # Dark cyberpunk stylesheet (all phases)
│   └── js/
│       ├── dashboard.js       # API calls, feed rendering, panels
│       ├── realtime.js        # SSE client, live chart, timeline, modal
│       └── animations.js      # 14-effect animation engine
│
└── templates/
    └── index.html             # Single-page dashboard
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/yourname/ipwnedyou.git
cd ipwnedyou
pip install -r requirements.txt
python app.py
# → Open http://localhost:5000
```

Press **`?`** for keyboard shortcuts once the dashboard loads.

---

## 🖥 Installation

### Windows

```bat
git clone https://github.com/yourname/ipwnedyou.git
cd ipwnedyou
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

### Linux / macOS

```bash
git clone https://github.com/yourname/ipwnedyou.git
cd ipwnedyou
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Production (Gunicorn)

```bash
pip install gunicorn
gunicorn -w 2 -b 0.0.0.0:5000 --timeout 120 app:app
```

> ⚠️ Use `-w 1` or `--worker-class gthread` to ensure SSE connections share state correctly.

---

## 🌐 API Reference

### Core API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | System stats snapshot |
| `GET` | `/api/threats` | All threat records (newest first) |
| `GET` | `/api/blacklist` | Blocked IPs with metadata |
| `POST` | `/api/block` | Block an IP `{"ip":"x.x.x.x"}` |
| `POST` | `/api/unblock` | Unblock an IP `{"ip":"x.x.x.x"}` |
| `POST` | `/api/scan/ip` | Scan single IP (JSON body) |
| `POST` | `/api/scan/log` | Upload + scan log file (multipart) |
| `GET` | `/api/report` | Full JSON threat report |
| `POST` | `/api/clear` | Wipe threat history |

### Prevention API

| Method | Endpoint | Description |
|---|---|---|
| `GET/POST` | `/api/prevention/config` | Read / update config |
| `GET` | `/api/prevention/whitelist` | List trusted IPs |
| `POST` | `/api/prevention/whitelist/add` | Add trusted IP |
| `POST` | `/api/prevention/whitelist/remove` | Remove trusted IP |
| `GET` | `/api/prevention/blacklist` | Enhanced blacklist |
| `GET` | `/api/prevention/ratelimit` | All rate-limit data |
| `POST` | `/api/prevention/ratelimit/reset` | Reset rate counters |
| `POST` | `/api/prevention/simulate` | Dry-run auto-block test |
| `GET` | `/api/prevention/stats` | Aggregated statistics |

### Stream API

| Method | Endpoint | Type | Description |
|---|---|---|---|
| `GET` | `/stream/threats` | **SSE** | Live push every 3s |
| `GET` | `/stream/stats` | **SSE** | Stats-only push every 5s |
| `GET` | `/api/ip/<ip>` | REST | Full IP status card |
| `GET` | `/api/activity` | REST | Activity timeline |
| `POST` | `/api/activity/clear` | REST | Clear activity log |

### Example requests

```bash
# Scan IP
curl -X POST http://localhost:5000/api/scan/ip \
  -H "Content-Type: application/json" \
  -d '{"ip":"10.0.0.55","failed_attempts":12,"request_count":350,"error_rate":0.82}'

# Scan log file
curl -X POST http://localhost:5000/api/scan/log -F "file=@SAMPLE_LOG.log"

# Update threshold
curl -X POST http://localhost:5000/api/prevention/config \
  -H "Content-Type: application/json" \
  -d '{"auto_block_threshold":70}'

# Get full IP status
curl http://localhost:5000/api/ip/192.168.1.100
```

---

## 🎯 Risk Score Algorithm

```
Score = min(100, sum of:
  failed_attempts × 3       (capped at 30)
  Brute Force flag  × 25
  High Freq flag    × 20
  SQL Injection     × 30
  XSS               × 25
  Path Traversal    × 20
  Auth Failure      × 10
  Error Rate (0–1)  × 15
)
```

| Score | Level | Colour |
|---|---|---|
| 0–30 | ✅ Safe | `#00ff88` |
| 31–60 | ⚠️ Suspicious | `#ffdd00` |
| 61–100 | 🔴 Danger | `#ff3333` |

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|---|---|
| `R` | Refresh all dashboard panels |
| `Esc` | Close modal / dismiss danger alert |
| `?` | Toggle keyboard shortcut help popup |

---

## 🔍 Supported Log Formats

**Apache / Nginx Combined:**
```
192.168.1.1 - - [20/Feb/2025:10:00:00 +0000] "POST /login HTTP/1.1" 401 512
```

**Simple format:**
```
2025-02-20T10:00:00 10.0.0.5 401 GET /admin
```

Any line containing a valid IPv4 address is parsed as a fallback.

---

## 🔮 Future Improvements

- WebSocket (Socket.IO) bidirectional events
- GeoIP world-map visualisation of attacker origins
- Email / Slack / webhook alerts on threshold breach
- SQLite / PostgreSQL for persistent storage at scale
- SIEM export (Splunk / ELK / Graylog JSON)
- Docker Compose with Nginx reverse proxy
- ML retraining on real production log data
- CVE pattern cross-referencing
- API key authentication on all endpoints
- Role-based access control for the dashboard

---

## 🏆 Hackathon Pitch Summary

### The Problem
Organisations lose an average of **207 days** before detecting a breach
(IBM Cost of Data Breach Report 2023). Log files sit unread while attacks escalate.

### Our Solution — BitSentinel
Compresses mean-time-to-detect from **207 days → seconds:**

1. **Drop any server log** → instant multi-layer AI analysis
2. **Regex rules** catch SQLi, XSS, Path Traversal, Brute Force instantly
3. **Auto-block engine** removes threats before they escalate
4. **Live SSE dashboard** shows every event as it happens
5. **Zero infrastructure** — runs offline, no data leaves your server

### Competitive Differentiation

| Feature | ipwnedyou | Traditional SIEM |
|---|---|---|
| Setup time | **< 60 seconds** | Days to weeks |
| Cost | **Free / Open Source** | $$$$$ |
| Real-time push (SSE) | ✅ | Usually polling |
| Offline / air-gapped | ✅ | Rare |
| UI engagement | **Cyberpunk 🔥** | Corporate grey |

### The Pitch
> Bitsentinel is the security tool that defenders actually want to open.
> We turn raw log noise into actionable threat intelligence in real time,
> with a zero-config AI engine and a UI that makes threat hunting feel like a mission.

---

*MIT License — ipwnedyou team — Built across 5 phases* 🛡️