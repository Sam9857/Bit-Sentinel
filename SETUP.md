# ⚙️ ipwnedyou — Setup Guide

Complete installation and configuration guide for all platforms.

---

## Prerequisites

| Requirement | Minimum | Recommended |
|---|---|---|
| Python | 3.10 | 3.11+ |
| RAM | 256 MB | 512 MB+ |
| Disk | 50 MB | 100 MB |
| OS | Windows 10 / Ubuntu 20 / macOS 11 | Any modern OS |
| Browser | Chrome 90+ / Firefox 88+ | Latest Chrome |

---

## 🪟 Windows — Step by Step

### 1. Install Python
Download from https://python.org/downloads  
✅ Check **"Add Python to PATH"** during install.

Verify:
```bat
python --version
```

### 2. Clone / Download the project
```bat
git clone https://github.com/sam9857/ipwnedyou.git
cd ipwnedyou
```

Or download the ZIP and extract it.

### 3. Create Virtual Environment
```bat
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` in your prompt.

### 4. Install Dependencies
```bat
pip install -r requirements.txt
```

### 5. Run
```bat
python app.py
```

Open your browser at: **http://localhost:5000**

### 6. Test with Sample Log
In another terminal (with venv active):
```bat
curl -X POST http://localhost:5000/api/scan/log -F "file=@SAMPLE_LOG.log"
```

---

## 🐧 Linux / macOS — Step by Step

### 1. Install Python
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install python3 python3-pip python3-venv -y

# macOS (Homebrew)
brew install python3
```

### 2. Clone the project
```bash
git clone https://github.com/yourname/ipwnedyou.git
cd ipwnedyou
```

### 3. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Run
```bash
python app.py
```

Open: **http://localhost:5000**

---

## 🐳 Docker

### Option A — Build and run manually

Create a `Dockerfile` in the project root:

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

EXPOSE 5000
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]
```

```bash
docker build -t ipwnedyou .
docker run -p 5000:5000 ipwnedyou
```

### Option B — Docker Compose (with Nginx)

Create `docker-compose.yml`:

```yaml
version: "3.9"
services:
  app:
    build: .
    expose:
      - "5000"
    volumes:
      - ./data:/app/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - app
    restart: unless-stopped
```

Create `nginx.conf`:
```nginx
server {
    listen 80;
    location / {
        proxy_pass         http://app:5000;
        proxy_http_version 1.1;
        proxy_set_header   Connection "";
        proxy_buffering    off;
        proxy_cache        off;
        chunked_transfer_encoding on;
    }
}
```

> ⚠️ `proxy_buffering off` is required for SSE (Server-Sent Events) to work correctly through Nginx.

```bash
docker compose up -d
```

---

## 🏭 Production Deployment

### Gunicorn (recommended)

```bash
pip install gunicorn
gunicorn -w 1 -b 0.0.0.0:5000 --timeout 120 app:app
```

> Use `-w 1` to prevent multiple workers from diverging on the in-memory rate limiter and activity log.
> For multi-worker setups, replace JSON files with SQLite and the in-memory rate limiter with Redis.

### Systemd service (Linux)

Create `/etc/systemd/system/ipwnedyou.service`:

```ini
[Unit]
Description=ipwnedyou Threat Detection Dashboard
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/ipwnedyou
Environment="PATH=/opt/ipwnedyou/venv/bin"
ExecStart=/opt/ipwnedyou/venv/bin/gunicorn -w 1 -b 0.0.0.0:5000 --timeout 120 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable ipwnedyou
sudo systemctl start  ipwnedyou
sudo systemctl status ipwnedyou
```

---

## ⚙️ Configuration

Edit `data/config.json` or use the **Config** tab in the dashboard UI.

| Setting | Default | Description |
|---|---|---|
| `auto_block_enabled` | `true` | Enable auto-block engine |
| `auto_block_threshold` | `65` | Risk score (0–100) that triggers auto-block |
| `rate_limit_enabled` | `true` | Enable per-IP rate limiting |
| `rate_limit_max_requests` | `100` | Max requests per window |
| `rate_limit_window_seconds` | `60` | Sliding window duration in seconds |
| `brute_force_threshold` | `5` | Failed 401/403 attempts before flagging |
| `high_freq_threshold` | `100` | Requests per window before flagging |
| `max_threat_history` | `500` | Max records to keep in threats.json |

---

## 🔒 Security Recommendations for Production

1. **Change the SECRET_KEY** — set `SECRET_KEY` as an environment variable:
   ```bash
   export SECRET_KEY="your-very-long-random-secret-here"
   ```

2. **Restrict network access** — bind to `127.0.0.1` and use Nginx as reverse proxy

3. **HTTPS** — add SSL via Let's Encrypt / Certbot with Nginx

4. **File upload directory** — ensure `uploads/` is outside the web root and not publicly accessible

5. **Data directory** — keep `data/` files readable only by the app user:
   ```bash
   chmod 700 data/
   ```

---

## 🧪 Testing the Installation

### Quick smoke test
```bash
python -c "
from app import app
with app.test_client() as c:
    r = c.get('/api/status')
    assert r.status_code == 200
    print('OK:', r.get_json())
"
```

### Test all detection types
```bash
curl -X POST http://localhost:5000/api/scan/log \
  -F "file=@SAMPLE_LOG.log"
```

Expected response includes at least 1 `danger` level result.

### Test auto-block
```bash
curl -X POST http://localhost:5000/api/prevention/simulate \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","risk_score":85,"threat_types":["Brute Force","SQL Injection"]}'
```

Expected: `"action": "auto_blocked"`

---

## 🐛 Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: flask` | Run `pip install -r requirements.txt` in your venv |
| Port 5000 already in use | Run `python app.py` — it will error. Change port: `app.run(port=5001)` in `app.py` |
| SSE "CONNECTING…" stuck | Ensure `threaded=True` in `app.run()`. Check browser console for CORS errors |
| Log file not parsed | Check format — must contain a valid IPv4 address per line |
| Auto-block not triggering | Check `data/config.json` — confirm `auto_block_enabled: true` and threshold is correct |
| Upload fails with 413 | File exceeds 5 MB limit. Trim the log or increase `MAX_CONTENT_LENGTH` in `app.py` |
| Whitelist not preventing block | Confirm the IP is in `data/whitelist.json` under `trusted_ips` |

---

## 📞 Support

- Open an issue on GitHub
- Check `data/threats.json` for raw threat data
- Use the **Export Report** button for a JSON snapshot of all findings

---

*ipwnedyou — SETUP.md — Phase 5 Finalization*