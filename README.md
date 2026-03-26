# ntopng-analyzer — Production Setup Guide

## Project Layout

```
/opt/ntopng-analyzer/
├── config/
│   ├── config.py          ← All tuneable settings
│   ├── db.py              ← DB connection pool + schema
│   └── .env               ← Secrets (chmod 600)
├── scripts/
│   ├── analyzer.py        ← Core log parser & threat processor
│   ├── mailer.py          ← HTML abuse email builder + SMTP sender
│   ├── rdap_lookup.py     ← RDAP/WHOIS abuse-contact lookup
│   └── run_analyzer.sh    ← Cron wrapper shell script
├── api/
│   ├── server.py                    ← REST API (pure stdlib, no Flask needed)
│   └── ntopng-analyzer-api.service  ← systemd unit
├── requirements.txt
└── README.md
```

---

## 1. System Prerequisites

```bash
apt-get install -y python3 python3-venv python3-pip whois postfix
```

For Postfix — choose **"Internet Site"** during setup and set your hostname.

---

## 2. Create Dedicated User

```bash
useradd -r -s /sbin/nologin -d /opt/ntopng-analyzer ntopng-analyzer
```

---

## 3. Deploy Project

```bash
cp -r ntopng-analyzer/ /opt/ntopng-analyzer/
cd /opt/ntopng-analyzer

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

---

## 4. MySQL / MariaDB Setup

```sql
CREATE DATABASE ntopng_threats CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'ntopng_user'@'127.0.0.1' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON ntopng_threats.* TO 'ntopng_user'@'127.0.0.1';
FLUSH PRIVILEGES;
```

---

## 5. Configure .env

```bash
cp config/.env.example config/.env
nano config/.env          # fill in DB_PASSWORD, SMTP_FROM, API_TOKEN, etc.
chmod 600 config/.env
```

---

## 6. Bootstrap Database Schema

```bash
cd /opt/ntopng-analyzer
export $(cat config/.env | xargs)
.venv/bin/python3 -m scripts.analyzer --bootstrap
```

---

## 7. Set Permissions

```bash
mkdir -p /var/log/ntopng_analyzer
chown -R ntopng-analyzer:ntopng-analyzer /opt/ntopng-analyzer /var/log/ntopng_analyzer

# Analyzer needs read access to logs and write to truncate them
chown ntopng-analyzer:ntopng-analyzer /var/log/remote   # adjust as needed
```

---

## 8. Cron Job (twice an hour)

```bash
crontab -u ntopng-analyzer -e
```

Add:
```cron
0,30 * * * * /opt/ntopng-analyzer/scripts/run_analyzer.sh >> /var/log/ntopng_analyzer/cron.log 2>&1
```

---

## 9. API Server (systemd)

```bash
cp api/ntopng-analyzer-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ntopng-analyzer-api
systemctl status ntopng-analyzer-api
```

---

## 10. API Usage

### Authentication
All requests need a Bearer token header:
```
Authorization: Bearer <API_TOKEN>
```
Or as a query param: `?token=<API_TOKEN>`

### Endpoints

#### List all blocked IPs (paginated)
```bash
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8765/api/v1/blocked-ips?page=1&per_page=50&active=1"
```

Response:
```json
{
  "status": "ok",
  "pagination": { "page": 1, "per_page": 50, "total": 142, "total_pages": 3 },
  "data": [
    {
      "ip": "115.231.78.15",
      "country": "CN",
      "asn": 58461,
      "blacklist_source": "IPsum Threat Intelligence Feed",
      "attack_count": 7,
      "block_hours": 96,
      "blocked_until": "2026-03-29T10:00:00",
      "is_active": 1,
      "abuse_email": "abuse@chinatelecom.cn",
      "last_seen": "2026-03-26T22:42:01"
    }
  ]
}
```

#### Detail + full event history for one IP
```bash
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8765/api/v1/blocked-ips/115.231.78.15"
```

#### Filter by country
```bash
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8765/api/v1/blocked-ips?country=CN&active=1"
```

#### Global statistics
```bash
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8765/api/v1/stats"
```

#### Recent cron run history
```bash
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8765/api/v1/cron-runs?limit=10"
```

#### Health check (no auth)
```bash
curl "http://localhost:8765/healthz"
```

---

## Block Duration Escalation Policy

| Offence | Block Duration |
|---------|---------------|
| 1st     | 24 hours      |
| 2nd     | 48 hours      |
| 3rd     | 96 hours (4d) |
| 4th     | 168 hours (7d)|
| 5th     | 336 hours (14d)|
| 6th+    | 720 hours (30d)|

When an IP reappears after its block window expired, `is_active` is set back
to `1` and the duration escalates from where it left off.

When the log is clean and a block window has passed, `is_active` is
automatically set to `0` (removed from active block list).

---

## Manual Run (for testing)

```bash
cd /opt/ntopng-analyzer
export $(cat config/.env | xargs)

# Process all servers
.venv/bin/python3 -m scripts.analyzer --victim-cc noc@yourdomain.com

# Process one specific server
.venv/bin/python3 -m scripts.analyzer --server 161.248.163.18 \
    --victim-cc noc@yourdomain.com,security@yourdomain.com
```

---

## Log Files

| File | Purpose |
|------|---------|
| `/var/log/ntopng_analyzer/analyzer.log` | Main analyzer output |
| `/var/log/ntopng_analyzer/cron.log`     | Cron wrapper stdout/stderr |
| `/var/log/ntopng_analyzer/api.log`      | API server access + errors |
# ntopng
