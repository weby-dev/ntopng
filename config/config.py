# =============================================================================
# config/config.py — Central Configuration
# =============================================================================

import os

# ── Database ──────────────────────────────────────────────────────────────────
DB = {
    "host":     os.getenv("DB_HOST",     "127.0.0.1"),
    "port":     int(os.getenv("DB_PORT", "3306")),
    "user":     os.getenv("DB_USER",     "ntopng_user"),
    "password": os.getenv("DB_PASSWORD", "your_strong_password"),
    "database": os.getenv("DB_NAME",     "ntopng_threats"),
    "charset":  "utf8mb4",
}

# ── Log Settings ──────────────────────────────────────────────────────────────
LOG_BASE_DIR   = os.getenv("LOG_BASE_DIR", "/var/log/remote")
LOG_FILENAME   = "ntopng.log"
SCRIPT_LOG     = os.getenv("SCRIPT_LOG",  "/var/log/ntopng_analyzer/analyzer.log")

# ── Email / SMTP ──────────────────────────────────────────────────────────────
SMTP = {
    "host":       os.getenv("SMTP_HOST",     "localhost"),
    "port":       int(os.getenv("SMTP_PORT", "25")),
    "use_tls":    os.getenv("SMTP_TLS",      "false").lower() == "true",
    "username":   os.getenv("SMTP_USER",     ""),          # blank = no auth
    "password":   os.getenv("SMTP_PASS",     ""),
    "from_name":  os.getenv("SMTP_FROM_NAME","NOC Security Team"),
    "from_addr":  os.getenv("SMTP_FROM",     "noc@yourdomain.com"),
}

# ── Abuse Reporting ───────────────────────────────────────────────────────────
WHOIS_ABUSE_FALLBACK = "abuse@arin.net"   # fallback if WHOIS parse fails
RDAP_TIMEOUT         = 10                 # seconds

# ── Block Duration Policy ─────────────────────────────────────────────────────
# Each time the same IP is seen attacking again the block doubles.
# Values in hours.
BLOCK_DURATIONS = [24, 48, 96, 168, 336, 720]   # 1d → 2d → 4d → 7d → 14d → 30d
MAX_BLOCK_HOURS = 720

# ── Alert Thresholds ──────────────────────────────────────────────────────────
MIN_SCORE_TO_ALERT = 200          # only process flows with score >= this
BURST_WINDOW_SECS  = 300          # 5-minute window for burst detection

# ── API ───────────────────────────────────────────────────────────────────────
API_HOST  = os.getenv("API_HOST",  "0.0.0.0")
API_PORT  = int(os.getenv("API_PORT", "8765"))
API_TOKEN = os.getenv("API_TOKEN", "change-me-strong-token")
