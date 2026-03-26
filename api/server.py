#!/usr/bin/env python3
# =============================================================================
# api/server.py — REST API for Blocked IP List
# Run: python3 api/server.py
# =============================================================================

import sys
import json
import logging
from pathlib      import Path
from datetime     import datetime, timezone
from http.server  import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.config import API_HOST, API_PORT, API_TOKEN, SCRIPT_LOG
from config.db     import cursor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(SCRIPT_LOG),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("ntopng.api")


# ══════════════════════════════════════════════════════════════════════════════
# Route Handlers
# ══════════════════════════════════════════════════════════════════════════════

def handle_blocked_ips(params: dict) -> tuple[int, dict]:
    """GET /api/v1/blocked-ips"""
    page        = max(1,   int(params.get("page",   ["1"])[0]))
    per_page    = min(500, int(params.get("per_page",["50"])[0]))
    active_only = params.get("active", ["1"])[0] not in ("0", "false", "no")
    country     = params.get("country", [None])[0]
    offset      = (page - 1) * per_page

    where_clauses = []
    bind_vals     = []

    if active_only:
        where_clauses.append("is_active = 1")
    if country:
        where_clauses.append("country = %s")
        bind_vals.append(country)

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    with cursor() as cur:
        cur.execute(f"SELECT COUNT(*) AS total FROM blocked_ips {where_sql}", bind_vals)
        total = cur.fetchone()["total"]

        cur.execute(f"""
            SELECT id, ip, asn, country, city, blacklist_source,
                   first_seen, last_seen, attack_count, block_hours,
                   blocked_until, is_active, abuse_email, abuse_sent_at
            FROM blocked_ips
            {where_sql}
            ORDER BY last_seen DESC
            LIMIT %s OFFSET %s
        """, bind_vals + [per_page, offset])
        rows = cur.fetchall()

    # Serialize datetime objects
    def serialize_row(r):
        out = {}
        for k, v in r.items():
            out[k] = v.isoformat() if isinstance(v, datetime) else v
        return out

    return 200, {
        "status":     "ok",
        "pagination": {
            "page":       page,
            "per_page":   per_page,
            "total":      total,
            "total_pages": -(-total // per_page),
        },
        "data": [serialize_row(r) for r in rows],
    }


def handle_blocked_ip_detail(ip: str) -> tuple[int, dict]:
    """GET /api/v1/blocked-ips/<ip>"""
    with cursor() as cur:
        cur.execute("SELECT * FROM blocked_ips WHERE ip = %s", (ip,))
        row = cur.fetchone()
        if not row:
            return 404, {"status": "error", "message": f"IP {ip} not found"}

        cur.execute("""
            SELECT id, cli_ip, cli_name, cli_country, score, alert_type,
                   blacklist_source, proto, srv_port, flow_risk,
                   source_server, event_time
            FROM attack_events
            WHERE blocked_ip_id = %s
            ORDER BY event_time DESC
            LIMIT 50
        """, (row["id"],))
        events = cur.fetchall()

        cur.execute("""
            SELECT to_email, cc_emails, sent_at, status
            FROM abuse_reports
            WHERE blocked_ip_id = %s
            ORDER BY sent_at DESC
            LIMIT 20
        """, (row["id"],))
        reports = cur.fetchall()

    def ser(v):
        return v.isoformat() if isinstance(v, datetime) else v

    return 200, {
        "status": "ok",
        "data": {
            "ip_info":      {k: ser(v) for k, v in row.items()},
            "events":       [{k: ser(v) for k, v in e.items()} for e in events],
            "abuse_reports":[{k: ser(v) for k, v in r.items()} for r in reports],
        },
    }


def handle_stats() -> tuple[int, dict]:
    """GET /api/v1/stats"""
    with cursor() as cur:
        cur.execute("""
            SELECT
                COUNT(*)                              AS total_ips,
                SUM(is_active)                        AS active_ips,
                SUM(attack_count)                     AS total_attacks,
                MAX(last_seen)                        AS last_attack_time,
                COUNT(DISTINCT country)               AS unique_countries
            FROM blocked_ips
        """)
        summary = cur.fetchone()

        cur.execute("""
            SELECT country, COUNT(*) AS ip_count, SUM(attack_count) AS attacks
            FROM blocked_ips
            GROUP BY country
            ORDER BY attacks DESC
            LIMIT 10
        """)
        top_countries = cur.fetchall()

        cur.execute("""
            SELECT blacklist_source, COUNT(*) AS ip_count
            FROM blocked_ips
            GROUP BY blacklist_source
            ORDER BY ip_count DESC
        """)
        by_blacklist = cur.fetchall()

        cur.execute("""
            SELECT started_at, finished_at, source_server,
                   lines_parsed, threats_found, new_ips,
                   repeat_ips, emails_sent, status
            FROM cron_runs
            ORDER BY started_at DESC
            LIMIT 10
        """)
        recent_runs = cur.fetchall()

    def ser(v):
        return v.isoformat() if isinstance(v, datetime) else v

    return 200, {
        "status": "ok",
        "data": {
            "summary":       {k: ser(v) for k, v in summary.items()},
            "top_countries": [{k: ser(v) for k, v in r.items()} for r in top_countries],
            "by_blacklist":  [{k: ser(v) for k, v in r.items()} for r in by_blacklist],
            "recent_runs":   [{k: ser(v) for k, v in r.items()} for r in recent_runs],
        },
    }


def handle_cron_runs(params: dict) -> tuple[int, dict]:
    """GET /api/v1/cron-runs"""
    limit = min(100, int(params.get("limit", ["20"])[0]))
    with cursor() as cur:
        cur.execute("""
            SELECT * FROM cron_runs
            ORDER BY started_at DESC
            LIMIT %s
        """, (limit,))
        rows = cur.fetchall()

    def ser(v):
        return v.isoformat() if isinstance(v, datetime) else v

    return 200, {
        "status": "ok",
        "data": [{k: ser(v) for k, v in r.items()} for r in rows],
    }


# ══════════════════════════════════════════════════════════════════════════════
# HTTP Handler
# ══════════════════════════════════════════════════════════════════════════════

class APIHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        logger.info(f"{self.client_address[0]} - {format % args}")

    def send_json(self, code: int, body: dict):
        payload = json.dumps(body, default=str, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type",   "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Powered-By",   "ntopng-analyzer")
        self.end_headers()
        self.wfile.write(payload)

    def _authenticate(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:] == API_TOKEN
        # Also accept ?token= query param
        return False

    def do_GET(self):
        parsed = urlparse(self.path)
        path   = parsed.path.rstrip("/")
        params = parse_qs(parsed.query)

        # Token via query string fallback
        if not self._authenticate():
            token_qs = params.get("token", [""])[0]
            if token_qs != API_TOKEN:
                self.send_json(401, {"status": "error", "message": "Unauthorized"})
                return

        try:
            # ── Route dispatch ────────────────────────────────────────────────
            if path == "/api/v1/blocked-ips":
                code, body = handle_blocked_ips(params)

            elif path.startswith("/api/v1/blocked-ips/"):
                ip = path.split("/api/v1/blocked-ips/", 1)[1]
                code, body = handle_blocked_ip_detail(ip)

            elif path == "/api/v1/stats":
                code, body = handle_stats()

            elif path == "/api/v1/cron-runs":
                code, body = handle_cron_runs(params)

            elif path in ("/", "/api/v1", "/api/v1/"):
                code, body = 200, {
                    "status":  "ok",
                    "service": "ntopng-analyzer API",
                    "version": "1.0",
                    "endpoints": [
                        "GET /api/v1/blocked-ips            — paginated blocked IP list",
                        "GET /api/v1/blocked-ips/<ip>       — detail + events for one IP",
                        "GET /api/v1/stats                  — global statistics",
                        "GET /api/v1/cron-runs              — recent cron run history",
                    ],
                }

            elif path == "/healthz":
                code, body = 200, {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}

            else:
                code, body = 404, {"status": "error", "message": "Endpoint not found"}

        except Exception as exc:
            logger.exception(f"Unhandled error for {self.path}")
            code, body = 500, {"status": "error", "message": str(exc)}

        self.send_json(code, body)


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    server = HTTPServer((API_HOST, API_PORT), APIHandler)
    logger.info(f"ntopng-analyzer API listening on {API_HOST}:{API_PORT}")
    logger.info(f"Auth: Bearer token required (set API_TOKEN env var)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("API server stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
