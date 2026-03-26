#!/usr/bin/env python3
# =============================================================================
# scripts/analyzer.py — Core Log Parser & Threat Processor
# =============================================================================

import os
import sys
import json
import glob
import logging
import argparse
from datetime  import datetime, timedelta, timezone
from pathlib   import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.config   import (LOG_BASE_DIR, LOG_FILENAME, SCRIPT_LOG,
                              MIN_SCORE_TO_ALERT, BLOCK_DURATIONS,
                              MAX_BLOCK_HOURS)
from config.db       import cursor, bootstrap_schema
from scripts.mailer  import send_abuse_report
from scripts.rdap_lookup import get_abuse_email

# ── Logging Setup ─────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(SCRIPT_LOG), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(SCRIPT_LOG),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("ntopng.analyzer")


# ══════════════════════════════════════════════════════════════════════════════
# Log Parsing
# ══════════════════════════════════════════════════════════════════════════════

def discover_log_files(server_ip: str | None = None) -> list[tuple[str, str]]:
    """
    Returns list of (server_ip, log_path) tuples.
    If server_ip is given, only that server's log is returned.
    """
    results = []
    if server_ip:
        log_path = os.path.join(LOG_BASE_DIR, server_ip, LOG_FILENAME)
        if os.path.exists(log_path):
            results.append((server_ip, log_path))
    else:
        pattern = os.path.join(LOG_BASE_DIR, "*", LOG_FILENAME)
        for log_path in glob.glob(pattern):
            parts = log_path.replace(LOG_BASE_DIR, "").strip("/").split("/")
            if len(parts) >= 2:
                results.append((parts[0], log_path))
    return results


def parse_log_file(log_path: str) -> list[dict]:
    """Parse JSON-lines ntopng log. Returns list of parsed event dicts."""
    events = []
    errors = 0
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue

            # Syslog prefix: "2026-03-25T22:37:30+00:00 host ntopng[pid]: {json}"
            json_start = line.find("{")
            if json_start == -1:
                continue
            try:
                ev = json.loads(line[json_start:])
                events.append(ev)
            except json.JSONDecodeError:
                errors += 1
                if errors <= 5:
                    logger.warning(f"JSON parse error at line {lineno}: {line[:120]}")

    logger.info(f"Parsed {len(events)} events from {log_path} ({errors} errors)")
    return events


def filter_threats(events: list[dict]) -> list[dict]:
    """Keep only high-score, blacklisted-server-contact flows."""
    threats = []
    for ev in events:
        if ev.get("score", 0) < MIN_SCORE_TO_ALERT:
            continue
        if not ev.get("srv_blacklisted", False):
            continue
        if not ev.get("srv_ip"):
            continue
        threats.append(ev)
    logger.info(f"  → {len(threats)} threat flows after filtering")
    return threats


def enrich_event(ev: dict, source_server: str) -> dict:
    """Flatten and enrich a raw flow event into a clean record."""
    # Parse inner json blob if present
    inner = {}
    try:
        inner = json.loads(ev.get("json", "{}"))
    except Exception:
        pass

    flow_risk = " | ".join(inner.get("flow_risk_info", {}).values()) or "N/A"
    blacklist  = inner.get("blacklist", ev.get("cli_blacklisted", "Unknown"))

    alert_type = "unknown"
    alerts = inner.get("alerts", {})
    if "13" in alerts:
        alert_type = alerts["13"].get("alert_generation", {}).get("script_key", "blacklisted_server_contact")

    # Event timestamp — prefer tstamp field
    ts_raw = ev.get("tstamp") or ev.get("first_seen")
    try:
        event_time = datetime.fromtimestamp(ts_raw, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "srv_ip":          ev.get("srv_ip"),
        "srv_port":        ev.get("srv_port"),
        "srv_country":     ev.get("srv_country_name", ""),
        "srv_city":        ev.get("srv_city_name", ""),
        "srv_asn":         ev.get("srv_asn"),
        "cli_ip":          ev.get("cli_ip"),
        "cli_name":        ev.get("cli_name", ""),
        "cli_country":     ev.get("cli_country_name", ""),
        "score":           ev.get("score", 0),
        "alert_id":        ev.get("alert_id"),
        "alert_type":      alert_type,
        "blacklist":       blacklist,
        "proto":           ev.get("proto.ndpi", str(ev.get("proto", ""))),
        "bytes_srv2cli":   ev.get("srv2cli_bytes", 0),
        "flow_risk":       flow_risk,
        "event_time":      event_time,
        "source_server":   source_server,
        "raw_json":        json.dumps(ev)[:65535],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Database Operations
# ══════════════════════════════════════════════════════════════════════════════

def upsert_blocked_ip(ev: dict) -> tuple[int, bool]:
    """
    Insert or update blocked_ips row.
    Returns (blocked_ip_id, is_new).
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ip  = ev["srv_ip"]

    with cursor() as cur:
        cur.execute("SELECT * FROM blocked_ips WHERE ip = %s FOR UPDATE", (ip,))
        row = cur.fetchone()

        if row is None:
            # New IP — first offence
            block_hours   = BLOCK_DURATIONS[0]
            blocked_until = (datetime.now(timezone.utc) + timedelta(hours=block_hours)).strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("""
                INSERT INTO blocked_ips
                    (ip, asn, country, city, blacklist_source, first_seen,
                     last_seen, attack_count, block_hours, blocked_until, is_active)
                VALUES (%s,%s,%s,%s,%s,%s,%s,1,%s,%s,1)
            """, (ip, ev["srv_asn"], ev["srv_country"], ev["srv_city"],
                  ev["blacklist"], now, now, block_hours, blocked_until))
            blocked_ip_id = cur.lastrowid
            return blocked_ip_id, True

        else:
            # Existing IP — escalate block duration
            attack_count  = row["attack_count"] + 1
            idx           = min(attack_count - 1, len(BLOCK_DURATIONS) - 1)
            block_hours   = min(BLOCK_DURATIONS[idx], MAX_BLOCK_HOURS)
            blocked_until = (datetime.now(timezone.utc) + timedelta(hours=block_hours)).strftime("%Y-%m-%d %H:%M:%S")

            cur.execute("""
                UPDATE blocked_ips
                SET last_seen      = %s,
                    attack_count   = %s,
                    block_hours    = %s,
                    blocked_until  = %s,
                    is_active      = 1,
                    blacklist_source = %s
                WHERE id = %s
            """, (now, attack_count, block_hours, blocked_until,
                  ev["blacklist"], row["id"]))
            return row["id"], False


def insert_attack_event(blocked_ip_id: int, ev: dict) -> int:
    with cursor() as cur:
        cur.execute("""
            INSERT INTO attack_events
                (blocked_ip_id, srv_ip, cli_ip, cli_name, cli_country,
                 score, alert_id, alert_type, blacklist_source, proto,
                 srv_port, bytes_srv2cli, flow_risk, source_server,
                 event_time, raw_json)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            blocked_ip_id, ev["srv_ip"], ev["cli_ip"], ev["cli_name"],
            ev["cli_country"], ev["score"], ev["alert_id"], ev["alert_type"],
            ev["blacklist"], ev["proto"], ev["srv_port"], ev["bytes_srv2cli"],
            ev["flow_risk"], ev["source_server"], ev["event_time"], ev["raw_json"],
        ))
        return cur.lastrowid


def record_abuse_sent(blocked_ip_id: int, to_email: str,
                      cc_emails: list[str], subject: str,
                      status: str, error_msg: str = None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with cursor() as cur:
        cur.execute("""
            INSERT INTO abuse_reports
                (blocked_ip_id, to_email, cc_emails, subject, sent_at, status, error_msg)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (blocked_ip_id, to_email, json.dumps(cc_emails),
              subject, now, status, error_msg))
        # Update last sent timestamp on blocked_ips
        cur.execute("""
            UPDATE blocked_ips SET abuse_email = %s, abuse_sent_at = %s
            WHERE id = %s
        """, (to_email, now, blocked_ip_id))


def expire_old_blocks():
    """Mark IPs as inactive if their block window has passed and no new attacks."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with cursor() as cur:
        cur.execute("""
            UPDATE blocked_ips
            SET is_active = 0
            WHERE is_active = 1 AND blocked_until <= %s
        """, (now,))
        affected = cur.rowcount
    if affected:
        logger.info(f"Expired {affected} IP block(s) — attack stopped, removed from active list")


def get_recent_events(blocked_ip_id: int, limit: int = 10) -> list[dict]:
    with cursor() as cur:
        cur.execute("""
            SELECT srv_ip, cli_ip, cli_name, proto, srv_port,
                   score, flow_risk, event_time
            FROM attack_events
            WHERE blocked_ip_id = %s
            ORDER BY event_time DESC
            LIMIT %s
        """, (blocked_ip_id, limit))
        return cur.fetchall()


def get_victim_cli_names(blocked_ip_id: int) -> list[str]:
    with cursor() as cur:
        cur.execute("""
            SELECT DISTINCT cli_name
            FROM attack_events
            WHERE blocked_ip_id = %s AND cli_name != ''
            LIMIT 20
        """, (blocked_ip_id,))
        return [r["cli_name"] for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════════════════════
# Cron Run Tracking
# ══════════════════════════════════════════════════════════════════════════════

def start_cron_run(source_server: str) -> int:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with cursor() as cur:
        cur.execute("""
            INSERT INTO cron_runs (started_at, source_server, status)
            VALUES (%s, %s, 'running')
        """, (now, source_server))
        return cur.lastrowid


def finish_cron_run(run_id: int, stats: dict, status: str = "success", error: str = None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with cursor() as cur:
        cur.execute("""
            UPDATE cron_runs
            SET finished_at   = %s,
                lines_parsed  = %s,
                threats_found = %s,
                new_ips       = %s,
                repeat_ips    = %s,
                emails_sent   = %s,
                status        = %s,
                error_msg     = %s
            WHERE id = %s
        """, (now,
              stats.get("lines_parsed", 0),
              stats.get("threats_found", 0),
              stats.get("new_ips", 0),
              stats.get("repeat_ips", 0),
              stats.get("emails_sent", 0),
              status, error, run_id))


# ══════════════════════════════════════════════════════════════════════════════
# Main Processing Pipeline
# ══════════════════════════════════════════════════════════════════════════════

def process_server_log(source_server: str, log_path: str,
                       victim_cc: list[str]) -> dict:
    stats = dict(lines_parsed=0, threats_found=0,
                 new_ips=0, repeat_ips=0, emails_sent=0)
    run_id = start_cron_run(source_server)

    try:
        raw_events = parse_log_file(log_path)
        stats["lines_parsed"] = len(raw_events)

        threats = filter_threats(raw_events)
        stats["threats_found"] = len(threats)

        # Deduplicate by srv_ip — one DB write + one email per IP per run
        by_ip: dict[str, list[dict]] = {}
        for ev in threats:
            enriched = enrich_event(ev, source_server)
            by_ip.setdefault(enriched["srv_ip"], []).append(enriched)

        for srv_ip, ip_events in by_ip.items():
            # Use the highest-score event as representative
            rep = max(ip_events, key=lambda e: e["score"])

            blocked_ip_id, is_new = upsert_blocked_ip(rep)

            if is_new:
                stats["new_ips"] += 1
            else:
                stats["repeat_ips"] += 1

            # Insert individual flow events
            for ev in ip_events:
                insert_attack_event(blocked_ip_id, ev)

            # Fetch abuse contact
            abuse_email = get_abuse_email(srv_ip)

            # Build victim info for email
            cli_names   = list({e["cli_name"] for e in ip_events if e["cli_name"]})
            victim_info = {"server_ip": source_server, "cli_names": cli_names}

            # Fetch latest attack events for email body
            recent_evs  = get_recent_events(blocked_ip_id, limit=10)

            # Fetch current block info
            with cursor() as cur:
                cur.execute("SELECT * FROM blocked_ips WHERE id = %s", (blocked_ip_id,))
                bi = cur.fetchone()

            ok = send_abuse_report(
                to_email     = abuse_email,
                cc_emails    = victim_cc,
                ip           = srv_ip,
                country      = rep["srv_country"],
                asn          = rep["srv_asn"],
                blacklist    = rep["blacklist"],
                attack_count = bi["attack_count"],
                block_hours  = bi["block_hours"],
                events       = [dict(e) for e in recent_evs],
                victim_info  = victim_info,
            )
            status = "sent" if ok else "failed"
            record_abuse_sent(
                blocked_ip_id = blocked_ip_id,
                to_email      = abuse_email,
                cc_emails     = victim_cc,
                subject       = f"[ABUSE] Malicious IP {srv_ip}",
                status        = status,
            )
            if ok:
                stats["emails_sent"] += 1

        # Expire old blocks
        expire_old_blocks()

        # Clear log file after successful processing
        truncate_log(log_path)

        finish_cron_run(run_id, stats, status="success")
        logger.info(f"[{source_server}] Run complete: {stats}")

    except Exception as exc:
        logger.exception(f"[{source_server}] Fatal error during processing")
        finish_cron_run(run_id, stats, status="failed", error=str(exc))

    return stats


def truncate_log(log_path: str):
    """Empty the log file after processing (preserves file handle)."""
    try:
        with open(log_path, "w") as fh:
            fh.truncate(0)
        logger.info(f"Log truncated: {log_path}")
    except Exception as e:
        logger.error(f"Could not truncate {log_path}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ntopng log analyzer")
    parser.add_argument("--server",    help="Specific server IP to process (default: all)")
    parser.add_argument("--victim-cc", help="Comma-separated CC email addresses",
                        default=os.getenv("VICTIM_CC_EMAILS", ""))
    parser.add_argument("--bootstrap", action="store_true",
                        help="Bootstrap DB schema and exit")
    args = parser.parse_args()

    if args.bootstrap:
        bootstrap_schema()
        logger.info("Schema bootstrapped. Run without --bootstrap for analysis.")
        sys.exit(0)

    victim_cc = [e.strip() for e in args.victim_cc.split(",") if e.strip()]

    log_files = discover_log_files(args.server)
    if not log_files:
        logger.error(f"No log files found under {LOG_BASE_DIR}/*/{LOG_FILENAME}")
        sys.exit(1)

    total_stats = dict(lines_parsed=0, threats_found=0,
                       new_ips=0, repeat_ips=0, emails_sent=0)

    for source_server, log_path in log_files:
        logger.info(f"Processing [{source_server}] → {log_path}")
        s = process_server_log(source_server, log_path, victim_cc)
        for k in total_stats:
            total_stats[k] += s.get(k, 0)

    logger.info(f"All done. Totals: {total_stats}")


if __name__ == "__main__":
    main()
