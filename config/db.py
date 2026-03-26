#!/usr/bin/env python3
# =============================================================================
# config/db.py — MySQL Connection Pool + Schema Bootstrap
# =============================================================================

import sys
import logging
import pymysql
import pymysql.cursors
from contextlib import contextmanager
from config.config import DB

logger = logging.getLogger("ntopng.db")


# ── Connection pool (simple persistent connection per process) ─────────────────
_connection = None

def get_connection():
    global _connection
    try:
        if _connection is None or not _connection.open:
            _connection = _make_connection()
        else:
            _connection.ping(reconnect=True)
    except Exception:
        _connection = _make_connection()
    return _connection


def _make_connection():
    return pymysql.connect(
        host=DB["host"],
        port=DB["port"],
        user=DB["user"],
        password=DB["password"],
        database=DB["database"],
        charset=DB["charset"],
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=10,
    )


@contextmanager
def cursor():
    conn = get_connection()
    cur  = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS blocked_ips (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip               VARCHAR(45)  NOT NULL,
    asn              INT UNSIGNED,
    country          VARCHAR(64),
    city             VARCHAR(128),
    blacklist_source VARCHAR(128),
    first_seen       DATETIME     NOT NULL,
    last_seen        DATETIME     NOT NULL,
    attack_count     INT UNSIGNED NOT NULL DEFAULT 1,
    block_hours      INT UNSIGNED NOT NULL DEFAULT 24,
    blocked_until    DATETIME     NOT NULL,
    is_active        TINYINT(1)   NOT NULL DEFAULT 1,
    abuse_email      VARCHAR(255),
    abuse_sent_at    DATETIME,
    notes            TEXT,
    UNIQUE KEY uq_ip (ip),
    INDEX idx_active      (is_active),
    INDEX idx_blocked_until (blocked_until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS attack_events (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    blocked_ip_id    BIGINT UNSIGNED NOT NULL,
    srv_ip           VARCHAR(45)  NOT NULL,
    cli_ip           VARCHAR(45),
    cli_name         VARCHAR(255),
    cli_country      VARCHAR(64),
    score            INT UNSIGNED,
    alert_id         INT UNSIGNED,
    alert_type       VARCHAR(128),
    blacklist_source VARCHAR(128),
    proto            VARCHAR(32),
    srv_port         INT UNSIGNED,
    bytes_srv2cli    BIGINT UNSIGNED DEFAULT 0,
    flow_risk        VARCHAR(512),
    source_server    VARCHAR(64),
    event_time       DATETIME NOT NULL,
    raw_json         MEDIUMTEXT,
    FOREIGN KEY (blocked_ip_id) REFERENCES blocked_ips(id) ON DELETE CASCADE,
    INDEX idx_blocked_ip_id (blocked_ip_id),
    INDEX idx_event_time    (event_time),
    INDEX idx_srv_ip        (srv_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS abuse_reports (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    blocked_ip_id    BIGINT UNSIGNED NOT NULL,
    to_email         VARCHAR(255),
    cc_emails        TEXT,
    subject          VARCHAR(512),
    sent_at          DATETIME,
    status           ENUM('sent','failed','skipped') DEFAULT 'sent',
    error_msg        TEXT,
    FOREIGN KEY (blocked_ip_id) REFERENCES blocked_ips(id) ON DELETE CASCADE,
    INDEX idx_blocked_ip_id (blocked_ip_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


CREATE TABLE IF NOT EXISTS cron_runs (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    started_at       DATETIME NOT NULL,
    finished_at      DATETIME,
    source_server    VARCHAR(64),
    lines_parsed     INT UNSIGNED DEFAULT 0,
    threats_found    INT UNSIGNED DEFAULT 0,
    new_ips          INT UNSIGNED DEFAULT 0,
    repeat_ips       INT UNSIGNED DEFAULT 0,
    emails_sent      INT UNSIGNED DEFAULT 0,
    status           ENUM('running','success','failed') DEFAULT 'running',
    error_msg        TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def bootstrap_schema():
    """Create all tables if they don't exist yet."""
    conn = get_connection()
    with conn.cursor() as cur:
        for stmt in SCHEMA_SQL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                cur.execute(stmt)
    conn.commit()
    logger.info("Schema bootstrap complete.")
