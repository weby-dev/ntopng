#!/usr/bin/env python3
# =============================================================================
# scripts/rdap_lookup.py — Fetch Abuse Contact via RDAP / WHOIS fallback
# =============================================================================

import re
import json
import socket
import logging
import subprocess
import urllib.request
import urllib.error
from config.config import RDAP_TIMEOUT, WHOIS_ABUSE_FALLBACK

logger = logging.getLogger("ntopng.rdap")

# RDAP bootstrap for IP lookups
RDAP_BOOTSTRAP = "https://rdap.arin.net/registry/ip/"

_ABUSE_RE = re.compile(
    r'(?:abuse[_\-]?(?:mailbox|email|contact)|OrgAbuseEmail)\s*[=:]\s*'
    r'([\w\.\+\-]+@[\w\.\-]+\.\w+)',
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r'[\w\.\+\-]+@[\w\.\-]+\.\w+')


def get_abuse_email(ip: str) -> str:
    """
    Try RDAP first, fall back to whois CLI, then return fallback address.
    Never raises — always returns a string.
    """
    try:
        email = _rdap_lookup(ip)
        if email:
            logger.debug(f"RDAP abuse contact for {ip}: {email}")
            return email
    except Exception as e:
        logger.debug(f"RDAP failed for {ip}: {e}")

    try:
        email = _whois_lookup(ip)
        if email:
            logger.debug(f"WHOIS abuse contact for {ip}: {email}")
            return email
    except Exception as e:
        logger.debug(f"WHOIS failed for {ip}: {e}")

    logger.warning(f"No abuse email found for {ip}, using fallback.")
    return WHOIS_ABUSE_FALLBACK


def _rdap_lookup(ip: str) -> str | None:
    url = f"{RDAP_BOOTSTRAP}{ip}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/rdap+json, application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 301:
            # Follow redirect manually to actual RDAP server
            location = e.headers.get("Location", "")
            if location:
                with urllib.request.urlopen(location, timeout=RDAP_TIMEOUT) as resp:
                    data = json.loads(resp.read().decode())
            else:
                return None
        else:
            raise

    return _extract_rdap_abuse(data)


def _extract_rdap_abuse(data: dict) -> str | None:
    """Walk RDAP response tree looking for abuse role vCard email."""
    # Check entities at this level
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "abuse" in roles:
            email = _vcard_email(entity.get("vcardArray", []))
            if email:
                return email

    # Recurse into nested entities
    for entity in data.get("entities", []):
        result = _extract_rdap_abuse(entity)
        if result:
            return result

    # Remarks / notices sometimes carry abuse info
    for remark in data.get("remarks", []):
        for desc in remark.get("description", []):
            m = _EMAIL_RE.search(desc)
            if m and "abuse" in desc.lower():
                return m.group(0)

    return None


def _vcard_email(vcard_array) -> str | None:
    if not vcard_array or len(vcard_array) < 2:
        return None
    for field in vcard_array[1]:
        if isinstance(field, list) and field[0] == "email":
            return field[3] if len(field) > 3 else None
    return None


def _whois_lookup(ip: str) -> str | None:
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=15,
        )
        text = result.stdout
    except FileNotFoundError:
        logger.warning("whois binary not found — skipping WHOIS lookup")
        return None

    m = _ABUSE_RE.search(text)
    if m:
        return m.group(1)

    # Generic email scan if no labelled field found
    emails = _EMAIL_RE.findall(text)
    abuse_emails = [e for e in emails if "abuse" in e.lower()]
    return abuse_emails[0] if abuse_emails else None
