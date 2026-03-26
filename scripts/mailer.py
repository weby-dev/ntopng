#!/usr/bin/env python3
# =============================================================================
# scripts/mailer.py — SMTP Abuse Report Sender
# =============================================================================

import smtplib
import logging
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from datetime             import datetime, timezone
from config.config        import SMTP

logger = logging.getLogger("ntopng.mailer")


# ── Public API ────────────────────────────────────────────────────────────────

def send_abuse_report(
    to_email:    str,
    cc_emails:   list[str],
    ip:          str,
    country:     str,
    asn:         int,
    blacklist:   str,
    attack_count:int,
    block_hours: int,
    events:      list[dict],
    victim_info: dict,
) -> bool:
    """
    Sends a formatted abuse report email.
    Returns True on success, False on failure.
    """
    subject  = f"[ABUSE REPORT] Malicious IP {ip} — {country} — {blacklist}"
    html     = _build_html(ip, country, asn, blacklist, attack_count,
                           block_hours, events, victim_info)
    plain    = _build_plain(ip, country, asn, blacklist, attack_count,
                            block_hours, events, victim_info)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{SMTP['from_name']} <{SMTP['from_addr']}>"
    msg["To"]      = to_email
    if cc_emails:
        msg["Cc"]  = ", ".join(cc_emails)

    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html,  "html"))

    recipients = [to_email] + (cc_emails or [])

    try:
        if SMTP["use_tls"]:
            smtp = smtplib.SMTP_SSL(SMTP["host"], SMTP["port"], timeout=15)
        else:
            smtp = smtplib.SMTP(SMTP["host"], SMTP["port"], timeout=15)
            smtp.ehlo()
            try:
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass   # plain SMTP on port 25 — no STARTTLS

        if SMTP["username"]:
            smtp.login(SMTP["username"], SMTP["password"])

        smtp.sendmail(SMTP["from_addr"], recipients, msg.as_string())
        smtp.quit()
        logger.info(f"Abuse report sent → {to_email} (cc: {cc_emails})")
        return True

    except Exception as exc:
        logger.error(f"Failed to send abuse report to {to_email}: {exc}")
        return False


# ── Template Builders ─────────────────────────────────────────────────────────

def _build_plain(ip, country, asn, blacklist, attack_count,
                 block_hours, events, victim_info):
    lines = [
        "=" * 72,
        "ABUSE REPORT — MALICIOUS IP ACTIVITY DETECTED",
        "=" * 72,
        f"Reported IP      : {ip}",
        f"Country          : {country}",
        f"ASN              : {asn}",
        f"Blacklist Source : {blacklist}",
        f"Attack Count     : {attack_count}",
        f"Block Duration   : {block_hours} hours",
        f"Report Generated : {datetime.now(timezone.utc).isoformat()}",
        f"Reported By      : {socket.getfqdn()}",
        "",
        "─" * 72,
        "VICTIM NETWORK INFO",
        "─" * 72,
        f"Victim Server    : {victim_info.get('server_ip','N/A')}",
        f"Victim Hosts     : {', '.join(victim_info.get('cli_names',[]))}",
        "",
        "─" * 72,
        "FLOW EVENTS (latest 10)",
        "─" * 72,
    ]
    for i, ev in enumerate(events[:10], 1):
        lines.append(
            f"{i:2}. [{ev.get('event_time','')}]  "
            f"SRC={ev.get('cli_ip','?')} ({ev.get('cli_name','?')})  "
            f"→  DST={ip}:{ev.get('srv_port','?')}  "
            f"proto={ev.get('proto','?')}  score={ev.get('score','?')}  "
            f"risk={ev.get('flow_risk','?')}"
        )
    lines += [
        "",
        "─" * 72,
        "Please take appropriate action to stop the malicious activity",
        "originating from this IP address.",
        "",
        "This report was generated automatically by the Network Security",
        "Monitoring System.",
        "=" * 72,
    ]
    return "\n".join(lines)


def _build_html(ip, country, asn, blacklist, attack_count,
                block_hours, events, victim_info):
    rows = ""
    for ev in events[:10]:
        rows += f"""
        <tr>
          <td>{ev.get('event_time','')}</td>
          <td>{ev.get('cli_ip','?')}</td>
          <td>{ev.get('cli_name','?')}</td>
          <td>{ip}:{ev.get('srv_port','?')}</td>
          <td>{ev.get('proto','?')}</td>
          <td style="color:#c0392b;font-weight:bold">{ev.get('score','?')}</td>
          <td>{ev.get('flow_risk','?')}</td>
        </tr>"""

    victim_hosts = ", ".join(victim_info.get("cli_names", []))

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body      {{ font-family: Arial, sans-serif; font-size: 14px; color: #222; }}
  h2        {{ background:#c0392b; color:#fff; padding:12px 16px; border-radius:4px; }}
  h3        {{ color:#c0392b; border-bottom:2px solid #c0392b; padding-bottom:4px; }}
  table     {{ border-collapse:collapse; width:100%; margin-top:8px; }}
  th        {{ background:#2c3e50; color:#fff; padding:8px 10px; text-align:left; }}
  td        {{ padding:7px 10px; border-bottom:1px solid #ddd; }}
  tr:hover  {{ background:#f9f9f9; }}
  .pill     {{ display:inline-block; padding:3px 10px; border-radius:12px;
               background:#e74c3c; color:#fff; font-size:12px; }}
  .box      {{ background:#fdf3f3; border-left:4px solid #c0392b;
               padding:10px 14px; margin:10px 0; border-radius:2px; }}
  footer    {{ font-size:11px; color:#999; margin-top:24px; }}
</style>
</head>
<body>
<h2>⚠ Abuse Report — Malicious IP Activity Detected</h2>

<div class="box">
  <strong>Reported IP:</strong> {ip} &nbsp;
  <strong>Country:</strong> {country} &nbsp;
  <strong>ASN:</strong> {asn} &nbsp;
  <span class="pill">{blacklist}</span>
</div>

<h3>Summary</h3>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Malicious IP</td><td><strong>{ip}</strong></td></tr>
  <tr><td>Country</td><td>{country}</td></tr>
  <tr><td>ASN</td><td>{asn}</td></tr>
  <tr><td>Blacklist Source</td><td>{blacklist}</td></tr>
  <tr><td>Total Attack Events</td><td><strong style="color:#c0392b">{attack_count}</strong></td></tr>
  <tr><td>Block Duration</td><td>{block_hours} hours</td></tr>
  <tr><td>Report Time (UTC)</td><td>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>

<h3>Victim Network</h3>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Monitoring Server</td><td>{victim_info.get('server_ip','N/A')}</td></tr>
  <tr><td>Affected Hosts</td><td>{victim_hosts}</td></tr>
</table>

<h3>Flow Events (Latest 10)</h3>
<table>
  <tr>
    <th>Time (UTC)</th><th>Source IP</th><th>Source Host</th>
    <th>Destination</th><th>Protocol</th><th>Score</th><th>Risk</th>
  </tr>
  {rows}
</table>

<p>Please investigate and take appropriate action to stop malicious activity
from the above IP address. This report was generated automatically by our
Network Security Monitoring System.</p>

<footer>
  Generated by ntopng-analyzer on {socket.getfqdn()} &nbsp;|&nbsp;
  {datetime.now(timezone.utc).isoformat()}
</footer>
</body>
</html>"""
