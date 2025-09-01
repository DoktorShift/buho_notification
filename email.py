#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buho → Email Bridge (SMTP)
- POST /notifications to send payment/auth emails
- Multipart (text + streamlined HTML) with retries
- /healthz for readiness
"""

import os
import ssl
import time
import json
import uuid
import socket
import logging
from typing import List, Optional, Tuple
from email.message import EmailMessage
from email.utils import make_msgid, formatdate

import smtplib
from flask import Flask, request, jsonify, g
from jinja2 import Template

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
def env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default

SMTP_HOST = env("SMTP_HOST") or ""
SMTP_PORT = int(env("SMTP_PORT", "587"))              # 465 for SSL, 587 for STARTTLS
SMTP_USERNAME = env("SMTP_USERNAME") or ""
SMTP_PASSWORD = env("SMTP_PASSWORD") or ""
SMTP_FROM = env("SMTP_FROM") or ""                    # e.g. "Buho <no-reply@yourdomain.tld>"
SMTP_USE_SSL = env("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes")
SMTP_USE_STARTTLS = env("SMTP_USE_STARTTLS", "true").lower() in ("1", "true", "yes")
DEFAULT_TO = [e.strip() for e in (env("DEFAULT_TO", "") or "").split(",") if e.strip()]

SERVICE_NAME = env("SERVICE_NAME", "Buho Notifications")
LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()
PORT = int(env("PORT", "5000"))
RETRY_ATTEMPTS = int(env("RETRY_ATTEMPTS", "3"))
RETRY_DELAY_SEC = float(env("RETRY_DELAY_SEC", "0.6"))

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s email-bridge %(message)s"
)
log = logging.getLogger("email-bridge")

if not (SMTP_HOST and SMTP_FROM):
    raise EnvironmentError("SMTP_HOST and SMTP_FROM must be set")

# ------------------------------------------------------------------------------
# Flask
# ------------------------------------------------------------------------------
app = Flask(__name__)

@app.before_request
def add_request_id():
    g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

@app.after_request
def set_request_id(resp):
    rid = g.get("request_id", "")
    resp.headers["X-Request-ID"] = rid
    return resp

@app.get("/healthz")
def health():
    return jsonify({
        "status": "ok",
        "service": SERVICE_NAME,
        "smtp_host": SMTP_HOST,
        "smtp_port": SMTP_PORT,
        "from": SMTP_FROM
    }), 200

# ------------------------------------------------------------------------------
# Email helpers
# ------------------------------------------------------------------------------
def _connect_smtp() -> smtplib.SMTP:
    context = ssl.create_default_context()
    if SMTP_USE_SSL:
        server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15)
    else:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
        server.ehlo()
        if SMTP_USE_STARTTLS:
            server.starttls(context=context)
    if SMTP_USERNAME:
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
    return server

def _send_email(msg: EmailMessage, recipients: List[str]) -> Tuple[bool, str]:
    last_err = ""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            with _connect_smtp() as smtp:
                smtp.send_message(msg, from_addr=SMTP_FROM, to_addrs=recipients)
            return True, "ok"
        except (smtplib.SMTPException, OSError, socket.error) as e:
            last_err = str(e)
            if attempt < RETRY_ATTEMPTS:
                time.sleep(RETRY_DELAY_SEC * attempt)
    return False, last_err

def _normalize_recipients(data: dict) -> Tuple[List[str], List[str], List[str]]:
    # accepts: recipient (string), recipients (list), cc (list/string), bcc (list/string)
    to = []
    if "recipient" in data and isinstance(data["recipient"], str):
        to = [data["recipient"].strip()]
    elif "recipients" in data and isinstance(data["recipients"], list):
        to = [str(x).strip() for x in data["recipients"] if str(x).strip()]

    if not to and DEFAULT_TO:
        to = DEFAULT_TO[:]

    cc = data.get("cc", [])
    if isinstance(cc, str):
        cc = [cc]
    cc = [str(x).strip() for x in cc if str(x).strip()]

    bcc = data.get("bcc", [])
    if isinstance(bcc, str):
        bcc = [bcc]
    bcc = [str(x).strip() for x in bcc if str(x).strip()]

    if not to:
        raise ValueError("at least one recipient email is required (recipient, recipients, or DEFAULT_TO)")

    return to, cc, bcc

def _subjects(etype: str, d: dict) -> str:
    if etype == "payment":
        direction = d.get("direction", "incoming")
        label = "RECEIVED" if direction == "incoming" else "SENT"
        return f"[Buho] {label} {d.get('amount', 0)} sats — {d.get('wallet_name', 'Wallet')}"
    else:
        # auth
        return f"[Buho] Login detected — {d.get('account_name','user')} @ {d.get('ip','?')}"

def format_payment_text(d: dict) -> str:
    direction = d.get("direction", "incoming")
    emoji = "🟢" if direction == "incoming" else "🔴"
    label = "RECEIVED" if direction == "incoming" else "SENT"
    return (
        f"{emoji} {label} {d.get('amount',0)} sats\n"
        f"Wallet: {d.get('wallet_name','—')}\n"
        f"Memo: {d.get('memo','—')}\n"
        f"Time: {d.get('timestamp','—')}\n"
    )

def format_auth_text(d: dict) -> str:
    return (
        f"🔐 Login Detected\n"
        f"Account: {d.get('account_name','—')}\n"
        f"IP: {d.get('ip','—')}\n"
        f"Time: {d.get('timestamp','—')}\n"
    )

HTML_TEMPLATE = Template("""\
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="x-apple-disable-message-reformatting">
    <title>{{ subject }}</title>
  </head>
  <body style="margin:0;padding:24px;background:#f6f7f9;">
    <div style="max-width:640px;margin:0 auto;background:#ffffff;border-radius:12px;border:1px solid #e9eef3;overflow:hidden;">
      <div style="padding:16px 20px;background:#0f172a;color:#ffffff;">
        <div style="font:600 16px/1.2 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;">{{ heading }}</div>
        <div style="opacity:.9;font:400 12px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin-top:4px;">{{ subheading }}</div>
      </div>

      <div style="padding:20px;">
        {% if banner %}
        <div style="display:inline-block;padding:4px 10px;border-radius:999px;background:#eef2ff;color:#3730a3;font:600 12px/1 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;margin-bottom:12px;">
          {{ banner }}
        </div>
        {% endif %}

        {% if lead %}
        <p style="margin:0 0 14px 0;color:#0f172a;font:400 14px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;">{{ lead }}</p>
        {% endif %}

        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:separate;border-spacing:0 8px;">
          {% for k, v in rows %}
          <tr>
            <td style="width:170px;padding:10px 12px;color:#475569;font:600 12px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:#f8fafc;border:1px solid #eef2f7;border-right:0;border-radius:8px 0 0 8px;">{{ k }}</td>
            <td style="padding:10px 12px;color:#0f172a;font:400 13px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;background:#ffffff;border:1px solid #eef2f7;border-left:0;border-radius:0 8px 8px 0;">{{ v }}</td>
          </tr>
          {% endfor %}
        </table>

        {% if footer %}
        <p style="margin:16px 0 0 0;color:#94a3b8;font:400 12px/1.6 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;">
          {{ footer }}
        </p>
        {% endif %}
      </div>
    </div>
  </body>
</html>
""")

def render_payment_html(d: dict, subject: str) -> str:
    heading = "Payment Notification"
    subheading = "Lightning payment update from Buho"
    banner = "Incoming" if d.get("direction", "incoming") == "incoming" else "Outgoing"
    lead = None
    rows = [
        ("Amount (sats)", str(d.get("amount", 0))),
        ("Wallet", d.get("wallet_name", "—")),
        ("Memo", d.get("memo", "—")),
        ("Timestamp", d.get("timestamp", "—")),
    ]
    return HTML_TEMPLATE.render(
        subject=subject, heading=heading, subheading=subheading,
        banner=banner, lead=lead, rows=rows, footer="Sent by Buho"
    )

def render_auth_html(d: dict, subject: str) -> str:
    heading = "Login Detected"
    subheading = "Security notification from Buho"
    banner = "Account Activity"
    lead = None
    rows = [
        ("Account", d.get("account_name", "—")),
        ("IP Address", d.get("ip", "—")),
        ("Timestamp", d.get("timestamp", "—")),
    ]
    return HTML_TEMPLATE.render(
        subject=subject, heading=heading, subheading=subheading,
        banner=banner, lead=lead, rows=rows, footer="Sent by Buho"
    )

def build_email(etype: str, data: dict, sender: str, to: List[str], cc: List[str], bcc: List[str]) -> EmailMessage:
    subject = _subjects(etype, data)
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=sender.split("@")[-1] if "@" in sender else None)

    if etype == "payment":
        text = format_payment_text(data)
        html = render_payment_html(data, subject)
    else:
        text = format_auth_text(data)
        html = render_auth_html(data, subject)

    # multipart/alternative: text first, then HTML
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg

# ------------------------------------------------------------------------------
# Endpoint
# ------------------------------------------------------------------------------
@app.post("/notifications")
def notifications():
    rid = g.get("request_id")
    payload = request.get_json(silent=True) or {}

    etype = (payload.get("type") or "").lower()
    if etype not in ("payment", "auth"):
        return jsonify({"error": "type must be 'payment' or 'auth'"}), 400

    try:
        to, cc, bcc = _normalize_recipients(payload)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    msg = build_email(etype, payload, SMTP_FROM, to, cc, bcc)
    all_rcpts = to + cc + bcc

    ok, info = _send_email(msg, all_rcpts)

    log.info(json.dumps({
        "rid": rid,
        "status": "sent" if ok else "failed",
        "type": etype,
        "to": to,
        "cc": cc,
        "bcc_count": len(bcc),
        "error": None if ok else info
    }))

    if ok:
        return jsonify({"status": "sent", "type": etype, "to": to, "cc": cc, "bcc": len(bcc)}), 200
    else:
        return jsonify({"status": "failed", "error": info}), 502

# ------------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
