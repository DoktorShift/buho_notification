import logging
from flask import Flask, request, jsonify
import requests
from urllib.parse import urlparse

# -----------------------------------------------------------------------------
# App + Logging
# -----------------------------------------------------------------------------
app = Flask(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _valid_webhook(url: str) -> bool:
    """Basic sanity check for a Mattermost incoming webhook URL."""
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and p.netloc and "/hooks/" in p.path
    except Exception:
        return False

def _post_to_mattermost(webhook_url: str, text: str) -> None:
    payload = {
        "text": text,           # Markdown supported
        # Optional overrides if you want:
        # "username": "Buho Bot",
        # "icon_emoji": ":owl:"
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        logging.info("✅ Message sent to Mattermost")
    except requests.RequestException as e:
        logging.error(f"❌ Failed to send to Mattermost: {e}")
        raise

# -----------------------------------------------------------------------------
# Formatters (same vibe as Telegram)
# -----------------------------------------------------------------------------
def format_payment_event(data: dict) -> str:
    direction = data.get("direction", "incoming")
    emoji = "🟢" if direction == "incoming" else "🔴"
    label = "RECEIVED" if direction == "incoming" else "SENT"
    amount = data.get("amount", 0)
    wallet = data.get("wallet_name", "—")
    memo = data.get("memo", "—")
    timestamp = data.get("timestamp", "—")

    return (
        f"{emoji} **{label} {amount} sats**\n"
        f"`{wallet}`  •  _{memo}_\n"
        f"🕒 {timestamp}"
    )

def format_auth_event(data: dict) -> str:
    account = data.get("account_name", "—")
    ip = data.get("ip", "—")
    timestamp = data.get("timestamp", "—")

    return (
        f"🔐 **Login Detected**\n"
        f"`{account}` from `{ip}`\n"
        f"🕒 {timestamp}"
    )

# -----------------------------------------------------------------------------
# Webhook Endpoint (Mattermost)
# -----------------------------------------------------------------------------
@app.route("/notifications", methods=["POST"])
def handle_mattermost_notification():
    data = request.get_json(silent=True)

    if not data:
        logging.warning("⚠️ Empty payload received.")
        return jsonify({"error": "No JSON body provided"}), 400

    # Buho now sends the Mattermost incoming webhook URL per event
    webhook_url = data.get("mattermost_webhook") or data.get("webhook") or data.get("mm_webhook")
    if not webhook_url or not _valid_webhook(webhook_url):
        logging.warning("⚠️ Missing or invalid mattermost_webhook.")
        return jsonify({"error": "Missing or invalid mattermost_webhook"}), 400

    event_type = data.get("type")
    if event_type == "payment":
        text = format_payment_event(data)
    elif event_type == "auth":
        text = format_auth_event(data)
    else:
        logging.warning(f"⚠️ Unknown event type: {event_type}")
        return jsonify({"error": "Unsupported event type"}), 400

    _post_to_mattermost(webhook_url, text)
    return jsonify({"status": "Message sent"}), 200

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = 5000
    logging.info(f"🚀 Starting Buho → Mattermost bridge on port {port}")
    app.run(host="0.0.0.0", port=port)
