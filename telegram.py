import os
import logging
from flask import Flask, request, jsonify
import requests

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
if not TELEGRAM_BOT_TOKEN:
    raise EnvironmentError("TELEGRAM_BOT_TOKEN is not set in environment variables.")

TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Logging Setup
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -----------------------------------------------------------------------------
# Send Message to Telegram
# -----------------------------------------------------------------------------
def send_telegram_message(chat_id: int, message: str) -> None:
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True,
        "disable_notification": False
    }
    try:
        response = requests.post(TELEGRAM_API_URL, json=payload)
        response.raise_for_status()
        logging.info(f"✅ Message sent to chat_id {chat_id}")
    except requests.RequestException as e:
        logging.error(f"❌ Failed to send Telegram message: {e}")

# -----------------------------------------------------------------------------
# Format Payment Event
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
        f"{emoji} *{label} {amount} sats*\n"
        f"`{wallet}`  •  _{memo}_\n"
        f"🕒 {timestamp}"
    )

# -----------------------------------------------------------------------------
# Format Login/Auth Event
# -----------------------------------------------------------------------------
def format_auth_event(data: dict) -> str:
    account = data.get("account_name", "—")
    ip = data.get("ip", "—")
    timestamp = data.get("timestamp", "—")

    return (
        f"🔐 *Login Detected*\n"
        f"`{account}` from `{ip}`\n"
        f"🕒 {timestamp}"
    )

# -----------------------------------------------------------------------------
# Webhook Endpoint
# -----------------------------------------------------------------------------
@app.route("/notifications-telegram", methods=["POST"])
def handle_telegram_notification():
    data = request.get_json()

    if not data:
        logging.warning("⚠️ Empty payload received.")
        return jsonify({"error": "No JSON body provided"}), 400

    chat_id = data.get("telegram_chat_id")
    if not chat_id:
        logging.warning("⚠️ Missing telegram_chat_id in request.")
        return jsonify({"error": "Missing telegram_chat_id"}), 400

    event_type = data.get("type")
    if event_type == "payment":
        message = format_payment_event(data)
    elif event_type == "auth":
        message = format_auth_event(data)
    else:
        logging.warning(f"⚠️ Unknown event type: {event_type}")
        return jsonify({"error": "Unsupported event type"}), 400

    send_telegram_message(chat_id, message)
    return jsonify({"status": "Message sent"}), 200

# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    logging.info(f"🚀 Starting Telegram Bot on port {port}")
    app.run(host="0.0.0.0", port=port)
