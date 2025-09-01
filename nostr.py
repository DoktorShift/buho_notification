#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Buho → Nostr DM Bridge (Production-Ready)
- Single Buho identity (NOSTR_SECRET: hex or nsec...)
- NIP-44 v2 (default) or NIP-04 encryption
- Persistent relay sessions with first-OK-wins publish (SimplePool-like)
- Async loop in a dedicated thread; Flask stays sync & scalable under gunicorn
"""

import os
import json
import time
import base64
import math
import hmac as py_hmac
import hashlib
import secrets
import logging
import threading
import uuid
from typing import List, Tuple, Optional, Dict

from flask import Flask, request, jsonify, g
import websockets
import asyncio

from coincurve import PrivateKey as CCPrivateKey, schnorr
from bech32 import bech32_decode, convertbits

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac


# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
def env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v is not None else default

DEFAULT_RELAYS = [
    r.strip() for r in (env("DEFAULT_RELAYS",
                            "wss://relay.damus.io,"
                            "wss://nos.lol,"
                            "wss://relay.snort.social,"
                            "wss://eden.nostr.land,"
                            "wss://nostr.wine") or "").split(",")
    if r.strip()
]

PREFERRED_CIPHER = (env("PREFERRED_CIPHER", "nip44") or "nip44").lower()
LOG_LEVEL = env("LOG_LEVEL", "INFO").upper()
PORT = int(env("PORT", "5000"))

# Structured logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
log = logging.getLogger("buho-nostr")


# ------------------------------------------------------------------------------
# Key handling (single Buho identity)
# ------------------------------------------------------------------------------
def bech32_to_bytes(hrp_expected: str, s: str) -> bytes:
    hrp, data = bech32_decode(s)
    if hrp != hrp_expected or data is None:
        raise ValueError(f"invalid {hrp_expected}")
    return bytes(convertbits(data, 5, 8, False))

def npub_to_hex(npub: str) -> str:
    return bech32_to_bytes("npub", npub).hex()

def nsec_to_hex(nsec: str) -> str:
    return bech32_to_bytes("nsec", nsec).hex()

def normalize_pubkey_hex(s: str) -> str:
    s = s.strip().lower()
    if s.startswith("npub"):
        return npub_to_hex(s)
    if len(s) == 64 and all(c in "0123456789abcdef" for c in s):
        return s
    raise ValueError("recipient must be npub… or 64-hex")

_RAW_SECRET = env("NOSTR_SECRET") or ""
if not _RAW_SECRET:
    raise EnvironmentError("NOSTR_SECRET must be set to Buho’s secret (hex or nsec...)")

if _RAW_SECRET.startswith("nsec"):
    NOSTR_SK = nsec_to_hex(_RAW_SECRET)
else:
    NOSTR_SK = _RAW_SECRET.lower()

if len(NOSTR_SK) != 64 or any(c not in "0123456789abcdef" for c in NOSTR_SK):
    raise EnvironmentError("NOSTR_SECRET must be 32-byte hex or a valid nsec")

SK = CCPrivateKey(bytes.fromhex(NOSTR_SK))
PUB_XONLY = SK.public_key.format_xonly().hex()


# ------------------------------------------------------------------------------
# Crypto: ECDH (x-only), NIP-04, NIP-44 v2
# ------------------------------------------------------------------------------
def ecdh_xonly(sender_sk_hex: str, recipient_hex: str) -> bytes:
    """ECDH using sender secret + recipient x-only pubkey (assume even y)."""
    recipient_compressed = bytes.fromhex("02" + recipient_hex)
    tmp_sk = CCPrivateKey(bytes.fromhex(sender_sk_hex))
    # coincurve ecdh returns 32-byte shared X coordinate
    return tmp_sk.ecdh(recipient_compressed)

# --- NIP-04 (AES-256-CBC + PKCS7) ---
def nip04_encrypt(sk_hex: str, recipient_hex: str, plaintext: str) -> str:
    key = ecdh_xonly(sk_hex, recipient_hex)  # 32 bytes = AES-256 key
    iv = secrets.token_bytes(16)
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    ct = cipher.update(padded) + cipher.finalize()
    return f"{base64.b64encode(ct).decode()}?iv={base64.b64encode(iv).decode()}"

# --- NIP-44 v2 (ChaCha20 + HMAC-SHA256 + padding) ---
def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    return py_hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    prev = b""
    counter = 1
    while len(out) < length:
        prev = py_hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return out[:length]

def calc_padded_len(n: int) -> int:
    if n < 1 or n > 0xFFFF:
        raise ValueError("invalid plaintext size")
    if n <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(n - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (math.floor((n - 1) / chunk) + 1)

def pad_v2(s: str) -> bytes:
    b = s.encode("utf-8")
    L = len(b)
    pref = L.to_bytes(2, "big")
    suff = bytes(calc_padded_len(L) - L)
    return pref + b + suff

def nip44_encrypt(sk_hex: str, recipient_hex: str, plaintext: str) -> str:
    shared = ecdh_xonly(sk_hex, recipient_hex)
    conv = hkdf_extract_sha256(b"nip44-v2", shared)  # 32-byte conversation key
    nonce32 = secrets.token_bytes(32)
    keys = hkdf_expand_sha256(conv, nonce32, 76)
    chacha_key = keys[0:32]
    chacha_nonce_12 = keys[32:44]
    hmac_key = keys[44:76]

    # cryptography expects 16-byte nonce: 4-byte counter + 12-byte derived nonce
    nonce16 = b"\x00\x00\x00\x00" + chacha_nonce_12
    cipher = Cipher(algorithms.ChaCha20(chacha_key, nonce16), mode=None, backend=default_backend()).encryptor()
    padded = pad_v2(plaintext)
    ct = cipher.update(padded) + cipher.finalize()

    mac = crypto_hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    mac.update(nonce32 + ct)  # aad||ciphertext
    tag = mac.finalize()

    payload = bytes([2]) + nonce32 + ct + tag
    return base64.b64encode(payload).decode()


# ------------------------------------------------------------------------------
# Nostr Event Build/Sign (kind 4)
# ------------------------------------------------------------------------------
def nostr_event_id(pubkey_hex: str, created_at: int, kind: int, tags: List, content: str) -> str:
    data = [0, pubkey_hex, created_at, kind, tags, content]
    ser = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode("utf-8")).hexdigest()

def build_dm_event(content: str, recipient_hex: str) -> dict:
    created = int(time.time())
    tags = [["p", recipient_hex]]
    ev_id = nostr_event_id(PUB_XONLY, created, 4, tags, content)
    sig = schnorr.sign(bytes.fromhex(ev_id), bytes.fromhex(NOSTR_SK), None).hex()
    return {
        "id": ev_id,
        "pubkey": PUB_XONLY,
        "created_at": created,
        "kind": 4,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


# ------------------------------------------------------------------------------
# SimplePool-like publisher (persistent sessions + first-OK-wins)
# ------------------------------------------------------------------------------
class RelaySession:
    def __init__(self, url: str, loop: asyncio.AbstractEventLoop):
        self.url = url
        self.loop = loop
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.lock = asyncio.Lock()
        self.connected_at = 0.0
        self.failures = 0
        self.backoff_until = 0.0

    async def ensure(self, timeout: float = 8.0) -> websockets.WebSocketClientProtocol:
        now = time.time()
        if self.ws and not self.ws.closed:
            return self.ws
        if now < self.backoff_until:
            raise ConnectionError(f"backing off until {self.backoff_until:.0f}")
        async with self.lock:
            if self.ws and not self.ws.closed:
                return self.ws
            try:
                self.ws = await websockets.connect(self.url, open_timeout=timeout, close_timeout=2)
                self.connected_at = time.time()
                self.failures = 0
                return self.ws
            except Exception as e:
                self.failures += 1
                self.backoff_until = now + min(60, 2 ** min(6, self.failures))
                raise e

    async def close(self):
        try:
            if self.ws and not self.ws.closed:
                await self.ws.close()
        except Exception:
            pass
        finally:
            self.ws = None


class SimplePublishPool:
    def __init__(self, relays: List[str], loop: asyncio.AbstractEventLoop):
        self.loop = loop
        self.relays = list(relays)
        self.sessions: Dict[str, RelaySession] = {r: RelaySession(r, loop) for r in self.relays}

    async def publish_any(self, event: dict, timeout_per: float = 8.0, overall_timeout: float = 12.0):
        async def send_one(rs: RelaySession):
            try:
                ws = await rs.ensure(timeout=timeout_per)
                await ws.send(json.dumps(["EVENT", event]))
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=timeout_per)
                    try:
                        frame = json.loads(msg)
                    except Exception:
                        continue
                    # ["OK", <id>, <true|false>, <message>]
                    if isinstance(frame, list) and len(frame) >= 4 and frame[0] == "OK" and frame[1] == event["id"]:
                        ok = bool(frame[2]); txt = str(frame[3])
                        return {"relay": rs.url, "ok": ok, "msg": txt}
            except asyncio.TimeoutError:
                return {"relay": rs.url, "ok": False, "msg": "timeout"}
            except Exception as e:
                return {"relay": rs.url, "ok": False, "msg": f"{e}"}

        tasks = [self.loop.create_task(send_one(self.sessions[r])) for r in self.relays]
        results = []
        accepted = []

        try:
            end = time.time() + overall_timeout
            pending = set(tasks)
            while pending and time.time() < end:
                done, pending = await asyncio.wait(pending, timeout=overall_timeout, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    res = t.result()
                    results.append(res)
                    if res.get("ok"):
                        accepted.append(res["relay"])
                        for p in pending:
                            p.cancel()
                        pending = set()
                        break
            for p in pending:
                try:
                    r = await p
                    results.append(r)
                except asyncio.CancelledError:
                    results.append({"relay": "cancelled", "ok": False, "msg": "cancelled"})
        finally:
            pass

        return {"accepted": accepted, "results": results}

    async def close(self):
        await asyncio.gather(*(rs.close() for rs in self.sessions.values()), return_exceptions=True)


# ------------------------------------------------------------------------------
# Async loop thread (so Flask workers can call into asyncio safely)
# ------------------------------------------------------------------------------
class LoopThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.loop = asyncio.new_event_loop()
        self._stop_evt = threading.Event()

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run_coro(self, coro):
        """Schedule a coroutine on the loop and block until result."""
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut

    def stop(self):
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        self._stop_evt.set()


# ------------------------------------------------------------------------------
# Flask app
# ------------------------------------------------------------------------------
app = Flask(__name__)

# request IDs in logs
@app.before_request
def _req_id():
    g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

@app.after_request
def _resp_headers(resp):
    resp.headers["X-Request-ID"] = g.get("request_id", "")
    return resp

# Start loop thread & default pool
_loop_thread = LoopThread()
_loop_thread.start()
POOL = SimplePublishPool(DEFAULT_RELAYS, _loop_thread.loop)

# Health endpoint
@app.get("/healthz")
def healthz():
    return jsonify({
        "status": "ok",
        "relays": DEFAULT_RELAYS,
        "sender": PUB_XONLY
    }), 200

# Message formatters
def fmt_payment(d: dict) -> str:
    direction = d.get("direction", "incoming")
    emoji = "🟢" if direction == "incoming" else "🔴"
    label = "RECEIVED" if direction == "incoming" else "SENT"
    return (
        f"{emoji} {label} {d.get('amount',0)} sats\n"
        f"`{d.get('wallet_name','—')}` • _{d.get('memo','—')}_\n"
        f"🕒 {d.get('timestamp','—')}"
    )

def fmt_auth(d: dict) -> str:
    return (
        f"🔐 Login Detected\n"
        f"`{d.get('account_name','—')}` from `{d.get('ip','—')}`\n"
        f"🕒 {d.get('timestamp','—')}"
    )

# Main notifications endpoint
@app.post("/notifications")
def notifications():
    rid = g.get("request_id")
    data = request.get_json(silent=True) or {}
    try:
        recipient_raw = data.get("recipient") or data.get("recipient_pubkey") or data.get("npub") or ""
        recipient_hex = normalize_pubkey_hex(recipient_raw)
    except Exception as e:
        log.warning(json.dumps({"rid": rid, "msg": "invalid recipient", "err": str(e)}))
        return jsonify({"error": f"recipient invalid: {e}"}), 400

    etype = (data.get("type") or "").lower()
    if etype == "payment":
        message = fmt_payment(data)
    elif etype == "auth":
        message = fmt_auth(data)
    else:
        return jsonify({"error": "type must be 'payment' or 'auth'"}), 400

    cipher = (data.get("cipher") or PREFERRED_CIPHER).lower()
    try:
        if cipher == "nip04":
            enc = nip04_encrypt(NOSTR_SK, recipient_hex, message)
        else:
            enc = nip44_encrypt(NOSTR_SK, recipient_hex, message)
            cipher = "nip44"
    except Exception as e:
        log.exception(json.dumps({"rid": rid, "msg": "encryption failed"}))
        return jsonify({"error": f"encryption failed: {e}"}), 500

    event = build_dm_event(enc, recipient_hex)

    # choose relay pool (reuse default if same set)
    relays = data.get("relays") or DEFAULT_RELAYS
    use_default_pool = set(relays) == set(DEFAULT_RELAYS)
    pool = POOL if use_default_pool else SimplePublishPool(relays, _loop_thread.loop)

    try:
        fut = _loop_thread.run_coro(pool.publish_any(event, timeout_per=8.0, overall_timeout=12.0))
        results = fut.result(timeout=15.0)
    except Exception as e:
        log.exception(json.dumps({"rid": rid, "msg": "publish failed"}))
        return jsonify({"error": f"publish failed: {e}"}), 502
    finally:
        if not use_default_pool:
            try:
                _loop_thread.run_coro(pool.close()).result(timeout=3.0)
            except Exception:
                pass

    ok_any = bool(results["accepted"])
    status = "sent" if ok_any else "not_confirmed"

    log.info(json.dumps({
        "rid": rid,
        "event": event["id"],
        "cipher": cipher,
        "accepted_on": results["accepted"],
        "relays": relays
    }))

    return jsonify({
        "status": status,
        "cipher": cipher,
        "event_id": event["id"],
        "sender": PUB_XONLY,
        "recipient": recipient_hex,
        "accepted_on": results["accepted"],
        "results": results["results"],
    }), 200 if ok_any else 207


# Graceful shutdown (for local `python app.py`)
def _shutdown():
    try:
        _loop_thread.run_coro(POOL.close()).result(timeout=3.0)
    except Exception:
        pass
    _loop_thread.stop()

if __name__ == "__main__":
    try:
        log.info(f"🚀 Buho → Nostr DM bridge on :{PORT} (sender={PUB_XONLY})")
        app.run(host="0.0.0.0", port=PORT)
    finally:
        _shutdown()
