# buho_notification
Python Skripts for receiving notifications via various services. Telegram, email, mattermost or nostr

here’s the **dev-facing contract** for what Buho must POST to each service so your four Python scripts work smoothly.

# Common notes

* HTTP header: `Content-Type: application/json`
* All timestamps are treated as display strings (no parsing required).
* `type` is always either `"payment"` or `"auth"`.

---

# 1) Telegram bridge

**Endpoint:** `POST /notifications`
**Env needed on server:** `TELEGRAM_BOT_TOKEN`
**Routing key:** `telegram_chat_id` (integer)

## Required fields

* `type`: `"payment"` or `"auth"`
* `telegram_chat_id`: integer (destination chat)

## Payment payload

```json
{
  "type": "payment",
  "telegram_chat_id": 123456789,
  "direction": "incoming",            // "incoming" | "outgoing"
  "amount": 3000,                     // sats (integer)
  "wallet_name": "Tips Wallet",
  "memo": "Danke ❤️",
  "timestamp": "2025-03-27 09:15"
}
```

## Auth payload

```json
{
  "type": "auth",
  "telegram_chat_id": 123456789,
  "account_name": "svenja",
  "ip": "95.211.217.30",
  "timestamp": "2025-03-27 09:15"
}
```

---

# 2) Mattermost bridge

**Endpoint:** `POST /notifications`
**Env needed on server:** *(none required; optional overrides inside code)*
**Routing key:** `mattermost_webhook` (string URL)

> The code also accepts `webhook` or `mm_webhook` as aliases.

## Required fields

* `type`: `"payment"` or `"auth"`
* `mattermost_webhook`: string, e.g. `"https://mattermost.example.com/hooks/XXXX"`

## Payment payload

```json
{
  "type": "payment",
  "mattermost_webhook": "https://mattermost.example.com/hooks/XXXX",
  "direction": "incoming",
  "amount": 3000,
  "wallet_name": "Tips Wallet",
  "memo": "Danke ❤️",
  "timestamp": "2025-03-27 09:15"
}
```

## Auth payload

```json
{
  "type": "auth",
  "mattermost_webhook": "https://mattermost.example.com/hooks/XXXX",
  "account_name": "svenja",
  "ip": "95.211.217.30",
  "timestamp": "2025-03-27 09:15"
}
```

---

# 3) Nostr DM bridge

**Endpoint:** `POST /notifications`
**Env needed on server:** `NOSTR_SECRET` (Buho’s nsec or 64-hex)
**Routing key:** `recipient` (recipient’s pubkey as `npub…` or 64-hex)

### Optional channel params

* `cipher`: `"nip44"` (default) or `"nip04"`
* `relays`: array of relay URLs; if omitted, defaults to the 5 baked into the service

## Required fields

* `type`: `"payment"` or `"auth"`
* `recipient`: `"npub1..."` **or** `"64hexpubkey"`

## Payment payload

```json
{
  "type": "payment",
  "recipient": "npub1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "direction": "incoming",
  "amount": 3000,
  "wallet_name": "Tips Wallet",
  "memo": "Danke ❤️",
  "timestamp": "2025-03-27 09:15",

  "cipher": "nip44",                  // optional: "nip44" (default) | "nip04"
  "relays": [                         // optional: override default pool
    "wss://relay.damus.io",
    "wss://nos.lol"
  ]
}
```

## Auth payload

```json
{
  "type": "auth",
  "recipient": "f3ab2c8f2c7a0d2f9e2b4d1c0a9e8f7d6c5b4a3928173645fedcba9876543210",
  "account_name": "svenja",
  "ip": "95.211.217.30",
  "timestamp": "2025-03-27 09:15",

  "cipher": "nip04"                   // optional
}
```

---

# 4) Email (SMTP) bridge

**Endpoint:** `POST /notifications`
**Env needed on server:** `SMTP_HOST`, `SMTP_FROM`, and either STARTTLS or SSL settings:

* STARTTLS (587): `SMTP_USE_SSL=false`, `SMTP_USE_STARTTLS=true`, `SMTP_PORT=587`
* SSL (465): `SMTP_USE_SSL=true`, `SMTP_USE_STARTTLS=false`, `SMTP_PORT=465`
* If your SMTP requires auth: `SMTP_USERNAME`, `SMTP_PASSWORD`
* Optional fallback: `DEFAULT_TO="ops@example.com,alerts@example.com"`

**Routing keys:** one of:

* `recipient`: single email string, or
* `recipients`: array of emails
  Optional: `cc` (string or array), `bcc` (string or array)

## Required fields

* `type`: `"payment"` or `"auth"`
* At least one target: `recipient` **or** `recipients` (or `DEFAULT_TO` must be set server-side)

## Payment payload

```json
{
  "type": "payment",
  "recipient": "alice@example.com",   // or "recipients": ["a@x.com","b@y.com"]
  "direction": "incoming",
  "amount": 3000,
  "wallet_name": "Tips Wallet",
  "memo": "Danke ❤️",
  "timestamp": "2025-03-27 09:15",

  "cc": "owner@example.com",          // optional: string or array
  "bcc": ["audit@example.com"]        // optional
}
```

## Auth payload

```json
{
  "type": "auth",
  "recipients": ["secops@example.com", "admin@example.com"],
  "account_name": "svenja",
  "ip": "95.211.217.30",
  "timestamp": "2025-03-27 09:15",

  "cc": [],
  "bcc": []
}
```

---

# Field reference (shared between channels)

| Field          | Type    | Used by                            | Notes                        |
| -------------- | ------- | ---------------------------------- | ---------------------------- |
| `type`         | string  | all                                | `"payment"` or `"auth"`      |
| `direction`    | string  | Telegram, Mattermost, Email, Nostr | `"incoming"` or `"outgoing"` |
| `amount`       | integer | Telegram, Mattermost, Email, Nostr | sats                         |
| `wallet_name`  | string  | Telegram, Mattermost, Email, Nostr | display only                 |
| `memo`         | string  | Telegram, Mattermost, Email, Nostr | display only                 |
| `timestamp`    | string  | all                                | display only                 |
| `account_name` | string  | Telegram, Mattermost, Email, Nostr | for auth events              |
| `ip`           | string  | Telegram, Mattermost, Email, Nostr | for auth events              |

**Channel-specific routing keys**

* Telegram: `telegram_chat_id` (int)
* Mattermost: `mattermost_webhook` (string URL) — aliases: `webhook`, `mm_webhook`
* Nostr: `recipient` (npub or 64-hex), optional `cipher`, optional `relays`
* Email: `recipient` (string) or `recipients` (array), optional `cc`, `bcc`

---

# Quick sanity checklist for Buho

* Always include `type`.
* Provide the **channel’s routing key** required for that script.
* For `payment`, include: `direction`, `amount`, `wallet_name`, `memo`, `timestamp`.
* For `auth`, include: `account_name`, `ip`, `timestamp`.

If you want, I can also ship these as **JSON Schemas** (\*.schema.json) for validation on Buho’s side.

