import sqlite3
import string
import random
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, redirect, jsonify, abort, send_from_directory
import os

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "tracker.db")
STALE_HOURS = 24   # link flagged stale after this many hours with no human click
EXPIRY_DAYS = 30   # links older than this are deleted by the cleanup job

# ── Bot detection ─────────────────────────────────────────────────────────────
# Covers: WhatsApp, Telegram, all major social previews, SEO crawlers,
# HTTP libraries that get used by scripts, and empty UAs (also bots).
BOT_SIGNATURES = [
    # Messaging app link previews
    "whatsapp", "telegrambot", "telegram",
    # Social media crawlers
    "facebookexternalhit", "facebookcatalog", "twitterbot", "linkedinbot",
    "slackbot", "slack-imgproxy", "discordbot", "pinterestbot",
    "redditbot", "tumblr", "vkshare", "w3c_validator",
    # Search engine bots
    "googlebot", "google-inspectiontool", "bingbot", "yandexbot",
    "baiduspider", "duckduckbot", "ahrefsbot", "semrushbot", "mj12bot",
    # Generic HTTP tools (scripts, not browsers)
    "curl", "wget", "python-requests", "python-urllib", "httpx",
    "go-http-client", "java/", "libwww-perl", "okhttp",
    # Preview / screenshot services
    "iframely", "embedly", "rogerbot", "screaming frog",
    "preview", "thumbnail", "screenshot",
]

def is_bot(user_agent: str) -> bool:
    if not user_agent or len(user_agent.strip()) == 0:
        return True   # empty UA = almost always a bot or script
    ua = user_agent.lower()
    return any(sig in ua for sig in BOT_SIGNATURES)


# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS links (
                id          TEXT PRIMARY KEY,
                original    TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL        -- NEW: hard expiry timestamp
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS clicks (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                link_id      TEXT NOT NULL,
                timestamp    TEXT NOT NULL,
                user_agent   TEXT,
                ip           TEXT,
                fingerprint  TEXT,
                is_bot       INTEGER NOT NULL DEFAULT 0,
                is_duplicate INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (link_id) REFERENCES links(id)
            )
        """)

init_db()


# ── Helpers ───────────────────────────────────────────────────────────────────
def gen_id(n=7):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def make_fingerprint(ip: str, ua: str) -> str:
    raw = f"{ip}|{ua}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]

def already_clicked(db, link_id: str, fingerprint: str) -> bool:
    row = db.execute(
        """SELECT 1 FROM clicks
           WHERE link_id = ? AND fingerprint = ? AND is_bot = 0 LIMIT 1""",
        (link_id, fingerprint)
    ).fetchone()
    return row is not None

def last_human_click(db, link_id: str):
    row = db.execute(
        """SELECT timestamp FROM clicks
           WHERE link_id = ? AND is_bot = 0
           ORDER BY timestamp DESC LIMIT 1""",
        (link_id,)
    ).fetchone()
    return row["timestamp"] if row else None


# ── Cleanup job ───────────────────────────────────────────────────────────────
def delete_expired_links():
    """
    Hard-deletes all links (and their clicks) past their expires_at timestamp.
    Call this on every shorten request so it runs passively with no scheduler.
    """
    now = datetime.utcnow().isoformat()
    with get_db() as db:
        expired = db.execute(
            "SELECT id FROM links WHERE expires_at < ?", (now,)
        ).fetchall()
        for row in expired:
            db.execute("DELETE FROM clicks WHERE link_id = ?", (row["id"],))
            db.execute("DELETE FROM links  WHERE id = ?",      (row["id"],))
    return len(expired)


# ── Privacy consent page ──────────────────────────────────────────────────────
CONSENT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>You're being redirected</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; margin: 0; background: #f4f5f7;
    }}
    .box {{
      background: white; border-radius: 12px; padding: 36px 40px;
      max-width: 460px; text-align: center;
      box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    }}
    h2 {{ font-size: 1.2rem; margin-bottom: 10px; }}
    p  {{ font-size: 0.9rem; color: #666; margin-bottom: 24px; line-height: 1.5; }}
    .dest {{ font-size: 0.8rem; color: #aaa; margin-bottom: 24px;
             word-break: break-all; }}
    .btn {{
      display: inline-block; padding: 12px 28px; background: #4f6ef7;
      color: white; border-radius: 8px; text-decoration: none;
      font-size: 0.95rem; font-weight: 600;
    }}
    .btn:hover {{ background: #3a57d4; }}
    .skip {{
      display: block; margin-top: 14px; font-size: 0.8rem; color: #aaa;
    }}
  </style>
</head>
<body>
  <div class="box">
    <h2>🔗 You're about to be redirected</h2>
    <p>This link is tracked. Clicking it records an anonymous click event
       (no personal data, no login required). The person who shared this
       link can see how many unique visitors clicked it.</p>
    <div class="dest">→ {dest}</div>
    <a class="btn" href="/r/{link_id}?consent=1">Continue to link</a>
    <a class="skip" href="{dest}">Go directly without tracking</a>
  </div>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/shorten")
def shorten():
    """
    Body: {{ "url": "...", "consent": true/false }}
    consent=true  → show privacy notice before redirect
    consent=false → redirect immediately (default)
    """
    delete_expired_links()   # passive cleanup on every shorten

    data        = request.get_json(force=True)
    original    = data.get("url", "").strip()
    show_consent = data.get("consent", False)  # NEW: opt-in consent notice

    if not original or not original.startswith("http"):
        return jsonify({"error": "Invalid URL"}), 400

    link_id    = gen_id()
    now        = datetime.utcnow()
    expires_at = (now + timedelta(days=EXPIRY_DAYS)).isoformat()

    with get_db() as db:
        db.execute(
            "INSERT INTO links (id, original, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (link_id, original, now.isoformat(), expires_at)
        )
        # Store consent preference in a separate small table if needed;
        # for now encode it in the ID prefix: 'c_' = consent required
        if show_consent:
            db.execute(
                "UPDATE links SET id = ? WHERE id = ?",
                ("c_" + link_id, link_id)
            )
            link_id = "c_" + link_id

    short_url = f"{request.host_url}r/{link_id}"
    return jsonify({
        "id":         link_id,
        "short_url":  short_url,
        "expires_at": expires_at,
        "consent_notice": show_consent
    }), 201


@app.get("/r/<link_id>")
def track_and_redirect(link_id):
    with get_db() as db:
        row = db.execute(
            "SELECT original, expires_at FROM links WHERE id = ?", (link_id,)
        ).fetchone()

    if not row:
        abort(404)

    # Check expiry
    if datetime.utcnow().isoformat() > row["expires_at"]:
        return jsonify({"error": "This link has expired"}), 410

    # Consent gate: links prefixed 'c_' show notice unless consent=1 in query
    if link_id.startswith("c_") and request.args.get("consent") != "1":
        return CONSENT_HTML.format(dest=row["original"], link_id=link_id), 200

    ua          = request.headers.get("User-Agent", "")
    ip          = request.headers.get("X-Forwarded-For", request.remote_addr)
    bot         = is_bot(ua)
    now         = datetime.utcnow().isoformat()
    fingerprint = make_fingerprint(ip, ua)
    duplicate   = (not bot) and already_clicked(db, link_id, fingerprint)

    with get_db() as db:
        db.execute(
            """INSERT INTO clicks
               (link_id, timestamp, user_agent, ip, fingerprint, is_bot, is_duplicate)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (link_id, now, ua, ip, fingerprint, int(bot), int(duplicate))
        )

    return redirect(row["original"], code=302)


@app.get("/stats/<link_id>")
def stats(link_id):
    with get_db() as db:
        link = db.execute(
            "SELECT * FROM links WHERE id = ?", (link_id,)
        ).fetchone()
        if not link:
            abort(404)

        clicks = db.execute(
            "SELECT * FROM clicks WHERE link_id = ? ORDER BY timestamp DESC",
            (link_id,)
        ).fetchall()

        last_click = last_human_click(db, link_id)

    human      = [c for c in clicks if not c["is_bot"]]
    bots       = [c for c in clicks if c["is_bot"]]
    unique     = [c for c in human  if not c["is_duplicate"]]
    duplicates = [c for c in human  if c["is_duplicate"]]

    stale = False
    if last_click:
        stale = (datetime.utcnow() - datetime.fromisoformat(last_click)) > timedelta(hours=STALE_HOURS)
    else:
        stale = (datetime.utcnow() - datetime.fromisoformat(link["created_at"])) > timedelta(hours=STALE_HOURS)

    # Check if expired
    expired = datetime.utcnow().isoformat() > link["expires_at"]

    return jsonify({
        "id":               link_id,
        "original_url":     link["original"],
        "created_at":       link["created_at"],
        "expires_at":       link["expires_at"],        # NEW
        "expired":          expired,                   # NEW
        "stale":            stale,
        "last_human_click": last_click,
        "total_clicks":     len(clicks),
        "human_clicks":     len(human),
        "unique_humans":    len(unique),
        "duplicate_clicks": len(duplicates),
        "bot_clicks":       len(bots),
        "recent": [
            {
                "timestamp":    c["timestamp"],
                "fingerprint":  c["fingerprint"],
                "is_bot":       bool(c["is_bot"]),
                "is_duplicate": bool(c["is_duplicate"])
            }
            for c in clicks[:10]
        ]
    })


@app.get("/cleanup")
def cleanup():
    """Manually trigger cleanup — returns how many links were deleted."""
    deleted = delete_expired_links()
    return jsonify({"deleted": deleted, "timestamp": datetime.utcnow().isoformat()})


@app.get("/links")
def list_links():
    with get_db() as db:
        rows = db.execute(
            "SELECT id FROM links ORDER BY created_at DESC"
        ).fetchall()
    return jsonify({"links": [r["id"] for r in rows]})


@app.get("/")
def dashboard():
    return send_from_directory(".", "dashboard.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000)