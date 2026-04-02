import os
import sqlite3
import string
import random
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, request, redirect, jsonify, abort,
    send_from_directory, session, g
)
import bcrypt

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")

DB          = os.environ.get("DB_PATH", "tracker.db")
STALE_HOURS = 24
EXPIRY_DAYS = 30

# ── Bot signatures ────────────────────────────────────────────────────────────
BOT_SIGNATURES = [
    "whatsapp", "telegrambot", "telegram",
    "facebookexternalhit", "facebookcatalog", "twitterbot", "linkedinbot",
    "slackbot", "slack-imgproxy", "discordbot", "pinterestbot",
    "redditbot", "tumblr", "vkshare", "w3c_validator",
    "googlebot", "google-inspectiontool", "bingbot", "yandexbot",
    "baiduspider", "duckduckbot", "ahrefsbot", "semrushbot", "mj12bot",
    "curl", "wget", "python-requests", "python-urllib", "httpx",
    "go-http-client", "java/", "libwww-perl", "okhttp",
    "iframely", "embedly", "rogerbot", "screaming frog",
    "preview", "thumbnail", "screenshot",
]

def is_bot(user_agent: str) -> bool:
    if not user_agent or not user_agent.strip():
        return True
    return any(sig in user_agent.lower() for sig in BOT_SIGNATURES)


# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT UNIQUE NOT NULL,
                password   TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS links (
                id         TEXT PRIMARY KEY,
                user_id    INTEGER NOT NULL,
                original   TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
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
        db.commit()

init_db()


# ── Auth helpers ──────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def current_user_id():
    return session.get("user_id")


# ── Helpers ───────────────────────────────────────────────────────────────────
def gen_id(n=7):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def make_fingerprint(ip, ua):
    return hashlib.sha256(f"{ip}|{ua}".encode()).hexdigest()[:16]

def already_clicked(db, link_id, fingerprint):
    return db.execute(
        "SELECT 1 FROM clicks WHERE link_id=? AND fingerprint=? AND is_bot=0 LIMIT 1",
        (link_id, fingerprint)
    ).fetchone() is not None

def last_human_click(db, link_id):
    row = db.execute(
        "SELECT timestamp FROM clicks WHERE link_id=? AND is_bot=0 ORDER BY timestamp DESC LIMIT 1",
        (link_id,)
    ).fetchone()
    return row["timestamp"] if row else None

def delete_expired_links():
    db  = get_db()
    now = datetime.utcnow().isoformat()
    expired = db.execute(
        "SELECT id FROM links WHERE expires_at < ?", (now,)
    ).fetchall()
    for row in expired:
        db.execute("DELETE FROM clicks WHERE link_id=?", (row["id"],))
        db.execute("DELETE FROM links  WHERE id=?",      (row["id"],))
    db.commit()
    return len(expired)


# ── Auth routes ───────────────────────────────────────────────────────────────
@app.post("/register")
def register():
    data     = request.get_json(force=True)
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db     = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (username, hashed, datetime.utcnow().isoformat())
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 409

    user = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    session["user_id"]  = user["id"]
    session["username"] = username
    return jsonify({"message": "Registered successfully", "username": username}), 201


@app.post("/login")
def login():
    data     = request.get_json(force=True)
    username = data.get("username", "").strip().lower()
    password = data.get("password", "").strip()

    db   = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username=?", (username,)
    ).fetchone()

    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return jsonify({"error": "Invalid username or password"}), 401

    session["user_id"]  = user["id"]
    session["username"] = user["username"]
    return jsonify({"message": "Logged in", "username": user["username"]}), 200


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"message": "Logged out"}), 200


@app.get("/me")
@login_required
def me():
    return jsonify({"user_id": session["user_id"], "username": session["username"]})


# ── Link routes ───────────────────────────────────────────────────────────────
@app.post("/shorten")
@login_required
def shorten():
    delete_expired_links()
    data         = request.get_json(force=True)
    original     = data.get("url", "").strip()
    show_consent = data.get("consent", False)

    if not original or not original.startswith("http"):
        return jsonify({"error": "Invalid URL"}), 400

    link_id    = ("c_" if show_consent else "") + gen_id()
    now        = datetime.utcnow()
    expires_at = (now + timedelta(days=EXPIRY_DAYS)).isoformat()
    db         = get_db()

    db.execute(
        "INSERT INTO links (id, user_id, original, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (link_id, current_user_id(), original, now.isoformat(), expires_at)
    )
    db.commit()

    return jsonify({
        "id":        link_id,
        "short_url": f"{request.host_url}r/{link_id}",
        "expires_at": expires_at
    }), 201


@app.get("/r/<link_id>")
def track_and_redirect(link_id):
    db  = get_db()
    row = db.execute(
        "SELECT original, expires_at FROM links WHERE id=?", (link_id,)
    ).fetchone()

    if not row:
        abort(404)
    if datetime.utcnow().isoformat() > row["expires_at"]:
        return jsonify({"error": "This link has expired"}), 410
    if link_id.startswith("c_") and request.args.get("consent") != "1":
        return CONSENT_HTML.format(dest=row["original"], link_id=link_id), 200

    ua          = request.headers.get("User-Agent", "")
    ip          = request.headers.get("X-Forwarded-For", request.remote_addr)
    bot         = is_bot(ua)
    fingerprint = make_fingerprint(ip, ua)
    duplicate   = (not bot) and already_clicked(db, link_id, fingerprint)

    db.execute(
        """INSERT INTO clicks (link_id, timestamp, user_agent, ip, fingerprint, is_bot, is_duplicate)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (link_id, datetime.utcnow().isoformat(), ua, ip, fingerprint, int(bot), int(duplicate))
    )
    db.commit()
    return redirect(row["original"], code=302)


@app.get("/stats/<link_id>")
@login_required
def stats(link_id):
    db   = get_db()
    link = db.execute(
        "SELECT * FROM links WHERE id=? AND user_id=?",
        (link_id, current_user_id())
    ).fetchone()

    if not link:
        abort(404)

    clicks     = db.execute(
        "SELECT * FROM clicks WHERE link_id=? ORDER BY timestamp DESC", (link_id,)
    ).fetchall()
    last_click = last_human_click(db, link_id)

    human      = [c for c in clicks if not c["is_bot"]]
    bots       = [c for c in clicks if c["is_bot"]]
    unique     = [c for c in human  if not c["is_duplicate"]]
    duplicates = [c for c in human  if c["is_duplicate"]]

    stale = (
        (datetime.utcnow() - datetime.fromisoformat(last_click))   > timedelta(hours=STALE_HOURS)
        if last_click else
        (datetime.utcnow() - datetime.fromisoformat(link["created_at"])) > timedelta(hours=STALE_HOURS)
    )

    return jsonify({
        "id":               link_id,
        "original_url":     link["original"],
        "created_at":       link["created_at"],
        "expires_at":       link["expires_at"],
        "expired":          datetime.utcnow().isoformat() > link["expires_at"],
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


@app.get("/links")
@login_required
def list_links():
    db   = get_db()
    rows = db.execute(
        "SELECT id FROM links WHERE user_id=? ORDER BY created_at DESC",
        (current_user_id(),)
    ).fetchall()
    return jsonify({"links": [r["id"] for r in rows]})


@app.get("/cleanup")
@login_required
def cleanup():
    return jsonify({"deleted": delete_expired_links()})


@app.get("/")
def dashboard():
    return send_from_directory(".", "dashboard.html")


# ── Consent page ──────────────────────────────────────────────────────────────
CONSENT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>You're being redirected</title>
  <style>
    body {{ font-family: -apple-system, sans-serif; display:flex; align-items:center;
            justify-content:center; min-height:100vh; margin:0; background:#f4f5f7; }}
    .box {{ background:white; border-radius:12px; padding:36px 40px; max-width:460px;
            text-align:center; box-shadow:0 2px 12px rgba(0,0,0,0.08); }}
    h2   {{ font-size:1.2rem; margin-bottom:10px; }}
    p    {{ font-size:0.9rem; color:#666; margin-bottom:24px; line-height:1.5; }}
    .dest {{ font-size:0.8rem; color:#aaa; margin-bottom:24px; word-break:break-all; }}
    .btn  {{ display:inline-block; padding:12px 28px; background:#4f6ef7; color:white;
             border-radius:8px; text-decoration:none; font-weight:600; }}
    .skip {{ display:block; margin-top:14px; font-size:0.8rem; color:#aaa; }}
  </style>
</head>
<body>
  <div class="box">
    <h2>🔗 You're about to be redirected</h2>
    <p>This link is tracked. Clicking it records an anonymous click event.
       The person who shared it can see how many unique visitors clicked.</p>
    <div class="dest">→ {dest}</div>
    <a class="btn" href="/r/{link_id}?consent=1">Continue to link</a>
    <a class="skip" href="{dest}">Go directly without tracking</a>
  </div>
</body>
</html>"""


if __name__ == "__main__":
    app.run(debug=True, port=5000)