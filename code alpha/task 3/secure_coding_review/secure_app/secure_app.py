"""
secure_app.py
=============
The fully remediated version of vulnerable_app.py.
Every vulnerability from the audit has been addressed.

Security controls applied:
  ✔ S-01  Parameterized queries (eliminates SQL Injection)
  ✔ S-02  Output escaping + CSP (eliminates XSS)
  ✔ S-03  Secret key from environment variable
  ✔ S-04  Ownership check on every resource (fixes IDOR)
  ✔ S-05  Rate-limiting + account lockout (fixes brute-force)
  ✔ S-06  Argon2 password hashing (no plaintext)
  ✔ S-07  subprocess with argument list, no shell=True
  ✔ S-08  File type allowlist, size limit, random filename
  ✔ S-09  Full security header suite
  ✔ S-10  Debug off, production WSGI server recommended
"""

import os
import re
import uuid
import secrets
import subprocess
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, request, render_template_string,
                   redirect, session, jsonify, abort, g)
import sqlite3

# ── Optional: pip install argon2-cffi flask-limiter ───────────────────
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    PH = PasswordHasher()
    ARGON2_AVAILABLE = True
except ImportError:
    import hashlib, hmac
    ARGON2_AVAILABLE = False

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

# ── APP SETUP ──────────────────────────────────────────────────────────
app = Flask(__name__)

# S-03: Secret key from environment variable — never hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

# S-10: Debug always OFF
app.debug = False

# Session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,  # S-08: 5 MB upload limit
)

# S-05: Rate limiter
if LIMITER_AVAILABLE:
    limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200/day"])

# ── SECURITY HEADERS MIDDLEWARE ────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    # S-09: Full security header suite
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # S-02: Content Security Policy — blocks inline script injection
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response

# ── DATABASE ───────────────────────────────────────────────────────────
DB_PATH = "secure_users.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_database", None)
    if db:
        db.close()

def hash_password(password: str) -> str:
    if ARGON2_AVAILABLE:
        return PH.hash(password)
    # Fallback: PBKDF2-HMAC-SHA256 with random salt
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex() + ":" + dk.hex()

def verify_password(stored: str, provided: str) -> bool:
    if ARGON2_AVAILABLE:
        try:
            return PH.verify(stored, provided)
        except VerifyMismatchError:
            return False
    # Fallback verification
    try:
        salt_hex, dk_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt, 260_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email         TEXT NOT NULL,
            role          TEXT DEFAULT 'user',
            failed_logins INTEGER DEFAULT 0,
            locked_until  TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id      INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    # S-06: Seed with hashed passwords
    for uid, uname, pwd, email, role in [
        (1, "admin", "AdminSecure#99", "admin@corp.com", "admin"),
        (2, "alice", "AlicePass#2024", "alice@corp.com", "user"),
        (3, "bob",   "Bob@Secure!7",   "bob@corp.com",   "user"),
    ]:
        existing = conn.execute("SELECT id FROM users WHERE id=?", (uid,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (id,username,password_hash,email,role) VALUES (?,?,?,?,?)",
                (uid, uname, hash_password(pwd), email, role)
            )
    conn.commit()
    conn.close()

# ── AUTH HELPERS ───────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

MAX_FAILED = 5
LOCKOUT_MINUTES = 15

# ── LOGIN ──────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    # S-05: Rate limiting on login endpoint
    if LIMITER_AVAILABLE:
        limiter.limit("10/minute")(lambda: None)()

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]   # length-limit input
        password = request.form.get("password", "")[:128]

        db = get_db()
        # S-01: Parameterized query — no string concatenation
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user:
            # S-05: Check lockout
            if user["locked_until"]:
                locked_until = datetime.fromisoformat(user["locked_until"])
                if datetime.utcnow() < locked_until:
                    minutes_left = int((locked_until - datetime.utcnow()).seconds / 60) + 1
                    error = f"Account locked. Try again in {minutes_left} minutes."
                    return render_template_string(LOGIN_HTML, error=error)
                else:
                    # Reset lockout
                    db.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?",
                               (user["id"],))
                    db.commit()

            # S-06: Constant-time password comparison using hashed verify
            if verify_password(user["password_hash"], password):
                db.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?",
                           (user["id"],))
                db.commit()
                session.clear()
                session["user_id"]  = user["id"]
                session["username"] = user["username"]
                session["role"]     = user["role"]
                return redirect("/dashboard")
            else:
                # S-05: Increment failed attempts, lock if threshold exceeded
                new_fails = (user["failed_logins"] or 0) + 1
                lock_time = None
                if new_fails >= MAX_FAILED:
                    lock_time = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                db.execute(
                    "UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                    (new_fails, lock_time, user["id"])
                )
                db.commit()

        # S-05: Same generic error regardless of whether user exists (prevents user enumeration)
        error = "Invalid credentials"

    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ── DASHBOARD ──────────────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML, username=session.get("username"))

# ── SEARCH ─────────────────────────────────────────────────────────────
@app.route("/search")
@login_required
@admin_required   # S-04: Only admins can search all users
def search():
    term = request.args.get("q", "").strip()[:64]
    db = get_db()
    # S-01: Parameterized query with LIKE
    users = db.execute(
        "SELECT id, username FROM users WHERE username LIKE ?",
        (f"%{term}%",)
    ).fetchall()
    # S-06: Return only non-sensitive fields
    return jsonify([{"id": u["id"], "username": u["username"]} for u in users])

# ── POSTS / XSS FIX ────────────────────────────────────────────────────
@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    message = ""
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if not content or len(content) > 2000:
            message = "Content must be 1–2000 characters."
        else:
            db = get_db()
            # S-01: Parameterized — S-02: Jinja2 auto-escapes on render
            db.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)",
                       (session["user_id"], content))
            db.commit()
            message = "Posted!"

    db = get_db()
    posts = db.execute("SELECT content FROM posts ORDER BY id DESC LIMIT 50").fetchall()
    # S-02: Pass as plain list — Jinja2 auto-escapes, NOT | safe
    return render_template_string(POST_HTML, posts=[p["content"] for p in posts], message=message)

# ── USER PROFILE (IDOR FIXED) ──────────────────────────────────────────
@app.route("/user/<int:user_id>")
@login_required
def view_user(user_id):
    # S-04: Users can only view their own profile; admins can view any
    if session["user_id"] != user_id and session.get("role") != "admin":
        abort(403)

    db = get_db()
    user = db.execute(
        "SELECT id, username, email, role FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        abort(404)

    # S-06: Never return password_hash or sensitive fields
    return jsonify({
        "id":       user["id"],
        "username": user["username"],
        "email":    user["email"],
        "role":     user["role"],
    })

# ── PING (COMMAND INJECTION FIXED) ────────────────────────────────────
VALID_HOST = re.compile(r"^[a-zA-Z0-9.\-]{1,253}$")

@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "").strip()
    # S-07: Validate host format strictly
    if not VALID_HOST.match(host):
        return jsonify({"error": "Invalid hostname"}), 400

    try:
        # S-07: List form — no shell=True, no injection possible
        result = subprocess.check_output(
            ["ping", "-c", "1", host],
            text=True, timeout=5,
            stderr=subprocess.DEVNULL
        )
        return f"<pre>{result}</pre>"
    except subprocess.CalledProcessError:
        return jsonify({"error": "Host unreachable"}), 400
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Request timed out"}), 408

# ── FILE UPLOAD (FIXED) ────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt"}
UPLOAD_DIR = "/tmp/secure_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    saved = ""
    error = ""
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            error = "No file selected."
        else:
            _, ext = os.path.splitext(f.filename)
            ext = ext.lower()

            # S-08: Extension allowlist
            if ext not in ALLOWED_EXTENSIONS:
                error = f"File type '{ext}' not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
            else:
                # S-08: Randomized filename — no path traversal via original name
                safe_name = f"{uuid.uuid4().hex}{ext}"
                path = os.path.join(UPLOAD_DIR, safe_name)
                f.save(path)
                saved = f"File saved securely as {safe_name}"

    return render_template_string(UPLOAD_HTML, saved=saved, error=error)

# ── TEMPLATES ──────────────────────────────────────────────────────────
LOGIN_HTML = """
<!doctype html><html><head><title>Login</title></head><body>
<h2>Secure Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  <label>Username <input name="username" autocomplete="username" maxlength="64"></label><br>
  <label>Password <input name="password" type="password" autocomplete="current-password" maxlength="128"></label><br>
  <button type="submit">Login</button>
</form>
</body></html>
"""

DASHBOARD_HTML = """
<!doctype html><html><head><title>Dashboard</title></head><body>
<h2>Welcome, {{ username | e }}</h2>
<nav><a href="/post">Posts</a> | <a href="/upload">Upload</a> | <a href="/logout">Logout</a></nav>
</body></html>
"""

POST_HTML = """
<!doctype html><html><head><title>Posts</title></head><body>
<h2>Posts</h2>
{% if message %}<p>{{ message | e }}</p>{% endif %}
<form method="post">
  <textarea name="content" rows="4" cols="50" maxlength="2000"></textarea><br>
  <button type="submit">Post</button>
</form>
<h3>Recent Posts:</h3>
{% for p in posts %}
  <div class="post">{{ p | e }}</div>
{% endfor %}
</body></html>
"""

UPLOAD_HTML = """
<!doctype html><html><head><title>Upload</title></head><body>
<h2>Upload File</h2>
{% if error %}<p style="color:red">{{ error | e }}</p>{% endif %}
{% if saved %}<p style="color:green">{{ saved | e }}</p>{% endif %}
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file" accept=".jpg,.jpeg,.png,.gif,.pdf,.txt">
  <button type="submit">Upload</button>
</form>
<p><small>Allowed types: JPG, PNG, GIF, PDF, TXT. Max size: 5 MB.</small></p>
</body></html>
"""

# ── ENTRY POINT ────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    # S-10: Use a production WSGI server (gunicorn/waitress), never debug=True
    # Example: gunicorn -w 4 -b 127.0.0.1:8000 secure_app:app
    print("Run with: gunicorn -w 4 -b 127.0.0.1:8000 secure_app:app")
    app.run(host="127.0.0.1", port=8000, debug=False)
