"""
vulnerable_app/app.py
=====================
A purposely INSECURE Flask web application (User Management API).
Used as the audit target for the Secure Coding Review project.

DO NOT deploy this in production.
Every flaw here is intentional and documented in the security report.
"""

from flask import Flask, request, jsonify, render_template_string, redirect
import sqlite3
import hashlib
import os
import subprocess
import pickle
import base64
import logging

app = Flask(__name__)

# ── VULN-01: Hardcoded secret key ─────────────────────────────────────────────
app.secret_key = "supersecret123"

# ── VULN-02: Hardcoded credentials ───────────────────────────────────────────
DB_PASSWORD = "admin123"
ADMIN_TOKEN = "token_abc123_admin"

# ── VULN-03: Overly verbose logging (leaks sensitive data) ───────────────────
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def get_db():
    """Return a raw SQLite connection (no ORM, no parameterization)."""
    conn = sqlite3.connect("users.db")
    return conn


def init_db():
    conn = get_db()
    # Create table and seed demo data
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        )
    """)
    # ── VULN-04: Passwords stored as plain MD5 (no salt) ─────────────────────
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','" +
                 hashlib.md5(b"admin123").hexdigest() + "','admin@corp.com','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','" +
                 hashlib.md5(b"password").hexdigest() + "','alice@corp.com','user')")
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """
    VULN-05: SQL Injection
    User input inserted directly into SQL query string.
    Payload: username = ' OR '1'='1' --
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Log credentials — VULN-03 (sensitive data in logs)
    logger.debug(f"Login attempt: username={username} password={password}")

    hashed = hashlib.md5(password.encode()).hexdigest()

    # ── VULN-05: Raw string concatenation into SQL ────────────────────────────
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashed}'"
    conn = get_db()
    user = conn.execute(query).fetchone()
    conn.close()

    if user:
        return jsonify({"status": "ok", "role": user[4], "token": ADMIN_TOKEN})
    return jsonify({"status": "fail"}), 401


@app.route("/user/<username>")
def get_user(username):
    """
    VULN-06: SQL Injection (GET parameter)
    VULN-07: Insecure Direct Object Reference — no auth check.
    Any user can access any other user's data.
    """
    # ── VULN-05b: SQL injection in GET parameter ──────────────────────────────
    query = "SELECT id, username, email, role FROM users WHERE username='" + username + "'"
    conn = get_db()
    row = conn.execute(query).fetchone()
    conn.close()

    if row:
        return jsonify({"id": row[0], "username": row[1], "email": row[2], "role": row[3]})
    return jsonify({"error": "not found"}), 404


@app.route("/search")
def search():
    """
    VULN-08: Reflected Cross-Site Scripting (XSS).
    User input rendered directly into HTML without escaping.
    Payload: ?q=<script>alert('XSS')</script>
    """
    q = request.args.get("q", "")
    # ── VULN-08: Unescaped user input in HTML ─────────────────────────────────
    html = f"""
    <html><body>
      <h2>Search results for: {q}</h2>
      <p>No results found.</p>
    </body></html>
    """
    return render_template_string(html)


@app.route("/ping")
def ping():
    """
    VULN-09: OS Command Injection.
    User controls the host argument passed directly to shell.
    Payload: ?host=8.8.8.8; cat /etc/passwd
    """
    host = request.args.get("host", "localhost")
    # ── VULN-09: shell=True with unsanitized input ────────────────────────────
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return jsonify({"output": result})


@app.route("/report")
def report():
    """
    VULN-10: Path Traversal.
    Allows reading arbitrary files on the server filesystem.
    Payload: ?file=../../etc/passwd
    """
    filename = request.args.get("file", "report.txt")
    # ── VULN-10: No path sanitization ─────────────────────────────────────────
    with open(f"reports/{filename}", "r") as f:
        return f.read()


@app.route("/restore", methods=["POST"])
def restore():
    """
    VULN-11: Insecure Deserialization.
    Pickle data from the user is deserialized — enables RCE.
    """
    # ── VULN-11: pickle.loads on untrusted data ───────────────────────────────
    data = base64.b64decode(request.data)
    obj = pickle.loads(data)
    return jsonify({"restored": str(obj)})


@app.route("/redirect")
def open_redirect():
    """
    VULN-12: Open Redirect.
    Attackers can redirect users to malicious sites.
    Payload: ?next=https://evil.com
    """
    # ── VULN-12: No URL validation ────────────────────────────────────────────
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/admin/users")
def list_users():
    """
    VULN-13: Missing Authentication / Broken Access Control.
    Admin endpoint with zero auth check.
    """
    # ── VULN-13: No authentication enforced ──────────────────────────────────
    conn = get_db()
    rows = conn.execute("SELECT id, username, email, role, password FROM users").fetchall()
    conn.close()
    # Also returns hashed passwords — information disclosure
    return jsonify([{"id": r[0], "username": r[1], "email": r[2],
                     "role": r[3], "password_hash": r[4]} for r in rows])


@app.route("/config")
def show_config():
    """
    VULN-14: Information Disclosure — exposes environment & config.
    """
    # ── VULN-14: Exposes internals ────────────────────────────────────────────
    return jsonify({
        "secret_key": app.secret_key,
        "db_password": DB_PASSWORD,
        "debug": app.debug,
        "env": dict(os.environ),
    })


if __name__ == "__main__":
    init_db()
    # ── VULN-15: Debug mode ON in production, bound to 0.0.0.0 ───────────────
    app.run(debug=True, host="0.0.0.0", port=5000)
