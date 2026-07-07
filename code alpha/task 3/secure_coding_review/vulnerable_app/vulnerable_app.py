"""
vulnerable_app.py
=================
A deliberately insecure Flask web application used as the audit target
for the Secure Coding Review project.

DO NOT deploy this in production. Every security flaw is intentional
and documented in the accompanying audit report.

Vulnerabilities present:
  V-01  SQL Injection (login & search)
  V-02  Stored Cross-Site Scripting (XSS)
  V-03  Hardcoded credentials & secret key
  V-04  Insecure Direct Object Reference (IDOR)
  V-05  Broken Authentication (no rate-limiting, no lockout)
  V-06  Sensitive data exposure (passwords in plaintext)
  V-07  Command Injection (ping utility)
  V-08  Insecure file upload (no type/size validation)
  V-09  Missing security headers
  V-10  Debug mode enabled in production
"""

from flask import Flask, request, render_template_string, redirect, session, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

# V-03: Hardcoded secret key — trivially guessable
app.secret_key = "password123"

# V-10: Debug mode ON — exposes interactive debugger to any visitor
app.debug = True

# ── DATABASE SETUP ─────────────────────────────────────────────────────
DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email    TEXT,
            role     TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id      INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT
        )
    """)
    # V-06: Passwords stored in plaintext
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@corp.com','admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','alice2024','alice@corp.com','user')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3,'bob',  'bob@pass', 'bob@corp.com', 'user')")
    conn.commit()
    conn.close()

# ── LOGIN ──────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # V-01: SQL Injection — user input concatenated directly into SQL
        # Attack: username = ' OR '1'='1' --
        conn = sqlite3.connect(DB_PATH)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        result = conn.execute(query).fetchone()
        conn.close()

        if result:
            session["user_id"] = result[0]
            session["username"] = result[1]
            session["role"] = result[4]
            return redirect("/dashboard")
        # V-05: No rate-limiting — attacker can brute-force indefinitely
        error = "Invalid credentials"

    return render_template_string(LOGIN_HTML, error=error)

# ── DASHBOARD ──────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template_string(DASHBOARD_HTML, username=session.get("username"))

# ── SEARCH ─────────────────────────────────────────────────────────────
@app.route("/search")
def search():
    # V-01: Second SQL injection point
    term = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{term}%'"
    results = conn.execute(query).fetchall()
    conn.close()
    return jsonify(results)

# ── POST / XSS ─────────────────────────────────────────────────────────
@app.route("/post", methods=["GET", "POST"])
def post():
    if "user_id" not in session:
        return redirect("/login")

    message = ""
    if request.method == "POST":
        content = request.form.get("content", "")
        conn = sqlite3.connect(DB_PATH)
        # V-02: Content stored raw — no sanitization, no escaping
        conn.execute("INSERT INTO posts (user_id, content) VALUES (?, ?)",
                     (session["user_id"], content))
        conn.commit()
        conn.close()
        message = "Posted!"

    conn = sqlite3.connect(DB_PATH)
    posts = conn.execute("SELECT content FROM posts").fetchall()
    conn.close()

    # V-02: Rendered with |safe — raw HTML/JS injected into page
    posts_html = "".join(f"<div class='post'>{p[0]}</div>" for p in posts)
    return render_template_string(POST_HTML, posts=posts_html, message=message)

# ── IDOR ───────────────────────────────────────────────────────────────
@app.route("/user/<int:user_id>")
def view_user(user_id):
    if "user_id" not in session:
        return redirect("/login")

    # V-04: IDOR — any logged-in user can view ANY user's profile
    # No check that session["user_id"] == user_id
    conn = sqlite3.connect(DB_PATH)
    user = conn.execute(
        "SELECT id, username, email, password, role FROM users WHERE id=?",
        (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        return "User not found", 404

    # V-06: Password exposed in API response
    return jsonify({
        "id": user[0],
        "username": user[1],
        "email": user[2],
        "password": user[3],   # plaintext password returned!
        "role": user[4]
    })

# ── COMMAND INJECTION ──────────────────────────────────────────────────
@app.route("/ping")
def ping():
    if "user_id" not in session:
        return redirect("/login")

    host = request.args.get("host", "localhost")

    # V-07: Command injection — input passed directly to shell=True
    # Attack: host = "localhost; cat /etc/passwd"
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, text=True)
    return f"<pre>{result}</pre>"

# ── FILE UPLOAD ────────────────────────────────────────────────────────
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect("/login")

    saved = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # V-08: No file type validation, no size limit, uses original filename
            # Attacker can upload shell.php, malware.exe, or a 10 GB bomb
            path = os.path.join(UPLOAD_DIR, f.filename)
            f.save(path)
            saved = f"Saved to {path}"

    return render_template_string(UPLOAD_HTML, saved=saved)

# ── MINIMAL HTML TEMPLATES ─────────────────────────────────────────────
LOGIN_HTML = """
<html><body>
<h2>Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <button type="submit">Login</button>
</form>
</body></html>
"""

DASHBOARD_HTML = """
<html><body>
<h2>Welcome, {{ username }}</h2>
<a href="/post">Posts</a> | <a href="/upload">Upload</a> | <a href="/ping?host=localhost">Ping</a>
</body></html>
"""

POST_HTML = """
<html><body>
<h2>Posts</h2>
{% if message %}<p>{{ message }}</p>{% endif %}
<form method="post">
  <textarea name="content" rows="4" cols="50"></textarea><br>
  <button type="submit">Post</button>
</form>
<h3>All Posts:</h3>
{{ posts | safe }}
</body></html>
"""

UPLOAD_HTML = """
<html><body>
<h2>Upload File</h2>
{% if saved %}<p>{{ saved }}</p>{% endif %}
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <button type="submit">Upload</button>
</form>
</body></html>
"""

if __name__ == "__main__":
    init_db()
    # V-10: Running on 0.0.0.0 (all interfaces) with debug=True
    app.run(host="0.0.0.0", port=5000, debug=True)
