"""
secure_app/app.py
=================
SECURE refactored Flask application.
Each fix is annotated with the vulnerability it addresses (VULN-XX).

Security controls applied:
  - Parameterized queries (SQLAlchemy ORM)
  - bcrypt password hashing with salt
  - JWT-based authentication
  - Role-based access control decorator
  - Input validation & output escaping
  - No shell=True in subprocess
  - Safe path resolution (no traversal)
  - JSON-only deserialization
  - Allowlist-based redirect validation
  - Secrets from environment variables
  - Debug mode OFF, bound to localhost only
  - Structured logging (no sensitive data)
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from functools import wraps

import bcrypt
import jwt
from flask import Flask, request, jsonify, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from markupsafe import escape
from datetime import datetime, timedelta, timezone

# ─────────────────────────────────────────────────────────────────────────────
# APP & CONFIG
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# FIX-01: Secret key loaded from environment variable, never hardcoded
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or (_ for _ in ()).throw(
    RuntimeError("SECRET_KEY environment variable is required")
)

# FIX-15: Debug mode controlled by environment, default OFF
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

# FIX for DB: Use SQLAlchemy ORM (prevents raw string SQL)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///secure_users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# FIX-03: Structured logging — never log credentials or tokens
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s"
)
logger = logging.getLogger(__name__)

# Allowlist for redirect targets (FIX-12)
ALLOWED_REDIRECT_HOSTS = {"app.example.com", "www.example.com"}

# Safe reports directory (FIX-10)
REPORTS_DIR = Path(__file__).parent / "reports"


# ─────────────────────────────────────────────────────────────────────────────
# MODEL
# ─────────────────────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = "users"
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)   # bcrypt hash
    email    = db.Column(db.String(120), unique=True, nullable=False)
    role     = db.Column(db.String(20), nullable=False, default="user")


def init_db():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        # FIX-04: bcrypt with automatic salt — never plain MD5
        hashed = bcrypt.hashpw(b"change_me_on_first_login", bcrypt.gensalt())
        admin = User(username="admin", password=hashed.decode(),
                     email="admin@corp.com", role="admin")
        db.session.add(admin)
        db.session.commit()
        logger.info("Admin user seeded.")


# ─────────────────────────────────────────────────────────────────────────────
# AUTH HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def create_token(user: User) -> str:
    """Issue a short-lived JWT. No sensitive data in payload."""
    payload = {
        "sub": user.id,
        "role": user.role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def require_auth(f):
    """Decorator: validate JWT, inject current user into kwargs."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401)
        token = auth_header.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        kwargs["current_user_id"] = payload["sub"]
        kwargs["current_role"] = payload["role"]
        return f(*args, **kwargs)
    return wrapper


def require_role(role: str):
    """Decorator: enforce role-based access control."""
    def decorator(f):
        @wraps(f)
        @require_auth
        def wrapper(*args, **kwargs):
            if kwargs.get("current_role") != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["POST"])
def login():
    """
    FIX-05: Parameterized query via ORM (SQLAlchemy).
    FIX-04: bcrypt comparison (constant-time).
    FIX-03: No credentials in logs.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # FIX-05: ORM parameterized query — no string concatenation
    user = User.query.filter_by(username=username).first()

    # FIX-04: constant-time bcrypt check (prevents timing attacks)
    if not user or not bcrypt.checkpw(password.encode(), user.password.encode()):
        logger.info("Failed login attempt for username: %s", username)
        # Generic message — don't leak whether username exists
        return jsonify({"error": "Invalid credentials"}), 401

    token = create_token(user)
    logger.info("Successful login for user id=%s", user.id)
    return jsonify({"token": token})


@app.route("/user/<int:user_id>")
@require_auth
def get_user(user_id, current_user_id, current_role):
    """
    FIX-06: ORM query (no SQL injection).
    FIX-07: Authorization check — users can only see their own profile
            unless they are admin.
    """
    if current_role != "admin" and current_user_id != user_id:
        abort(403)

    user = User.query.get_or_404(user_id)
    return jsonify({"id": user.id, "username": user.username,
                    "email": user.email, "role": user.role})


@app.route("/search")
def search():
    """
    FIX-08: Output escaped with markupsafe.escape() — no XSS.
    """
    q = request.args.get("q", "")
    safe_q = escape(q)   # All special HTML chars encoded
    # Use Jinja2 autoescaping (never render_template_string with raw input)
    return f"<html><body><h2>Results for: {safe_q}</h2><p>No results.</p></body></html>"


@app.route("/ping")
@require_auth
def ping(current_user_id, current_role):
    """
    FIX-09: No shell=True. Input validated against strict allowlist.
    Only admins can ping.
    """
    if current_role != "admin":
        abort(403)

    host = request.args.get("host", "")
    # Strict allowlist: only valid hostnames or IPv4
    if not re.match(r'^[a-zA-Z0-9.\-]{1,253}$', host) or ".." in host:
        return jsonify({"error": "Invalid host"}), 400

    # FIX-09: List form (no shell), explicit binary path
    result = subprocess.run(
        ["/bin/ping", "-c", "1", "-W", "2", host],
        capture_output=True, text=True, timeout=5
    )
    return jsonify({"output": result.stdout})


@app.route("/report")
@require_auth
def report(current_user_id, current_role):
    """
    FIX-10: Path traversal prevented via Path.resolve() + strict root check.
    """
    filename = request.args.get("file", "")
    if not filename:
        return jsonify({"error": "file parameter required"}), 400

    # Resolve and verify the path stays inside REPORTS_DIR
    requested = (REPORTS_DIR / filename).resolve()
    try:
        requested.relative_to(REPORTS_DIR.resolve())
    except ValueError:
        logger.warning("Path traversal attempt by user %s: %s", current_user_id, filename)
        abort(400)

    if not requested.exists() or not requested.is_file():
        abort(404)

    return requested.read_text()


@app.route("/restore", methods=["POST"])
@require_auth
def restore(current_user_id, current_role):
    """
    FIX-11: JSON-only. pickle.loads on untrusted data is never used.
    """
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"error": "JSON body required"}), 400
    # Process only safe, typed JSON fields
    name = str(data.get("name", ""))[:64]
    return jsonify({"restored": {"name": name}})


@app.route("/redirect")
def safe_redirect():
    """
    FIX-12: URL validated against an explicit allowlist of trusted hosts.
    """
    from urllib.parse import urlparse
    next_url = request.args.get("next", "/")
    parsed = urlparse(next_url)

    # Allow relative paths OR explicitly allowlisted hosts
    if parsed.netloc and parsed.netloc not in ALLOWED_REDIRECT_HOSTS:
        logger.warning("Blocked open redirect to: %s", next_url)
        return redirect("/")

    return redirect(next_url)


@app.route("/admin/users")
@require_role("admin")
def list_users(current_user_id, current_role):
    """
    FIX-13: Protected by @require_role("admin").
    FIX: Password hashes are NEVER returned in API responses.
    """
    users = User.query.all()
    return jsonify([
        {"id": u.id, "username": u.username, "email": u.email, "role": u.role}
        for u in users
    ])


@app.route("/health")
def health():
    """Minimal health endpoint — no internals exposed."""
    return jsonify({"status": "ok"})

# FIX-14: /config endpoint removed entirely.
# FIX-15: Run config moved to __main__ — never debug=True in production.

if __name__ == "__main__":
    with app.app_context():
        init_db()
    # FIX-15: Debug OFF, bound to localhost only (reverse proxy in front)
    app.run(debug=False, host="127.0.0.1", port=5000)
