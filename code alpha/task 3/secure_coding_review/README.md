# 🔐 Secure Coding Review — Python / Flask

A complete security audit project targeting a Python Flask web application.  
Covers static analysis, manual code review, vulnerability documentation, and a fully remediatedSecure version.

> **Educational purposes only.** The vulnerable app intentionally contains real-world security flaws.

---

## 📁 Project Structure

```
secure_coding_review/
│
├── vulnerable_app/
│   └── app.py              ← Intentionally insecure Flask API (15 vulnerabilities)
│
├── secure_app/
│   └── app.py              ← Fully remediated secure version
│
├── analyzer/
│   └── security_analyzer.py  ← Custom Python static security analyzer (15 rules)
│
├── report/
│   ├── security_audit_report.html   ← Interactive HTML audit report (open in browser)
│   ├── findings_vulnerable.json     ← Machine-readable findings (17 issues)
│   └── findings_secure.json         ← Findings after remediation (0 issues)
│
├── requirements.txt
└── README.md
```

---

## 🚨 Vulnerabilities Found (17 Findings)

| ID | Severity | Category | Vulnerability |
|----|----------|----------|---------------|
| VULN-01 | 🔴 CRITICAL | SQL Injection | String-formatted SQL in `/login` |
| VULN-02 | 🔴 CRITICAL | SQL Injection | String concatenation in `/user/<username>` |
| VULN-03 | 🔴 CRITICAL | Command Injection | `subprocess` with `shell=True` in `/ping` |
| VULN-04 | 🔴 CRITICAL | Insecure Deserialization | `pickle.loads()` on user data in `/restore` |
| VULN-05 | 🔴 CRITICAL | XSS | `render_template_string` with raw user input in `/search` |
| VULN-06 | 🟠 HIGH | Weak Cryptography | MD5 password hashing (no salt) |
| VULN-07 | 🟠 HIGH | Sensitive Data Exposure | Hardcoded Flask `secret_key` |
| VULN-08 | 🟠 HIGH | Sensitive Data Exposure | Hardcoded DB password & admin token |
| VULN-09 | 🟠 HIGH | Broken Access Control | No authentication on `/admin/users` |
| VULN-10 | 🟠 HIGH | Broken Access Control | IDOR — no ownership check on `/user/<username>` |
| VULN-11 | 🟠 HIGH | Information Disclosure | `/config` endpoint exposes all secrets |
| VULN-12 | 🟠 HIGH | Open Redirect | No URL validation in `/redirect` |
| VULN-13 | 🟠 HIGH | Debug Mode | `debug=True` exposes interactive Python REPL |
| VULN-14 | 🟡 MEDIUM | Security Misconfiguration | Server bound to `0.0.0.0` |
| VULN-15 | 🟡 MEDIUM | Path Traversal | No path sanitization in `/report` |
| VULN-16 | 🟢 LOW | Logging | Passwords written to application logs |
| VULN-17 | 🟢 LOW | Dependency | `pickle` module imported |

---

## 🛠 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the custom static analyzer
```bash
# Scan the vulnerable app
python3 analyzer/security_analyzer.py vulnerable_app/app.py

# Scan the secure app (should report 0 findings)
python3 analyzer/security_analyzer.py secure_app/app.py

# Scan both, output JSON
python3 analyzer/security_analyzer.py --dir . --json findings.json
```

### 3. View the interactive HTML report
```bash
open report/security_audit_report.html
# or just double-click it
```

### 4. Run professional tools (optional)
```bash
# Bandit — Python SAST
pip install bandit
bandit -r vulnerable_app/ -f txt

# pip-audit — dependency CVE scan
pip install pip-audit
pip-audit

# Semgrep — semantic analysis
pip install semgrep
semgrep --config=p/python vulnerable_app/
```

---

## 🔍 OWASP Top 10 Coverage

| OWASP Category | Findings |
|----------------|----------|
| A01 — Broken Access Control | 3 |
| A02 — Cryptographic Failures | 6 |
| A03 — Injection | 5 |
| A05 — Security Misconfiguration | 2 |
| A08 — Software & Data Integrity Failures | 2 |
| A09 — Security Logging Failures | 1 |

---

## ✅ Remediations Applied (secure_app/app.py)

| Vulnerability | Fix Applied |
|---------------|-------------|
| SQL Injection | SQLAlchemy ORM with parameterized queries |
| Command Injection | `shell=False` + strict hostname allowlist regex |
| Insecure Deserialization | `json.loads()` — pickle removed entirely |
| XSS | `markupsafe.escape()` + static templates |
| Weak Crypto | `bcrypt` with auto-salt (rounds=12) |
| Hardcoded Secrets | `os.environ['SECRET_KEY']` — never in source |
| Missing Auth | JWT-based auth + `@require_role` RBAC decorator |
| IDOR | Ownership check: `current_user_id == user_id` or admin role |
| Path Traversal | `Path.resolve()` + `relative_to()` confinement |
| Open Redirect | Explicit allowlist of trusted redirect hosts |
| Debug Mode | `debug=False`, bound to `127.0.0.1` |
| Logging | Only user IDs and event types logged |

---

## 📚 References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [OWASP Python Security Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Python_Security_Cheat_Sheet.html)
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Flask Security Considerations](https://flask.palletsprojects.com/en/3.0.x/security/)

---

## ⚠️ Disclaimer

The vulnerable application (`vulnerable_app/app.py`) is intentionally insecure for educational purposes.  
**Never deploy it.** Use only in isolated, offline lab environments.

---

## 📄 License

MIT License
