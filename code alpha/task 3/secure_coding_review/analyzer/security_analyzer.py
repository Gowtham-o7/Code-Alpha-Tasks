#!/usr/bin/env python3
"""
analyzer/security_analyzer.py
==============================
Static security analyzer for Python source code.
Detects common vulnerabilities using pattern matching and AST inspection.

Usage:
    python3 analyzer/security_analyzer.py vulnerable_app/app.py
    python3 analyzer/security_analyzer.py secure_app/app.py
    python3 analyzer/security_analyzer.py --dir vulnerable_app/
"""

import ast
import re
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[34m",
    "INFO":     "\033[36m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


@dataclass
class Finding:
    rule_id:     str
    severity:    str
    category:    str
    title:       str
    description: str
    file:        str
    line:        int
    code:        str
    remediation: str
    cwe:         str
    owasp:       str


@dataclass
class AnalysisResult:
    file:          str
    findings:      List[Finding] = field(default_factory=list)
    lines_scanned: int = 0

    @property
    def critical(self): return [f for f in self.findings if f.severity == "CRITICAL"]
    @property
    def high(self):     return [f for f in self.findings if f.severity == "HIGH"]
    @property
    def medium(self):   return [f for f in self.findings if f.severity == "MEDIUM"]
    @property
    def low(self):      return [f for f in self.findings if f.severity == "LOW"]


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION RULES
# ─────────────────────────────────────────────────────────────────────────────

REGEX_RULES = [
    {
        "rule_id":     "SEC-001",
        "severity":    "CRITICAL",
        "category":    "SQL Injection",
        "title":       "String-formatted SQL query",
        "pattern":     re.compile(r'(execute|query)\s*\(\s*[f"\'](.*?)(SELECT|INSERT|UPDATE|DELETE|WHERE)', re.IGNORECASE),
        "description": "SQL query constructed via string formatting allows injection.",
        "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
        "cwe":  "CWE-89",
        "owasp": "A03:2021 – Injection",
    },
    {
        "rule_id":     "SEC-002",
        "severity":    "CRITICAL",
        "category":    "SQL Injection",
        "title":       "String concatenation in SQL",
        "pattern":     re.compile(r'(WHERE|AND|OR)\s+\w+\s*=\s*[\'"]?\s*\+', re.IGNORECASE),
        "description": "SQL built via string concatenation is injectable.",
        "remediation": "Use an ORM (SQLAlchemy) or parameterized placeholders.",
        "cwe":  "CWE-89",
        "owasp": "A03:2021 – Injection",
    },
    {
        "rule_id":     "SEC-003",
        "severity":    "CRITICAL",
        "category":    "Command Injection",
        "title":       "subprocess with shell=True",
        "pattern":     re.compile(r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True'),
        "description": "shell=True passes command to the OS shell, enabling injection.",
        "remediation": "Use a list of arguments and shell=False: subprocess.run(['/bin/cmd', arg])",
        "cwe":  "CWE-78",
        "owasp": "A03:2021 – Injection",
    },
    {
        "rule_id":     "SEC-004",
        "severity":    "CRITICAL",
        "category":    "Insecure Deserialization",
        "title":       "pickle.loads on potentially untrusted data",
        "pattern":     re.compile(r'pickle\.(loads|load)\s*\('),
        "description": "Deserializing untrusted pickle data allows arbitrary code execution.",
        "remediation": "Use JSON for data exchange. Never deserialize untrusted binary data with pickle.",
        "cwe":  "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
    },
    {
        "rule_id":     "SEC-005",
        "severity":    "HIGH",
        "category":    "Weak Cryptography",
        "title":       "MD5 used for password hashing",
        "pattern":     re.compile(r'hashlib\.md5\s*\('),
        "description": "MD5 is cryptographically broken and unsuitable for password storage.",
        "remediation": "Use bcrypt, scrypt, or Argon2: bcrypt.hashpw(password, bcrypt.gensalt())",
        "cwe":  "CWE-327",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    {
        "rule_id":     "SEC-006",
        "severity":    "HIGH",
        "category":    "Weak Cryptography",
        "title":       "SHA1 used for sensitive operation",
        "pattern":     re.compile(r'hashlib\.sha1\s*\('),
        "description": "SHA-1 is deprecated for security-sensitive uses.",
        "remediation": "Use SHA-256 minimum, or bcrypt/Argon2 for passwords.",
        "cwe":  "CWE-327",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    {
        "rule_id":     "SEC-007",
        "severity":    "HIGH",
        "category":    "Sensitive Data Exposure",
        "title":       "Hardcoded secret / password",
        "pattern":     re.compile(r'(secret_key|password|token|api_key|passwd)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        "description": "Credentials embedded in source code are exposed in version control.",
        "remediation": "Load secrets from environment variables or a secrets manager.",
        "cwe":  "CWE-798",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    {
        "rule_id":     "SEC-008",
        "severity":    "HIGH",
        "category":    "XSS",
        "title":       "render_template_string with user input",
        "pattern":     re.compile(r'render_template_string\s*\([^)]*\{[^}]*\}'),
        "description": "render_template_string with formatted user data enables XSS and SSTI.",
        "remediation": "Use render_template with a static template file and pass context variables.",
        "cwe":  "CWE-79",
        "owasp": "A03:2021 – Injection",
    },
    {
        "rule_id":     "SEC-009",
        "severity":    "HIGH",
        "category":    "Debug / Information Disclosure",
        "title":       "Flask debug=True",
        "pattern":     re.compile(r'app\.run\s*\([^)]*debug\s*=\s*True'),
        "description": "Debug mode exposes a browser-accessible Python REPL — full RCE risk.",
        "remediation": "Set debug=False in production. Use FLASK_ENV=production.",
        "cwe":  "CWE-94",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    {
        "rule_id":     "SEC-010",
        "severity":    "MEDIUM",
        "category":    "Debug / Information Disclosure",
        "title":       "Flask bound to 0.0.0.0",
        "pattern":     re.compile(r'app\.run\s*\([^)]*host\s*=\s*["\']0\.0\.0\.0["\']'),
        "description": "Binding to all interfaces exposes the dev server publicly.",
        "remediation": "Bind to 127.0.0.1 and use a production WSGI server (gunicorn/uwsgi) behind a reverse proxy.",
        "cwe":  "CWE-200",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    {
        "rule_id":     "SEC-011",
        "severity":    "MEDIUM",
        "category":    "Path Traversal",
        "title":       "open() with user-controlled filename",
        "pattern":     re.compile(r'open\s*\(\s*f["\'][^"\']*\{'),
        "description": "User input in file paths allows directory traversal (../../etc/passwd).",
        "remediation": "Resolve and validate path is inside a trusted base directory using Path.resolve().",
        "cwe":  "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
    },
    {
        "rule_id":     "SEC-012",
        "severity":    "LOW",
        "category":    "Logging",
        "title":       "Potential sensitive data in log statement",
        "pattern":     re.compile(r'log(ger)?\.(debug|info|warning)\s*\(.*?(password|token|secret|key)', re.IGNORECASE),
        "description": "Logging credentials creates sensitive data exposure in log files.",
        "remediation": "Never log passwords, tokens, or secrets. Log only user IDs and event types.",
        "cwe":  "CWE-532",
        "owasp": "A09:2021 – Security Logging Failures",
    },
    {
        "rule_id":     "SEC-013",
        "severity":    "LOW",
        "category":    "Dependency",
        "title":       "Import of dangerous module",
        "pattern":     re.compile(r'^import\s+(pickle|marshal|shelve)\b', re.MULTILINE),
        "description": "These serialization modules are dangerous with untrusted data.",
        "remediation": "Prefer json module for data exchange. Use pickle only with trusted local data.",
        "cwe":  "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# AST-BASED RULES
# ─────────────────────────────────────────────────────────────────────────────

class ASTSecurityVisitor(ast.NodeVisitor):
    """Walk the AST to find patterns that regex can't reliably catch."""

    def __init__(self, lines: List[str]):
        self.lines = lines
        self.ast_findings: List[dict] = []

    def _add(self, node, rule_id, severity, category, title, description, remediation, cwe, owasp):
        self.ast_findings.append({
            "rule_id": rule_id, "severity": severity, "category": category,
            "title": title, "description": description,
            "line": node.lineno,
            "code": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
            "remediation": remediation, "cwe": cwe, "owasp": owasp,
        })

    def visit_Call(self, node):
        # Detect os.system()
        if (isinstance(node.func, ast.Attribute) and
                isinstance(node.func.value, ast.Name) and
                node.func.value.id == "os" and node.func.attr == "system"):
            self._add(node, "SEC-014", "CRITICAL", "Command Injection",
                      "os.system() with potentially unsanitized input",
                      "os.system() passes the command to the shell and is vulnerable to injection.",
                      "Use subprocess.run(['cmd', arg], shell=False) instead.",
                      "CWE-78", "A03:2021 – Injection")

        # Detect eval() / exec()
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self._add(node, "SEC-015", "CRITICAL", "Code Injection",
                      f"{node.func.id}() with dynamic input",
                      f"{node.func.id}() executes arbitrary Python code — extremely dangerous with user input.",
                      "Remove eval/exec. Use a safe parser or explicit logic instead.",
                      "CWE-95", "A03:2021 – Injection")

        self.generic_visit(node)


# ─────────────────────────────────────────────────────────────────────────────
# ANALYZER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class SecurityAnalyzer:
    def analyze_file(self, filepath: str) -> AnalysisResult:
        path = Path(filepath)
        result = AnalysisResult(file=filepath)

        try:
            source = path.read_text(encoding="utf-8")
        except Exception as e:
            print(f"  [ERROR] Cannot read {filepath}: {e}")
            return result

        lines = source.splitlines()
        result.lines_scanned = len(lines)

        # ── Regex scan ───────────────────────────────────────────────────────
        for rule in REGEX_RULES:
            for i, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    result.findings.append(Finding(
                        rule_id     = rule["rule_id"],
                        severity    = rule["severity"],
                        category    = rule["category"],
                        title       = rule["title"],
                        description = rule["description"],
                        file        = filepath,
                        line        = i,
                        code        = line.strip(),
                        remediation = rule["remediation"],
                        cwe         = rule["cwe"],
                        owasp       = rule["owasp"],
                    ))

        # ── AST scan ─────────────────────────────────────────────────────────
        try:
            tree = ast.parse(source)
            visitor = ASTSecurityVisitor(lines)
            visitor.visit(tree)
            for f in visitor.ast_findings:
                result.findings.append(Finding(
                    rule_id     = f["rule_id"],
                    severity    = f["severity"],
                    category    = f["category"],
                    title       = f["title"],
                    description = f["description"],
                    file        = filepath,
                    line        = f["line"],
                    code        = f["code"],
                    remediation = f["remediation"],
                    cwe         = f["cwe"],
                    owasp       = f["owasp"],
                ))
        except SyntaxError as e:
            print(f"  [WARN] AST parse error in {filepath}: {e}")

        # Sort by severity
        result.findings.sort(key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
        return result

    def analyze_directory(self, dirpath: str) -> List[AnalysisResult]:
        results = []
        for p in sorted(Path(dirpath).rglob("*.py")):
            results.append(self.analyze_file(str(p)))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# REPORTERS
# ─────────────────────────────────────────────────────────────────────────────

def print_terminal_report(results: List[AnalysisResult]):
    total = sum(len(r.findings) for r in results)
    total_critical = sum(len(r.critical) for r in results)
    total_high     = sum(len(r.high)     for r in results)
    total_medium   = sum(len(r.medium)   for r in results)
    total_low      = sum(len(r.low)      for r in results)

    print(f"\n{BOLD}{'─'*70}{RESET}")
    print(f"{BOLD}  SECURITY ANALYSIS REPORT{RESET}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*70}{RESET}")

    for result in results:
        if not result.findings:
            print(f"\n  {result.file}: {SEVERITY_COLOR['INFO']}✓ No issues found{RESET}")
            continue

        print(f"\n  {BOLD}File: {result.file}{RESET}  ({result.lines_scanned} lines, {len(result.findings)} findings)")
        print(f"  {'─'*60}")

        for f in result.findings:
            col = SEVERITY_COLOR.get(f.severity, "")
            print(f"\n  {col}{BOLD}[{f.severity}]{RESET} {f.rule_id} — {f.title}")
            print(f"  Line {f.line:>4}: {BOLD}{f.code[:80]}{RESET}")
            print(f"  Category : {f.category}  |  {f.cwe}  |  {f.owasp}")
            print(f"  Issue    : {f.description}")
            print(f"  Fix      : {f.remediation}")

    print(f"\n{'─'*70}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"  Files scanned : {len(results)}")
    print(f"  Total findings: {total}")
    print(f"  {SEVERITY_COLOR['CRITICAL']}CRITICAL: {total_critical}{RESET}  "
          f"{SEVERITY_COLOR['HIGH']}HIGH: {total_high}{RESET}  "
          f"{SEVERITY_COLOR['MEDIUM']}MEDIUM: {total_medium}{RESET}  "
          f"{SEVERITY_COLOR['LOW']}LOW: {total_low}{RESET}")
    print(f"{'─'*70}\n")


def save_json_report(results: List[AnalysisResult], outpath: str):
    data = {
        "generated_at": datetime.now().isoformat(),
        "files": [
            {
                "file": r.file,
                "lines_scanned": r.lines_scanned,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in results
        ],
        "summary": {
            "total_findings": sum(len(r.findings) for r in results),
            "critical": sum(len(r.critical) for r in results),
            "high":     sum(len(r.high)     for r in results),
            "medium":   sum(len(r.medium)   for r in results),
            "low":      sum(len(r.low)      for r in results),
        }
    }
    Path(outpath).write_text(json.dumps(data, indent=2))
    print(f"  JSON report saved → {outpath}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Static security analyzer for Python source files"
    )
    parser.add_argument("target", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--dir",  help="Directory to scan recursively")
    parser.add_argument("--json", help="Output JSON report to file")
    args = parser.parse_args()

    analyzer = SecurityAnalyzer()
    results: List[AnalysisResult] = []

    target = args.dir or args.target
    p = Path(target)

    if p.is_dir():
        print(f"\n  Scanning directory: {target}")
        results = analyzer.analyze_directory(target)
    elif p.is_file():
        print(f"\n  Scanning file: {target}")
        results = [analyzer.analyze_file(target)]
    else:
        print(f"  [ERROR] Target not found: {target}")
        sys.exit(1)

    print_terminal_report(results)

    if args.json:
        save_json_report(results, args.json)


if __name__ == "__main__":
    main()
