"""
Static vulnerability analysis using Bandit (Python) and regex pattern matching
(JavaScript/TypeScript/PHP/other languages). No LLM, no network required.
"""

import os
import json
import re
import subprocess
import tempfile
import asyncio
from typing import AsyncGenerator

LANGUAGE_EXTENSIONS = {
    "javascript": ".js",
    "typescript": ".ts",
    "python": ".py",
    "java": ".java",
    "php": ".php",
    "ruby": ".rb",
    "go": ".go",
    "c": ".c",
    "cpp": ".cpp",
    "kotlin": ".kt",
    "rust": ".rs",
    "swift": ".swift",
    "scala": ".scala",
    "html": ".html",
}

BANDIT_SEVERITY_MAP = {
    "HIGH": "critical",
    "MEDIUM": "high",
    "LOW": "medium",
}

BANDIT_OWASP_MAP = {
    "B101": "A05:2021",  # assert
    "B102": "A03:2021",  # exec
    "B103": "A01:2021",  # chmod
    "B104": "A05:2021",  # bind all interfaces
    "B105": "A02:2021",  # hardcoded password
    "B106": "A02:2021",  # hardcoded password funcarg
    "B107": "A02:2021",  # hardcoded password default
    "B108": "A01:2021",  # temp file
    "B110": "A09:2021",  # try except pass
    "B112": "A09:2021",  # try except continue
    "B201": "A05:2021",  # flask debug
    "B202": "A05:2021",  # tarfile unsafe
    "B301": "A08:2021",  # pickle
    "B302": "A08:2021",  # marshal loads
    "B303": "A02:2021",  # md5/sha1
    "B304": "A02:2021",  # cipher DES
    "B305": "A02:2021",  # cipher ECB
    "B306": "A01:2021",  # mktemp
    "B307": "A03:2021",  # eval
    "B308": "A03:2021",  # mark_safe
    "B310": "A10:2021",  # urllib open
    "B311": "A02:2021",  # random
    "B312": "A10:2021",  # telnet
    "B313": "A05:2021",  # xml cetree
    "B314": "A05:2021",  # xml etree
    "B315": "A05:2021",  # xml expat
    "B316": "A05:2021",  # xml minidom
    "B317": "A05:2021",  # xml pulldom
    "B318": "A05:2021",  # xml dom
    "B319": "A05:2021",  # xml sax
    "B320": "A05:2021",  # xml xmlrpc
    "B321": "A02:2021",  # ftp
    "B322": "A03:2021",  # input
    "B323": "A02:2021",  # unverified context
    "B324": "A02:2021",  # md5/sha1 hashlib
    "B325": "A02:2021",  # tempnam
    "B401": "A02:2021",  # telnet
    "B402": "A01:2021",  # ftplib
    "B403": "A08:2021",  # pickle import
    "B404": "A03:2021",  # subprocess import
    "B405": "A05:2021",  # xml etree import
    "B406": "A05:2021",  # xml minidom import
    "B407": "A05:2021",  # xml expat import
    "B408": "A05:2021",  # xml dom import
    "B409": "A05:2021",  # xml sax import
    "B410": "A05:2021",  # xml lxml import
    "B411": "A03:2021",  # xmlrpc
    "B412": "A09:2021",  # httpoxy
    "B413": "A02:2021",  # pycrypto
    "B501": "A02:2021",  # ssl with bad version
    "B502": "A02:2021",  # ssl wrap socket
    "B503": "A02:2021",  # ssl no cert
    "B504": "A02:2021",  # ssl no cert wrap
    "B505": "A02:2021",  # weak key
    "B506": "A08:2021",  # yaml load
    "B507": "A02:2021",  # ssh no host key
    "B601": "A03:2021",  # paramiko exec command
    "B602": "A03:2021",  # subprocess popen shell true
    "B603": "A03:2021",  # subprocess without shell equals true
    "B604": "A03:2021",  # any other function with shell=true
    "B605": "A03:2021",  # os.system
    "B606": "A03:2021",  # os.startfile
    "B607": "A03:2021",  # start process partial path
    "B608": "A03:2021",  # hardcoded sql expressions
    "B609": "A03:2021",  # wildcard injection
    "B610": "A03:2021",  # django extra used
    "B611": "A03:2021",  # django rawsql
    "B701": "A03:2021",  # jinja2 autoescape false
    "B702": "A03:2021",  # use of mako templates
    "B703": "A03:2021",  # django mark safe
}

BANDIT_VULN_TYPE_MAP = {
    "B105": "HARDCODED_SECRET", "B106": "HARDCODED_SECRET", "B107": "HARDCODED_SECRET",
    "B303": "WEAK_CRYPTOGRAPHY", "B304": "WEAK_CRYPTOGRAPHY", "B305": "WEAK_CRYPTOGRAPHY",
    "B324": "WEAK_CRYPTOGRAPHY",
    "B301": "INSECURE_DESERIALIZATION", "B302": "INSECURE_DESERIALIZATION",
    "B403": "INSECURE_DESERIALIZATION", "B506": "INSECURE_DESERIALIZATION",
    "B307": "CODE_INJECTION", "B102": "CODE_INJECTION",
    "B605": "COMMAND_INJECTION", "B602": "COMMAND_INJECTION",
    "B603": "COMMAND_INJECTION", "B604": "COMMAND_INJECTION",
    "B601": "COMMAND_INJECTION",
    "B608": "SQL_INJECTION", "B610": "SQL_INJECTION", "B611": "SQL_INJECTION",
    "B310": "SSRF", "B312": "SSRF",
    "B313": "XXE", "B314": "XXE", "B315": "XXE", "B316": "XXE",
    "B317": "XXE", "B318": "XXE", "B319": "XXE",
    "B108": "PATH_TRAVERSAL", "B306": "PATH_TRAVERSAL",
    "B501": "WEAK_CRYPTOGRAPHY", "B502": "WEAK_CRYPTOGRAPHY",
    "B505": "WEAK_CRYPTOGRAPHY",
    "B701": "XSS", "B702": "XSS", "B703": "XSS", "B308": "XSS",
    "B201": "SECURITY_VULNERABILITY",
    "B311": "WEAK_CRYPTOGRAPHY",
}

BANDIT_CWE_MAP = {
    "SQL_INJECTION": "CWE-89",
    "XSS": "CWE-79",
    "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL": "CWE-22",
    "SSRF": "CWE-918",
    "XXE": "CWE-611",
    "CSRF": "CWE-352",
    "INSECURE_DESERIALIZATION": "CWE-502",
    "HARDCODED_SECRET": "CWE-798",
    "WEAK_CRYPTOGRAPHY": "CWE-327",
    "OPEN_REDIRECT": "CWE-601",
    "CODE_INJECTION": "CWE-94",
    "SECURITY_VULNERABILITY": "CWE-693",
}

# ─── Regex-based patterns for non-Python languages ─────────────────────────

JS_PATTERNS = [
    {
        "id": "sql-injection-js",
        "regex": r'(?:query|execute)\s*\(\s*["\`][^"]*["\`]\s*\+|(?:query|execute)\s*\(\s*`[^`]*\$\{',
        "type": "SQL_INJECTION",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "severity": "critical",
        "title": "SQL Injection",
        "description": "User input concatenated into SQL query. Use parameterized queries instead.",
    },
    {
        "id": "xss-innerhtml",
        "regex": r'\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(',
        "type": "XSS",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "severity": "high",
        "title": "Cross-Site Scripting (XSS)",
        "description": "Assigning to innerHTML/outerHTML or document.write() with user data enables XSS. Use textContent or DOMPurify.",
    },
    {
        "id": "eval-injection-js",
        "regex": r'\beval\s*\(|\bnew\s+Function\s*\(',
        "type": "CODE_INJECTION",
        "owasp": "A03:2021",
        "cwe": "CWE-94",
        "severity": "critical",
        "title": "Code Injection via eval()",
        "description": "eval() or new Function() with user input allows arbitrary JavaScript execution.",
    },
    {
        "id": "command-injection-js",
        "regex": r'(?:exec|execSync|spawn|spawnSync)\s*\(\s*["\`][^"]*["\`]\s*\+|child_process\.exec\s*\(`[^`]*\$\{',
        "type": "COMMAND_INJECTION",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "severity": "critical",
        "title": "Command Injection",
        "description": "User input passed to exec/spawn. Use execFile() with an argument array.",
    },
    {
        "id": "hardcoded-secret-js",
        "regex": r'(?:secret|password|passwd|api_key|apikey|token|auth)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "type": "HARDCODED_SECRET",
        "owasp": "A02:2021",
        "cwe": "CWE-798",
        "severity": "high",
        "title": "Hardcoded Secret",
        "description": "Hardcoded credential or secret found. Use environment variables instead.",
    },
    {
        "id": "md5-js",
        "regex": r'createHash\s*\(\s*["\']md5["\']|createHash\s*\(\s*["\']sha1["\']',
        "type": "WEAK_CRYPTOGRAPHY",
        "owasp": "A02:2021",
        "cwe": "CWE-327",
        "severity": "high",
        "title": "Weak Hash Algorithm",
        "description": "MD5/SHA-1 are cryptographically broken. Use SHA-256 or bcrypt for passwords.",
    },
    {
        "id": "prototype-pollution",
        "regex": r'\[__proto__\]|\.__proto__\s*=|constructor\[prototype\]',
        "type": "PROTOTYPE_POLLUTION",
        "owasp": "A03:2021",
        "cwe": "CWE-1321",
        "severity": "high",
        "title": "Prototype Pollution",
        "description": "Potential prototype pollution via __proto__ or constructor.prototype access.",
    },
    {
        "id": "open-redirect-js",
        "regex": r'(?:window\.location|location\.href|res\.redirect)\s*[=\(]\s*req\.',
        "type": "OPEN_REDIRECT",
        "owasp": "A01:2021",
        "cwe": "CWE-601",
        "severity": "high",
        "title": "Open Redirect",
        "description": "User-controlled URL used for redirect. Validate against an allowlist.",
    },
    {
        "id": "cors-wildcard",
        "regex": r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]?\*",
        "type": "CORS_MISCONFIGURATION",
        "owasp": "A05:2021",
        "cwe": "CWE-942",
        "severity": "medium",
        "title": "CORS Wildcard (*)",
        "description": "Wildcard CORS policy may allow unauthorized cross-origin requests. Restrict to specific domains.",
    },
]

PHP_PATTERNS = [
    {
        "id": "php-sql-injection",
        "regex": r'mysql_query\s*\(\s*["\'][^"\']*["\']\s*\.\s*\$|mysqli_query\s*\([^,]+,\s*["\'][^"\']*["\']\s*\.\s*\$',
        "type": "SQL_INJECTION",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "severity": "critical",
        "title": "SQL Injection",
        "description": "User input concatenated into SQL query. Use PDO prepared statements.",
    },
    {
        "id": "php-command-injection",
        "regex": r'(?:system|exec|shell_exec|passthru|popen)\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        "type": "COMMAND_INJECTION",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "severity": "critical",
        "title": "Command Injection",
        "description": "User input from $_GET/$_POST passed to system()/exec(). Validate input with escapeshellarg().",
    },
    {
        "id": "php-xss",
        "regex": r'echo\s+\$(?:_GET|_POST|_REQUEST)|print\s+\$(?:_GET|_POST|_REQUEST)',
        "type": "XSS",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "severity": "high",
        "title": "Reflected XSS",
        "description": "User input echoed without encoding. Use htmlspecialchars() before outputting.",
    },
    {
        "id": "php-file-inclusion",
        "regex": r'(?:include|require|include_once|require_once)\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        "type": "PATH_TRAVERSAL",
        "owasp": "A01:2021",
        "cwe": "CWE-22",
        "severity": "critical",
        "title": "Remote/Local File Inclusion",
        "description": "User input used in include/require. Validate and restrict to allowed files.",
    },
    {
        "id": "php-eval",
        "regex": r'eval\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
        "type": "CODE_INJECTION",
        "owasp": "A03:2021",
        "cwe": "CWE-94",
        "severity": "critical",
        "title": "PHP Code Injection",
        "description": "eval() with user input allows arbitrary PHP code execution.",
    },
]


def _run_bandit(code: str) -> list[dict]:
    """Run Bandit on Python code and return vulnerability list."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        temp_path = f.name

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", temp_path],
            capture_output=True,
            text=True,
            timeout=15,
        )

        raw = result.stdout.strip()
        if not raw:
            return []

        data = json.loads(raw)
        findings = data.get("results", [])
        lines = code.splitlines()

        vulnerabilities = []
        for i, f in enumerate(findings):
            test_id = f.get("test_id", "")
            severity_raw = f.get("issue_severity", "LOW")
            line_no = f.get("line_number", 1)
            message = f.get("issue_text", "")
            code_snippet = f.get("code", "").strip()
            test_name = f.get("test_name", "").replace("_", " ").title()

            vuln_type = BANDIT_VULN_TYPE_MAP.get(test_id, "SECURITY_VULNERABILITY")
            severity = BANDIT_SEVERITY_MAP.get(severity_raw, "medium")
            owasp = BANDIT_OWASP_MAP.get(test_id, "A05:2021")
            cwe = BANDIT_CWE_MAP.get(vuln_type, "CWE-693")

            # Try to get actual lines from source
            actual_snippet = code_snippet
            if not actual_snippet and line_no <= len(lines):
                actual_snippet = lines[line_no - 1].strip()

            vulnerabilities.append({
                "id": f"vuln_{i + 1}",
                "type": vuln_type,
                "owasp_category": owasp,
                "cwe_id": cwe,
                "severity": severity,
                "title": test_name or vuln_type.replace("_", " ").title(),
                "description": message,
                "affected_lines": [line_no],
                "code_snippet": actual_snippet,
            })

        return vulnerabilities

    except subprocess.TimeoutExpired:
        return []
    except json.JSONDecodeError:
        return []
    finally:
        os.unlink(temp_path)


def _run_regex_patterns(code: str, patterns: list[dict]) -> list[dict]:
    """Scan code with regex patterns and return vulnerability list."""
    lines = code.splitlines()
    vulnerabilities = []
    seen = set()

    for pat in patterns:
        regex = re.compile(pat["regex"], re.IGNORECASE | re.MULTILINE)
        for match in regex.finditer(code):
            # Find line number
            line_no = code[:match.start()].count("\n") + 1
            key = (pat["id"], line_no)
            if key in seen:
                continue
            seen.add(key)

            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else match.group(0)

            vulnerabilities.append({
                "id": f"vuln_{len(vulnerabilities) + 1}",
                "type": pat["type"],
                "owasp_category": pat["owasp"],
                "cwe_id": pat["cwe"],
                "severity": pat["severity"],
                "title": pat["title"],
                "description": pat["description"],
                "affected_lines": [line_no],
                "code_snippet": snippet,
            })

    return vulnerabilities


def _analyze(code: str, language: str) -> list[dict]:
    """Run appropriate analysis based on language."""
    lang = language.lower()

    if lang == "python":
        results = _run_bandit(code)
    elif lang in ("javascript", "typescript"):
        results = _run_regex_patterns(code, JS_PATTERNS)
    elif lang == "php":
        results = _run_regex_patterns(code, PHP_PATTERNS)
    else:
        # Generic regex scan with a combined set
        results = _run_regex_patterns(code, JS_PATTERNS + PHP_PATTERNS)

    # Re-number IDs sequentially
    for i, v in enumerate(results):
        v["id"] = f"vuln_{i + 1}"

    return results


async def stream_vulnerability_analysis(code: str, language: str) -> AsyncGenerator[str, None]:
    """Stream vulnerability analysis results (no LLM, no network)."""
    loop = asyncio.get_event_loop()

    yield f"data: {json.dumps({'type': 'chunk', 'text': f'Analyzing {language} code for security vulnerabilities...'})}\n\n"

    try:
        vulnerabilities = await loop.run_in_executor(None, _analyze, code, language)
        yield f"data: {json.dumps({'type': 'complete', 'vulnerabilities': vulnerabilities})}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    yield "data: [DONE]\n\n"
