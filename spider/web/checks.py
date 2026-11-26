"""Passive, non-destructive checks on fetched pages. Each check has an id so verification can re-run it."""
import re
import secrets
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ..owasp import normalize_owasp


def finding(check_id, url, title, severity, owasp, cwe, description, fix, evidence="", confidence="high"):
    return {"kind": "web", "check_id": check_id, "file": url, "line": 1, "end_line": 1, "title": title,
            "severity": severity, "owasp": normalize_owasp(owasp), "cwe": cwe, "confidence": confidence,
            "description": description, "fix": fix, "fixed_code": "", "evidence": evidence}


HEADER_CHECKS = [
    ("content-security-policy", "Missing Content-Security-Policy", "medium", "A05", "CWE-693",
     "No Content-Security-Policy header. A CSP limits the damage of any XSS bug.",
     "Send a Content-Security-Policy that restricts script sources, e.g. default-src 'self'."),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low", "A05", "CWE-693",
     "Browsers may MIME-sniff responses.", "Send X-Content-Type-Options: nosniff."),
    ("referrer-policy", "Missing Referrer-Policy", "low", "A05", "CWE-200",
     "Full URLs may leak to other sites through the Referer header.", "Send Referrer-Policy: strict-origin-when-cross-origin."),
]


def check_headers(page):
    r, out = page.response, []
    if not page.is_html:
        return out
    for h, title, sev, owasp, cwe, desc, fix in HEADER_CHECKS:
        if not r.header(h):
            out.append(finding("hdr:" + h, page.url, title, sev, owasp, cwe, desc, fix, f"response had no {h} header"))
    csp = r.header("content-security-policy").lower()
    if not r.header("x-frame-options") and "frame-ancestors" not in csp:
        out.append(finding("hdr:framing", page.url, "No clickjacking protection", "medium", "A05", "CWE-1021",
                           "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed by other sites.",
                           "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'.", "no X-Frame-Options / frame-ancestors"))
    if page.url.startswith("https:") and not r.header("strict-transport-security"):
        out.append(finding("hdr:hsts", page.url, "Missing Strict-Transport-Security", "medium", "A05", "CWE-319",
                           "HTTPS site without HSTS; first visits can be downgraded.", "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                           "no HSTS header on https response"))
    for h in ("server", "x-powered-by", "x-aspnet-version"):
        v = r.header(h)
        if v and re.search(r"\d+\.\d+", v):
            out.append(finding("hdr:version:" + h, page.url, f"Version disclosed in {h} header", "low", "A05", "CWE-200",
                               "Exact software versions help attackers match known vulnerabilities.", f"Remove or genericize the {h} header.",
                               f"{h}: {v}"))
    return out


def check_cookies(page):
    out = []
    for c in page.response.set_cookies():
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = []
        if page.url.startswith("https:") and "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            sensitive = re.search(r"sess|auth|token|jwt|sid", name, re.I)
            out.append(finding(f"cookie:{name}", page.url, f"Cookie '{name}' lacks {', '.join(missing)}",
                               "medium" if sensitive else "low", "A05", "CWE-614" if "Secure" in missing else "CWE-1004",
                               "Cookie attributes limit theft and cross-site sending.",
                               "Set Secure, HttpOnly and SameSite=Lax (or Strict) on the cookie.", f"Set-Cookie: {name}=...; missing {', '.join(missing)}"))
    return out


TOKEN_NAMES = re.compile(r"csrf|xsrf|token|authenticity|nonce", re.I)


def check_forms(page):
    out = []
    for i, f in enumerate(page.forms):
        names = [x["name"] for x in f["inputs"]]
        has_pw = any(x["type"] == "password" for x in f["inputs"])
        if has_pw and f["method"] == "get":
            out.append(finding(f"form:getpw:{f['action']}", page.url, "Password submitted with GET", "high", "A02", "CWE-598",
                               "Credentials in the URL end up in logs and browser history.", "Use method=POST.", f"form action {f['action']}"))
        if has_pw and f["action"].startswith("http:") and urlsplit(f["action"]).hostname not in ("localhost", "127.0.0.1", "::1"):
            out.append(finding(f"form:httppw:{f['action']}", page.url, "Login form posts over plain HTTP", "high", "A02", "CWE-319",
                               "Credentials travel unencrypted.", "Serve the form and its action over HTTPS.", f"form action {f['action']}"))
        if f["method"] == "post" and not any(TOKEN_NAMES.search(n or "") for n in names):
            out.append(finding(f"form:csrf:{f['action']}", page.url, "State-changing form without an anti-CSRF token", "medium", "A01", "CWE-352",
                               "A POST form has no field that looks like a CSRF token (token may be sent as a header instead; verify).",
                               "Add a per-session CSRF token and validate it server side, plus SameSite cookies.",
                               f"form POST {f['action']} fields: {', '.join(n for n in names if n) or 'none'}", confidence="low"))
    return out


SECRET_WORDS = re.compile(r"password|passwd|secret|api[_-]?key|token|todo|fixme|debug|admin|credential", re.I)
ERROR_PATTERNS = [(r"Traceback \(most recent call last\)", "Python stack trace"), (r"at [\w.$]+\([\w.]+\.java:\d+\)", "Java stack trace"),
                  (r"Warning: .{0,60} in /[\w/.-]+\.php on line \d+", "PHP error with file path"), (r"You have an error in your SQL syntax", "SQL error message"),
                  (r"<b>Fatal error</b>:", "PHP fatal error"), (r"Server Error in '/' Application", "ASP.NET error page")]


def check_content(page):
    out = []
    if not page.is_html:
        return out
    for c in page.comments:
        if SECRET_WORDS.search(c) and len(c) < 300:
            out.append(finding("content:comment", page.url, "Sensitive-looking HTML comment", "low", "A05", "CWE-615",
                               "Comments ship to every visitor. This one mentions a sensitive word.", "Remove internal comments from production output.",
                               f"<!-- {c[:120]} -->", confidence="medium"))
            break
    for pat, label in ERROR_PATTERNS:
        if re.search(pat, page.response.body):
            out.append(finding("content:error:" + label, page.url, f"Verbose error output ({label})", "medium", "A05", "CWE-209",
                               "Error details reveal internals.", "Show a generic error page and log details server side.", label))
    if "Index of /" in page.response.body[:600] or "<title>Directory listing" in page.response.body[:600]:
        out.append(finding("content:dirlist", page.url, "Directory listing enabled", "medium", "A05", "CWE-548",
                           "The server lists directory contents.", "Disable autoindex / directory listing.", "page title looks like a directory index"))
    for s in page.mixed:
        out.append(finding("content:mixed:" + s, page.url, "Mixed content: script loaded over HTTP", "medium", "A02", "CWE-319",
                           "An HTTPS page loads a script over HTTP.", "Load all scripts over HTTPS.", s))
    return out


SENSITIVE_PATHS = [("/.git/HEAD", "ref:", "Exposed .git directory", "high", "CWE-527"),
                   ("/.env", "=", "Exposed .env file", "critical", "CWE-538"),
                   ("/server-status", "Apache Server Status", "Exposed Apache server-status", "medium", "CWE-200"),
                   ("/phpinfo.php", "phpinfo()", "Exposed phpinfo()", "medium", "CWE-200"),
                   ("/backup.zip", "PK", "Exposed backup archive", "high", "CWE-530")]


def probe_paths(client, base):
    """GET a short fixed list of well-known sensitive paths. Content is matched, never stored."""
    out = []
    p = urlsplit(base)
    root = f"{p.scheme}://{p.netloc}"
    for path, needle, title, sev, cwe in SENSITIVE_PATHS:
        try:
            r = client.get(root + path)
        except Exception:
            continue
        if r.status == 200 and needle in r.body[:2000] and "<html" not in r.body[:200].lower():
            out.append(finding("path:" + path, root + path, title, sev, "A05", cwe,
                               f"{path} is publicly readable.", f"Block access to {path} at the web server and remove the file from the web root.",
                               f"GET {path} returned 200 with expected content marker"))
    return out


def check_cors(client, page):
    try:
        r = client.get(page.url, headers={"Origin": "https://spider-probe.invalid"})
    except Exception:
        return []
    acao, acac = r.header("Access-Control-Allow-Origin"), r.header("Access-Control-Allow-Credentials").lower()
    if acao == "https://spider-probe.invalid" and acac == "true":
        return [finding("cors:reflect", page.url, "CORS reflects arbitrary Origin with credentials", "high", "A05", "CWE-942",
                        "Any website can read authenticated responses.", "Use a fixed allowlist of origins.", f"ACAO: {acao}, ACAC: true")]
    if acao == "*" and acac == "true":
        return [finding("cors:wild", page.url, "CORS wildcard with credentials", "medium", "A05", "CWE-942",
                        "Misconfigured CORS.", "Do not combine * with credentials.", "ACAO: *, ACAC: true")]
    return []


def check_reflection(client, page):
    """Send a harmless unique marker (with angle brackets) in each existing query parameter; report if echoed unescaped."""
    out = []
    p = urlsplit(page.url)
    params = parse_qsl(p.query, keep_blank_values=True)
    for i, (k, _) in enumerate(params[:5]):
        tag = "spd" + secrets.token_hex(3)
        probe = f"{tag}<{tag}>"
        new = [(kk, probe if j == i else vv) for j, (kk, vv) in enumerate(params)]
        url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(new, quote_via=quote), ""))
        try:
            r = client.get(url)
        except Exception:
            continue
        if f"<{tag}>" in r.body and "html" in r.header("Content-Type", "html").lower():
            out.append(finding(f"reflect:{k}", page.url, f"Parameter '{k}' is reflected without HTML encoding", "medium", "A03", "CWE-79",
                               "A harmless marker containing angle brackets came back unescaped, so output encoding is likely missing here (possible XSS).",
                               "Encode output for the HTML context (or use a templating engine that auto-escapes).",
                               f"marker with <> echoed raw via parameter {k}", confidence="medium"))
    return out


def run_all(client, pages, probe=True):
    out = []
    for page in pages:
        out += check_headers(page) + check_cookies(page) + check_forms(page) + check_content(page)
        if probe:
            out += check_reflection(client, page)
    if pages and probe:
        out += probe_paths(client, pages[0].url)
        out += check_cors(client, pages[0])
    # header and cookie findings repeat on every page: keep the first, note how many pages share it
    merged, seen = [], {}
    for f in out:
        key = f["check_id"] if f["check_id"].startswith(("hdr:", "cookie:", "content:comment")) else (f["check_id"], f["file"])
        if key in seen:
            seen[key][1] += 1
        else:
            seen[key] = [f, 0]
            merged.append(f)
    for f, extra in seen.values():
        if extra:
            f["description"] += f" (same issue on {extra} other page(s))"
    return merged
