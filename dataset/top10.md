# OWASP Top 10

OWASP publishes the Top 10 every few years, not every year. The recent lists are 2017, 2021 and 2025. There is no 2022, 2023 or 2024 list. CWE lists are the notable or typical ones, not the full mapping. Examples are minimal Python snippets for illustration.

SPIDER's own labels in `dataset/*.jsonl` use the **2021** categories (`owasp` field, e.g. `A03:2021 - Injection`).

## OWASP Top 10:2025

Status: Official final release. owasp.org/Top10/2025 and the OWASP/Top10 GitHub README list it as released (Final) and mark 2021 as superseded. It went through alpha and release-candidate stages first.
Source: https://owasp.org/Top10/2025/

### A01:2025 Broken Access Control

Still #1. Users act outside their permissions. SSRF was folded into this category in 2025.

Typical CWEs: CWE-200, CWE-201, CWE-352, CWE-918

Vulnerable:
```python
@app.get('/invoice/<int:id>')
def invoice(id):
    return db.invoice(id)
```
Fixed:
```python
@app.get('/invoice/<int:id>')
def invoice(id):
    inv = db.invoice(id)
    if inv.owner_id != current_user.id:
        abort(403)
    return inv
```

### A02:2025 Security Misconfiguration

Up from #5. Systems, apps or cloud services set up insecurely: debug on, default credentials, open storage, risky XML parser settings.

Typical CWEs: CWE-16, CWE-611

Vulnerable:
```python
app.config['DEBUG'] = True
ADMIN_PASSWORD = 'admin'
```
Fixed:
```python
app.config['DEBUG'] = False
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
```

### A03:2025 Software Supply Chain Failures

New name and wider scope than 2021's Vulnerable and Outdated Components: compromised or vulnerable dependencies, build systems and distribution.

Typical CWEs: CWE-477, CWE-1104, CWE-1329, CWE-1395

Vulnerable:
```python
# requirements.txt
log4j-core==2.14.1
```
Fixed:
```python
# requirements: pin a patched version and scan dependencies in CI
log4j-core==2.17.1
```

### A04:2025 Cryptographic Failures

Down from #2. Missing or weak encryption, bad key handling, weak randomness.

Typical CWEs: CWE-327, CWE-331, CWE-338, CWE-1241

Vulnerable:
```python
import hashlib
h = hashlib.md5(password.encode()).hexdigest()
```
Fixed:
```python
import bcrypt
h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### A05:2025 Injection

Down from #3. Untrusted input reaches an interpreter, from cross-site scripting to SQL injection.

Typical CWEs: CWE-79, CWE-89, CWE-78, CWE-94

Vulnerable:
```python
cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
```
Fixed:
```python
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
```

### A06:2025 Insecure Design

Down from #4. Design and architecture flaws, including business logic, missing threat modeling and secure design patterns.

Typical CWEs: CWE-256, CWE-269, CWE-434, CWE-501, CWE-522

Vulnerable:
```python
def reset_password(email):
    # security question is the only check, unlimited tries
    if answer == user.answer:
        set_password(user)
```
Fixed:
```python
def reset_password(email, token):
    # single-use emailed token, rate limited, expires in 15 min
    if rate_limit_ok(email) and verify_token(email, token):
        set_password(user)
```

### A07:2025 Authentication Failures

Renamed from Identification and Authentication Failures. Weak login, credential or session handling.

Typical CWEs: CWE-259, CWE-287, CWE-297, CWE-384, CWE-798

Vulnerable:
```python
if user and user.password == request.form['password']:
    login(user)
```
Fixed:
```python
if user and bcrypt.checkpw(request.form['password'].encode(), user.pw_hash):
    session.clear()
    login(user)
```

### A08:2025 Software or Data Integrity Failures

Renamed (and to 'or'). Missing integrity checks on code, updates and data, at a lower level than supply chain failures.

Typical CWEs: CWE-345, CWE-502, CWE-829, CWE-915

Vulnerable:
```python
import pickle
obj = pickle.loads(request.data)
```
Fixed:
```python
import json
obj = json.loads(request.data)  # data only, never executable objects
```

### A09:2025 Security Logging & Alerting Failures

Renamed from Logging and Monitoring. Logging without alerting is of little use for catching incidents.

Typical CWEs: CWE-117, CWE-221, CWE-223, CWE-532, CWE-778

Vulnerable:
```python
def login(u, p):
    if not check(u, p):
        return False
```
Fixed:
```python
def login(u, p):
    if not check(u, p):
        log.warning('failed login user=%s ip=%s', u, ip)  # alert on bursts
        return False
```

### A10:2025 Mishandling of Exceptional Conditions

New in 2025. Poor error handling, logical errors and failing open when something unusual happens.

Typical CWEs: CWE-209, CWE-234, CWE-274, CWE-476, CWE-636

Vulnerable:
```python
try:
    ok = verify_token(t)
except Exception:
    ok = True  # fails open
```
Fixed:
```python
try:
    ok = verify_token(t)
except Exception:
    log.exception('token check failed')
    ok = False  # fail closed
```

## OWASP Top 10:2021

Status: Official release, now marked superseded by the 2025 list on the OWASP project page
Source: https://owasp.org/Top10/2021/

### A01:2021 Broken Access Control

Users can act outside their intended permissions: reading other users' data, changing records, or reaching admin functions.

Typical CWEs: CWE-22, CWE-200, CWE-284, CWE-352, CWE-639, CWE-862, CWE-863

Vulnerable:
```python
@app.get('/invoice/<int:id>')
def invoice(id):
    return db.invoice(id)
```
Fixed:
```python
@app.get('/invoice/<int:id>')
def invoice(id):
    inv = db.invoice(id)
    if inv.owner_id != current_user.id:
        abort(403)
    return inv
```

### A02:2021 Cryptographic Failures

Sensitive data is not protected in transit or at rest, or weak or misused cryptography is used.

Typical CWEs: CWE-259, CWE-311, CWE-319, CWE-327, CWE-328, CWE-330, CWE-331

Vulnerable:
```python
import hashlib
h = hashlib.md5(password.encode()).hexdigest()
```
Fixed:
```python
import bcrypt
h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### A03:2021 Injection

Untrusted input is sent to an interpreter (SQL, OS shell, LDAP, browser) and runs as commands. Includes cross-site scripting.

Typical CWEs: CWE-20, CWE-77, CWE-78, CWE-79, CWE-89, CWE-94, CWE-917

Vulnerable:
```python
cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
```
Fixed:
```python
cur.execute("SELECT * FROM users WHERE name = %s", (name,))
```

### A04:2021 Insecure Design

Missing or weak security controls in the design itself, such as no threat modeling or unsafe business flows. Not fixable by perfect code alone.

Typical CWEs: CWE-209, CWE-256, CWE-501, CWE-522, CWE-602, CWE-840

Vulnerable:
```python
def reset_password(email):
    # security question is the only check, unlimited tries
    if answer == user.answer:
        set_password(user)
```
Fixed:
```python
def reset_password(email, token):
    # single-use emailed token, rate limited, expires in 15 min
    if rate_limit_ok(email) and verify_token(email, token):
        set_password(user)
```

### A05:2021 Security Misconfiguration

Insecure defaults, unneeded features, verbose errors, missing hardening, or misconfigured cloud services.

Typical CWEs: CWE-2, CWE-16, CWE-611, CWE-1004

Vulnerable:
```python
app.config['DEBUG'] = True
ADMIN_PASSWORD = 'admin'
```
Fixed:
```python
app.config['DEBUG'] = False
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
```

### A06:2021 Vulnerable and Outdated Components

Using libraries, frameworks or other components with known vulnerabilities or that are no longer supported.

Typical CWEs: CWE-937, CWE-1035, CWE-1104

Vulnerable:
```python
# requirements.txt
log4j-core==2.14.1
```
Fixed:
```python
# requirements: pin a patched version and scan dependencies in CI
log4j-core==2.17.1
```

### A07:2021 Identification and Authentication Failures

Weak login, credential, or session handling lets attackers assume other users' identities.

Typical CWEs: CWE-255, CWE-287, CWE-297, CWE-307, CWE-384, CWE-798

Vulnerable:
```python
if user and user.password == request.form['password']:
    login(user)
```
Fixed:
```python
if user and bcrypt.checkpw(request.form['password'].encode(), user.pw_hash):
    session.clear()
    login(user)
```

### A08:2021 Software and Data Integrity Failures

Code and data are trusted without integrity checks: unsafe deserialization, unsigned updates, insecure CI/CD pipelines.

Typical CWEs: CWE-345, CWE-353, CWE-426, CWE-494, CWE-502, CWE-829, CWE-915

Vulnerable:
```python
import pickle
obj = pickle.loads(request.data)
```
Fixed:
```python
import json
obj = json.loads(request.data)  # data only, never executable objects
```

### A09:2021 Security Logging and Monitoring Failures

Security events are not logged, monitored or alerted on, so attacks go unnoticed.

Typical CWEs: CWE-117, CWE-223, CWE-532, CWE-778

Vulnerable:
```python
def login(u, p):
    if not check(u, p):
        return False
```
Fixed:
```python
def login(u, p):
    if not check(u, p):
        log.warning('failed login user=%s ip=%s', u, ip)  # alert on bursts
        return False
```

### A10:2021 Server-Side Request Forgery (SSRF)

The server fetches a URL supplied by the user, letting attackers reach internal services or cloud metadata.

Typical CWEs: CWE-918

Vulnerable:
```python
url = request.args['url']
return requests.get(url).text
```
Fixed:
```python
host = urlparse(url).hostname
if host not in ALLOWED_HOSTS:
    abort(400)
return requests.get(url, timeout=5).text
```
