"""Regenerates dataset/samples.jsonl (original samples written for this project). Run: python dataset/build_originals.py"""
import json
import os

NAMES = {"A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection", "A04": "Insecure Design",
         "A05": "Security Misconfiguration", "A06": "Vulnerable and Outdated Components",
         "A07": "Identification and Authentication Failures", "A08": "Software and Data Integrity Failures",
         "A09": "Security Logging and Monitoring Failures", "A10": "Server-Side Request Forgery"}

# (owasp, cwe, description, {language: (vulnerable, fixed)})
T = [
("A01", "CWE-639", "IDOR: object fetched by id without an ownership check", {
 "python": ("@app.route('/invoice/<int:i>')\ndef invoice(i):\n    return db.get_invoice(i)",
            "@app.route('/invoice/<int:i>')\n@login_required\ndef invoice(i):\n    inv = db.get_invoice(i)\n    if inv.owner_id != current_user.id:\n        abort(403)\n    return inv"),
 "javascript": ("app.get('/orders/:id', async (req, res) => {\n  res.json(await Order.findById(req.params.id));\n});",
                "app.get('/orders/:id', auth, async (req, res) => {\n  const o = await Order.findById(req.params.id);\n  if (!o || String(o.userId) !== req.user.id) return res.sendStatus(403);\n  res.json(o);\n});"),
 "java": ("@GetMapping(\"/accounts/{id}\")\npublic Account get(@PathVariable long id) {\n    return repo.findById(id).orElseThrow();\n}",
          "@GetMapping(\"/accounts/{id}\")\npublic Account get(@PathVariable long id, Principal p) {\n    Account a = repo.findById(id).orElseThrow();\n    if (!a.getOwner().equals(p.getName())) throw new AccessDeniedException(\"forbidden\");\n    return a;\n}"),
 "php": ("$r = $db->query(\"SELECT * FROM docs WHERE id = \" . (int)$_GET['id']);\necho json_encode($r->fetch());",
         "$st = $db->prepare('SELECT * FROM docs WHERE id = ? AND owner_id = ?');\n$st->execute([(int)$_GET['id'], $_SESSION['uid']]);\necho json_encode($st->fetch());")}),
("A01", "CWE-22", "Path traversal in file access", {
 "python": ("def download(name):\n    return open('/srv/files/' + name, 'rb').read()",
            "import os\ndef download(name):\n    base = os.path.realpath('/srv/files')\n    path = os.path.realpath(os.path.join(base, name))\n    if not path.startswith(base + os.sep):\n        raise PermissionError(name)\n    return open(path, 'rb').read()"),
 "javascript": ("app.get('/f', (req, res) => res.sendFile('/srv/files/' + req.query.name));",
                "const path = require('path');\napp.get('/f', (req, res) => {\n  const p = path.resolve('/srv/files', req.query.name);\n  if (!p.startsWith('/srv/files' + path.sep)) return res.sendStatus(400);\n  res.sendFile(p);\n});"),
 "java": ("File f = new File(\"/srv/files/\" + name);\nreturn Files.readAllBytes(f.toPath());",
          "Path base = Paths.get(\"/srv/files\").toRealPath();\nPath p = base.resolve(name).normalize();\nif (!p.startsWith(base)) throw new SecurityException(name);\nreturn Files.readAllBytes(p);"),
 "go": ("func dl(w http.ResponseWriter, r *http.Request) {\n\thttp.ServeFile(w, r, \"/srv/files/\"+r.URL.Query().Get(\"n\"))\n}",
        "func dl(w http.ResponseWriter, r *http.Request) {\n\tn := filepath.Base(r.URL.Query().Get(\"n\"))\n\thttp.ServeFile(w, r, filepath.Join(\"/srv/files\", n))\n}")}),
("A01", "CWE-862", "Admin action without an authorization check", {
 "python": ("@app.route('/admin/delete/<int:uid>', methods=['POST'])\ndef delete_user(uid):\n    db.delete_user(uid)\n    return 'ok'",
            "@app.route('/admin/delete/<int:uid>', methods=['POST'])\n@login_required\ndef delete_user(uid):\n    if not current_user.is_admin:\n        abort(403)\n    db.delete_user(uid)\n    return 'ok'"),
 "javascript": ("router.delete('/users/:id', async (req, res) => {\n  await User.deleteOne({ _id: req.params.id });\n  res.sendStatus(204);\n});",
                "router.delete('/users/:id', auth, requireRole('admin'), async (req, res) => {\n  await User.deleteOne({ _id: req.params.id });\n  res.sendStatus(204);\n});")}),
("A01", "CWE-601", "Open redirect from a user-controlled URL", {
 "python": ("@app.route('/go')\ndef go():\n    return redirect(request.args['next'])",
            "from urllib.parse import urlparse\n@app.route('/go')\ndef go():\n    nxt = request.args.get('next', '/')\n    if urlparse(nxt).netloc:\n        nxt = '/'\n    return redirect(nxt)"),
 "javascript": ("app.get('/go', (req, res) => res.redirect(req.query.next));",
                "app.get('/go', (req, res) => {\n  const n = String(req.query.next || '/');\n  res.redirect(n.startsWith('/') && !n.startsWith('//') ? n : '/');\n});")}),
("A01", "CWE-352", "State-changing request without CSRF protection", {
 "python": ("@app.route('/transfer', methods=['POST'])\ndef transfer():\n    do_transfer(session['uid'], request.form['to'], request.form['amt'])",
            "@app.route('/transfer', methods=['POST'])\n@csrf.protect\ndef transfer():\n    do_transfer(session['uid'], request.form['to'], request.form['amt'])"),
 "javascript": ("app.post('/settings', (req, res) => updateSettings(req.session.uid, req.body));",
                "app.use(csurf());\napp.post('/settings', (req, res) => updateSettings(req.session.uid, req.body));")}),
("A02", "CWE-327", "Weak hash used for passwords", {
 "python": ("import hashlib\ndef hash_pw(pw):\n    return hashlib.md5(pw.encode()).hexdigest()",
            "import bcrypt\ndef hash_pw(pw):\n    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())"),
 "javascript": ("const crypto = require('crypto');\nconst hash = pw => crypto.createHash('sha1').update(pw).digest('hex');",
                "const bcrypt = require('bcrypt');\nconst hash = pw => bcrypt.hash(pw, 12);"),
 "java": ("MessageDigest md = MessageDigest.getInstance(\"MD5\");\nbyte[] h = md.digest(pw.getBytes(UTF_8));",
          "SecretKeyFactory f = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");\nbyte[] h = f.generateSecret(new PBEKeySpec(pw.toCharArray(), salt, 310000, 256)).getEncoded();"),
 "php": ("$h = md5($password);", "$h = password_hash($password, PASSWORD_ARGON2ID);")}),
("A02", "CWE-798", "Hard-coded secret in source", {
 "python": ("API_KEY = 'sk-live-1234567890abcdef'", "import os\nAPI_KEY = os.environ['API_KEY']"),
 "javascript": ("const stripe = require('stripe')('sk_live_51Habcdef123456');", "const stripe = require('stripe')(process.env.STRIPE_KEY);"),
 "java": ("private static final String DB_PASS = \"P@ssw0rd!\";", "private static final String DB_PASS = System.getenv(\"DB_PASS\");"),
 "go": ("const token = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"", "var token = os.Getenv(\"GITHUB_TOKEN\")")}),
("A02", "CWE-295", "TLS certificate verification disabled", {
 "python": ("r = requests.get(url, verify=False)", "r = requests.get(url, timeout=10)"),
 "javascript": ("const agent = new https.Agent({ rejectUnauthorized: false });", "const agent = new https.Agent({ rejectUnauthorized: true });"),
 "go": ("tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}", "tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}")}),
("A02", "CWE-338", "Non-cryptographic random for security tokens", {
 "python": ("import random\ntoken = str(random.randint(0, 10**6))", "import secrets\ntoken = secrets.token_urlsafe(32)"),
 "javascript": ("const token = Math.random().toString(36).slice(2);", "const token = require('crypto').randomBytes(32).toString('hex');"),
 "java": ("String t = Long.toString(new Random().nextLong());", "byte[] b = new byte[32];\nnew SecureRandom().nextBytes(b);\nString t = Base64.getUrlEncoder().encodeToString(b);")}),
("A02", "CWE-327", "ECB mode / DES encryption", {
 "python": ("cipher = AES.new(key, AES.MODE_ECB)", "cipher = AES.new(key, AES.MODE_GCM)"),
 "java": ("Cipher c = Cipher.getInstance(\"DES/ECB/PKCS5Padding\");", "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");")}),
("A03", "CWE-89", "SQL injection via string building", {
 "python": ("cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")", "cur.execute('SELECT * FROM users WHERE name = ?', (name,))"),
 "javascript": ("db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);", "db.query('SELECT * FROM users WHERE email = ?', [req.body.email]);"),
 "java": ("Statement s = c.createStatement();\nResultSet r = s.executeQuery(\"SELECT * FROM t WHERE id=\" + id);",
          "PreparedStatement s = c.prepareStatement(\"SELECT * FROM t WHERE id=?\");\ns.setString(1, id);\nResultSet r = s.executeQuery();"),
 "php": ("$r = mysqli_query($c, \"SELECT * FROM u WHERE n='\" . $_GET['n'] . \"'\");",
         "$st = $c->prepare('SELECT * FROM u WHERE n = ?');\n$st->bind_param('s', $_GET['n']);\n$st->execute();"),
 "go": ("rows, _ := db.Query(\"SELECT * FROM u WHERE n='\" + n + \"'\")", "rows, _ := db.Query(\"SELECT * FROM u WHERE n=$1\", n)")}),
("A03", "CWE-78", "OS command injection", {
 "python": ("subprocess.run('ping -c 1 ' + host, shell=True)", "subprocess.run(['ping', '-c', '1', host], check=True)"),
 "javascript": ("exec('convert ' + req.query.file + ' out.png');", "execFile('convert', [req.query.file, 'out.png']);"),
 "java": ("Runtime.getRuntime().exec(\"nslookup \" + host);", "new ProcessBuilder(\"nslookup\", host).start();"),
 "php": ("system('ls ' . $_GET['dir']);", "system('ls ' . escapeshellarg($_GET['dir']));")}),
("A03", "CWE-79", "Cross-site scripting (reflected / DOM)", {
 "javascript": ("el.innerHTML = location.hash.slice(1);", "el.textContent = location.hash.slice(1);"),
 "python": ("return '<h1>Hello ' + request.args['name'] + '</h1>'", "from markupsafe import escape\nreturn '<h1>Hello ' + str(escape(request.args['name'])) + '</h1>'"),
 "php": ("echo '<p>' . $_GET['q'] . '</p>';", "echo '<p>' . htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') . '</p>';"),
 "java": ("out.println(\"<p>\" + request.getParameter(\"q\") + \"</p>\");", "out.println(\"<p>\" + Encode.forHtml(request.getParameter(\"q\")) + \"</p>\");")}),
("A03", "CWE-90", "LDAP injection", {
 "python": ("conn.search('dc=ex,dc=com', '(uid=' + user + ')')", "from ldap3.utils.conv import escape_filter_chars\nconn.search('dc=ex,dc=com', '(uid=' + escape_filter_chars(user) + ')')")}),
("A03", "CWE-94", "Code injection through eval", {
 "python": ("result = eval(request.args['expr'])", "import ast\nresult = ast.literal_eval(request.args['expr'])"),
 "javascript": ("const v = eval(req.query.expr);", "const v = JSON.parse(req.query.expr);"),
 "php": ("eval('$x = ' . $_GET['v'] . ';');", "$x = filter_var($_GET['v'], FILTER_VALIDATE_INT);")}),
("A03", "CWE-943", "NoSQL injection through unvalidated object", {
 "javascript": ("User.findOne({ name: req.body.name, pass: req.body.pass });", "User.findOne({ name: String(req.body.name), pass: String(req.body.pass) });")}),
("A03", "CWE-611", "XML external entity processing enabled", {
 "python": ("from lxml import etree\ntree = etree.fromstring(data)", "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ntree = etree.fromstring(data, parser)"),
 "java": ("DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nDocument d = f.newDocumentBuilder().parse(in);",
          "DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\nDocument d = f.newDocumentBuilder().parse(in);")}),
("A04", "CWE-307", "No rate limiting or lockout on login", {
 "python": ("def login(u, p):\n    return check(u, p)", "def login(u, p):\n    if attempts.get(u, 0) >= 5:\n        raise Locked(u)\n    ok = check(u, p)\n    attempts[u] = 0 if ok else attempts.get(u, 0) + 1\n    return ok"),
 "javascript": ("app.post('/login', login);", "app.post('/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }), login);")}),
("A04", "CWE-840", "Business logic: client-supplied price trusted", {
 "python": ("total = int(request.form['price']) * qty", "total = db.get_product(pid).price * qty"),
 "javascript": ("const total = req.body.price * req.body.qty;", "const p = await Product.findById(req.body.id);\nconst total = p.price * Math.max(1, Math.floor(req.body.qty));")}),
("A04", "CWE-770", "No limit on upload size or request count", {
 "python": ("data = request.get_data()", "app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024\ndata = request.get_data()"),
 "javascript": ("app.use(express.json());", "app.use(express.json({ limit: '100kb' }));")}),
("A04", "CWE-640", "Password reset token that is guessable and never expires", {
 "python": ("token = str(user.id)\nsend_mail(user.email, '/reset/' + token)", "token = secrets.token_urlsafe(32)\nstore_reset(user.id, hash(token), expires=now() + timedelta(minutes=30))\nsend_mail(user.email, '/reset/' + token)")}),
("A05", "CWE-489", "Debug mode enabled", {
 "python": ("app.run(debug=True, host='0.0.0.0')", "app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='127.0.0.1')"),
 "php": ("ini_set('display_errors', 1);", "ini_set('display_errors', 0);\nini_set('log_errors', 1);"),
 "javascript": ("app.use(errorhandler());", "if (process.env.NODE_ENV !== 'production') app.use(errorhandler());")}),
("A05", "CWE-942", "Overly permissive CORS", {
 "javascript": ("app.use(cors({ origin: '*', credentials: true }));", "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"),
 "python": ("CORS(app, origins='*', supports_credentials=True)", "CORS(app, origins=['https://app.example.com'], supports_credentials=True)")}),
("A05", "CWE-1004", "Session cookie without Secure/HttpOnly", {
 "python": ("app.config['SESSION_COOKIE_SECURE'] = False\napp.config['SESSION_COOKIE_HTTPONLY'] = False", "app.config['SESSION_COOKIE_SECURE'] = True\napp.config['SESSION_COOKIE_HTTPONLY'] = True\napp.config['SESSION_COOKIE_SAMESITE'] = 'Lax'"),
 "javascript": ("res.cookie('sid', sid);", "res.cookie('sid', sid, { httpOnly: true, secure: true, sameSite: 'lax' });")}),
("A05", "CWE-16", "Default credentials / admin interface exposed", {
 "yaml": ("services:\n  db:\n    image: mysql\n    environment:\n      MYSQL_ROOT_PASSWORD: root\n    ports: ['3306:3306']", "services:\n  db:\n    image: mysql\n    environment:\n      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/db_root\n    expose: ['3306']")}),
("A05", "CWE-250", "Container runs as root", {
 "dockerfile": ("FROM python:3.12\nCOPY . /app\nCMD [\"python\", \"/app/main.py\"]", "FROM python:3.12\nCOPY . /app\nRUN useradd -m app\nUSER app\nCMD [\"python\", \"/app/main.py\"]")}),
("A06", "CWE-1104", "Dependency pinned to a release with known vulnerabilities", {
 "text": ("requests==2.5.0\nflask==0.12", "requests>=2.32.0\nflask>=3.0  # keep updated; run pip-audit in CI"),
 "json": ("{\"dependencies\": {\"lodash\": \"4.17.4\", \"express\": \"3.0.0\"}}", "{\"dependencies\": {\"lodash\": \"^4.17.21\", \"express\": \"^4.19.0\"}}"),
 "xml": ("<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>",
         "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.23.1</version></dependency>")}),
("A06", "CWE-1104", "Untrusted package source / no lockfile integrity", {
 "text": ("pip install -r requirements.txt --index-url http://pypi.mirror.local/simple", "pip install -r requirements.txt --require-hashes"),
 "dockerfile": ("RUN npm install", "RUN npm ci --ignore-scripts")}),
("A07", "CWE-798", "Hard-coded credential check", {
 "javascript": ("if (pass === 'admin123') grant(user);", "if (await bcrypt.compare(pass, user.hash)) grant(user);"),
 "java": ("if (\"admin\".equals(user) && \"1234\".equals(pw)) login();", "if (auth.verify(user, pw)) login();")}),
("A07", "CWE-384", "Session id not rotated on login", {
 "python": ("def login():\n    session['uid'] = user.id", "def login():\n    session.clear()\n    session['uid'] = user.id\n    session.modified = True"),
 "php": ("$_SESSION['uid'] = $uid;", "session_regenerate_id(true);\n$_SESSION['uid'] = $uid;")}),
("A07", "CWE-613", "JWT without expiry / signature check", {
 "javascript": ("const p = jwt.decode(token);", "const p = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });"),
 "python": ("jwt.decode(token, options={'verify_signature': False})", "jwt.decode(token, SECRET, algorithms=['HS256'])")}),
("A07", "CWE-521", "Weak password policy", {
 "python": ("if len(pw) >= 4:\n    create_user(u, pw)", "if len(pw) >= 12 and pw not in COMMON_PASSWORDS:\n    create_user(u, pw)")}),
("A07", "CWE-208", "Timing-unsafe secret comparison", {
 "python": ("if token == expected:\n    ok()", "import hmac\nif hmac.compare_digest(token, expected):\n    ok()"),
 "javascript": ("if (sig === expected) ok();", "if (crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) ok();")}),
("A08", "CWE-502", "Unsafe deserialization", {
 "python": ("obj = pickle.loads(request.data)", "obj = json.loads(request.data)"),
 "java": ("ObjectInputStream in = new ObjectInputStream(req.getInputStream());\nObject o = in.readObject();", "ObjectMapper m = new ObjectMapper();\nDto o = m.readValue(req.getInputStream(), Dto.class);"),
 "php": ("$o = unserialize($_COOKIE['data']);", "$o = json_decode($_COOKIE['data'], true);"),
 "javascript": ("const o = require('node-serialize').unserialize(req.body.d);", "const o = JSON.parse(req.body.d);")}),
("A08", "CWE-502", "YAML load of untrusted input", {
 "python": ("cfg = yaml.load(text, Loader=yaml.Loader)", "cfg = yaml.safe_load(text)")}),
("A08", "CWE-494", "Download and execute without integrity check", {
 "shell": ("curl -s http://example.com/install.sh | sh", "curl -sO https://example.com/install.sh\necho \"$EXPECTED_SHA256  install.sh\" | sha256sum -c -\nsh install.sh"),
 "python": ("urllib.request.urlretrieve(url, 'update.bin')\nos.chmod('update.bin', 0o755)", "urllib.request.urlretrieve(url, 'update.bin')\nassert hashlib.sha256(open('update.bin','rb').read()).hexdigest() == EXPECTED\nos.chmod('update.bin', 0o755)")}),
("A08", "CWE-829", "Third-party script without Subresource Integrity", {
 "html": ("<script src=\"https://cdn.example.com/lib.js\"></script>", "<script src=\"https://cdn.example.com/lib.js\" integrity=\"sha384-BASE64HASH\" crossorigin=\"anonymous\"></script>")}),
("A08", "CWE-915", "Mass assignment", {
 "javascript": ("const u = await User.create(req.body);", "const { name, email } = req.body;\nconst u = await User.create({ name, email });"),
 "python": ("user = User(**request.json)", "data = request.json\nuser = User(name=data['name'], email=data['email'])")}),
("A09", "CWE-532", "Sensitive data in logs", {
 "python": ("logger.info('login %s %s', user, password)", "logger.info('login attempt for %s', user)"),
 "javascript": ("console.log('card', req.body.cardNumber);", "console.log('card ending', String(req.body.cardNumber).slice(-4));"),
 "java": ("log.info(\"token=\" + token);", "log.info(\"token issued for user {}\", userId);")}),
("A09", "CWE-778", "Security event not logged", {
 "python": ("def login(u, p):\n    if not check(u, p):\n        return False", "def login(u, p):\n    if not check(u, p):\n        audit.warning('failed login user=%s ip=%s', u, request.remote_addr)\n        return False"),
 "javascript": ("if (!ok) return res.sendStatus(401);", "if (!ok) { audit.warn({ event: 'login_failed', user, ip: req.ip }); return res.sendStatus(401); }")}),
("A09", "CWE-117", "Log injection through unsanitised input", {
 "python": ("logger.info('user ' + request.args['u'])", "logger.info('user %s', request.args['u'].replace('\\n', ' ').replace('\\r', ' '))"),
 "java": ("log.info(\"user \" + request.getParameter(\"u\"));", "log.info(\"user {}\", request.getParameter(\"u\").replaceAll(\"[\\r\\n]\", \"_\"));")}),
("A09", "CWE-209", "Stack trace returned to the client", {
 "python": ("except Exception as e:\n    return str(traceback.format_exc()), 500", "except Exception:\n    logger.exception('request failed')\n    return 'Internal error', 500"),
 "javascript": ("app.use((err, req, res, next) => res.status(500).send(err.stack));", "app.use((err, req, res, next) => { logger.error(err); res.status(500).send('Internal error'); });")}),
("A10", "CWE-918", "SSRF: server fetches a user-supplied URL", {
 "python": ("def preview(url):\n    return requests.get(url).text", "from urllib.parse import urlparse\nALLOWED = {'example.com'}\ndef preview(url):\n    if urlparse(url).hostname not in ALLOWED:\n        raise ValueError('host not allowed')\n    return requests.get(url, timeout=5, allow_redirects=False).text"),
 "javascript": ("const r = await axios.get(req.query.url);", "const u = new URL(req.query.url);\nif (!ALLOWED_HOSTS.has(u.hostname)) return res.sendStatus(400);\nconst r = await axios.get(u.href, { maxRedirects: 0, timeout: 5000 });"),
 "java": ("URL u = new URL(request.getParameter(\"url\"));\nInputStream in = u.openStream();", "URI u = URI.create(request.getParameter(\"url\"));\nif (!ALLOWED.contains(u.getHost())) throw new SecurityException(\"host\");\nInputStream in = u.toURL().openStream();"),
 "go": ("resp, _ := http.Get(r.URL.Query().Get(\"u\"))", "u, _ := url.Parse(r.URL.Query().Get(\"u\"))\nif !allowed[u.Hostname()] {\n\thttp.Error(w, \"forbidden\", 403)\n\treturn\n}\nresp, _ := http.Get(u.String())"),
 "php": ("echo file_get_contents($_GET['url']);", "$h = parse_url($_GET['url'], PHP_URL_HOST);\nif (!in_array($h, $ALLOWED, true)) { http_response_code(400); exit; }\necho file_get_contents($_GET['url']);")}),
("A10", "CWE-918", "SSRF: webhook target not restricted to public addresses", {
 "python": ("requests.post(user_webhook_url, json=payload)", "ip = socket.gethostbyname(urlparse(user_webhook_url).hostname)\nif ipaddress.ip_address(ip).is_private:\n    raise ValueError('private address')\nrequests.post(user_webhook_url, json=payload, timeout=5, allow_redirects=False)")}),
]

if __name__ == "__main__":
    out, n = [], 0
    for o, c, d, langs in T:
        for lang, (v, x) in langs.items():
            n += 1
            out.append({"id": f"O{n:04d}", "owasp": f"{o}:2021 - {NAMES[o]}", "cwe": c, "language": lang, "description": d,
                        "vulnerable_code": v, "fixed_code": x, "source": "original, written for this project", "license": "MIT"})
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(len(out), "samples")
