# Screenshots

This folder must contain all evidence screenshots referenced in the report.
Take each screenshot while the relevant app is running, then save it here
with the exact filename listed below.

## Required Screenshots

### Task 2 — Exploit Evidence (before fixes)

| Filename | What to capture |
|----------|----------------|
| `exploit_a1_sqli_bypass.png` | Dashboard page after logging in with `' OR '1'='1' --` |
| `exploit_a2_sqli_union.png` | Browser or terminal showing UNION extraction result |
| `exploit_a3_blind_sqli.png` | Terminal output of `sql_injection_poc.py` (all three exploits succeed) |
| `exploit_b1_reflected_xss.png` | JavaScript alert box showing `document.cookie` via the search URL |
| `exploit_b2_stored_xss.png` | JavaScript alert triggered when viewing `/history` after injecting note |
| `exploit_c_csrf_transfer.png` | Transaction history showing the forged transfer after opening `csrf_attack.html` |
| `exploit_d_idor.png` | Alice's browser at `/account/2` showing Bob's username and balance |
| `exploit_plaintext_db.png` | SQLite CLI output: `SELECT username, password FROM users;` showing plaintext |
| `exploit_session_cookie.png` | DevTools Application > Cookies showing no HttpOnly/Secure/SameSite flags |
| `exploit_no_headers.png` | DevTools Network tab showing response with no security headers |

### Task 3 — Fix Verification Evidence (after fixes, secure app port 5001)

| Filename | What to capture |
|----------|----------------|
| `fix1_sqli_blocked.png` | Login page returned with "Invalid credentials" after injection payload |
| `fix2_xss_blocked.png` | XSS payload displayed as escaped text `&lt;script&gt;` — not executed |
| `fix3_csrf_blocked.png` | HTTP 400 error or CSRF error page when `csrf_attack.html` is opened |
| `fix4_idor_blocked.png` | "Access denied" 403 response when accessing `/account/2` as alice |
| `fix5_hashed_passwords.png` | SQLite CLI showing `$2b$12$...` bcrypt hashes in the password column |
| `fix6_security_headers.png` | DevTools Network tab showing all security headers present |

## How to Take Screenshots

**Vulnerable app (port 5000):**
```
cd src/vulnerable
python app.py
# Open http://localhost:5000
```

**Secure app (port 5001):**
```
cd src/secure
pip install -r requirements.txt
python app.py
# Open http://localhost:5001
```

**For exploit scripts:**
```
pip install requests
python exploits/sql_injection_poc.py   # SQL injection
python exploits/idor_poc.py            # IDOR
# Open exploits/xss_poc.html in browser while logged in
# Open exploits/csrf_attack.html in browser while logged in to vulnerable app
```

**For database inspection:**
```
sqlite3 src/vulnerable/bank.db "SELECT username, password FROM users;"
sqlite3 src/secure/bank.db    "SELECT username, password FROM users;"
```
