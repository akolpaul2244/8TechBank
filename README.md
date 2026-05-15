# 8TechBank - Deliberately Vulnerable Banking App

This is a deliberately vulnerable banking application built for security auditing and exploitation demonstration.

## Setup Instructions

1. Navigate to the vulnerable source code:
   ```
   cd src/vulnerable
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the application:
   ```
   python app.py
   ```

4. Access the app at http://localhost:5000

## Project Structure

- `src/vulnerable/` - Original vulnerable code
- `src/secure/` - Fixed secure version
- `exploits/` - Proof-of-concept attack scripts
- `screenshots/` - Evidence screenshots
- `report/` - Security report PDF
- `README.md` - This file

## Features

- User registration and login
- Account dashboard with balance
- Fund transfer between accounts
- Transaction history
- Admin panel for viewing all users

## Vulnerabilities (Embedded)

1. SQL Injection in login
2. Reflected XSS in search
3. Stored XSS in transfer notes
4. IDOR in account access
5. Plaintext password storage
6. Missing CSRF protection

## Additional Vulnerabilities Found

7. Missing security headers
8. Session misconfiguration

## Tasks

1. Security Audit
2. Exploit Demonstrations
3. Fix Vulnerabilities
4. API Security Implementation
5. Security Report