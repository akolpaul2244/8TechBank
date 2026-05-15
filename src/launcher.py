"""
8TechBank — App Launcher
Runs on port 5002. Links out to:
  - Vulnerable app: http://localhost:5000
  - Secure app:     http://localhost:5001

Usage:
  python launcher.py
"""

from flask import Flask, render_template_string
import os

app = Flask(__name__)

# Adjust these if your ports differ
VULNERABLE_URL = os.environ.get('VULNERABLE_URL', 'http://localhost:5000')
SECURE_URL     = os.environ.get('SECURE_URL',     'http://localhost:5001')

LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>8TechBank — Lab Launcher</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;1,300;1,400&family=Figtree:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --gold:        #c9a84c;
      --gold-lt:     #e8d08e;
      --gold-dim:    rgba(201,168,76,0.10);
      --gold-border: rgba(201,168,76,0.28);
      --danger:      #e05252;
      --danger-lt:   #ff8080;
      --danger-dim:  rgba(224,82,82,0.10);
      --danger-border: rgba(224,82,82,0.28);
      --success:     #2ecc8f;
      --bg:          #090a0c;
      --bg-1:        #0f1114;
      --bg-2:        #171a1f;
      --border:      rgba(255,255,255,0.07);
      --text:        #cdd2da;
      --text-dim:    #5a6270;
      --font-display:'Cormorant Garamond', Georgia, serif;
      --font-body:   'Figtree', sans-serif;
      --font-mono:   'JetBrains Mono', monospace;
    }

    html, body {
      height: 100%;
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-body);
      -webkit-font-smoothing: antialiased;
    }

    /* ── noise grain overlay ── */
    body::before {
      content: '';
      position: fixed; inset: 0; z-index: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.035'/%3E%3C/svg%3E");
      background-size: 200px 200px;
      pointer-events: none;
      opacity: 0.6;
    }

    /* ── radial glow center ── */
    body::after {
      content: '';
      position: fixed;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      width: 900px; height: 900px;
      background: radial-gradient(ellipse, rgba(201,168,76,0.04) 0%, transparent 65%);
      pointer-events: none; z-index: 0;
    }

    /* ── gold top line ── */
    .top-line {
      position: fixed; top: 0; left: 0; right: 0; height: 1px; z-index: 10;
      background: linear-gradient(90deg, transparent 0%, var(--gold) 40%, var(--gold-lt) 50%, var(--gold) 60%, transparent 100%);
    }

    /* ── layout ── */
    .stage {
      position: relative; z-index: 1;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 3rem 1.5rem;
      gap: 0;
    }

    /* ── eyebrow ── */
    .eyebrow {
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--gold);
      margin-bottom: 1.75rem;
      opacity: 0;
      animation: rise 0.6s 0.1s cubic-bezier(0.22,1,0.36,1) forwards;
    }

    /* ── logo mark ── */
    .logo-mark {
      width: 56px; height: 56px;
      background: var(--gold);
      border-radius: 10px;
      display: flex; align-items: center; justify-content: center;
      font-family: var(--font-body);
      font-size: 18px; font-weight: 700;
      color: #000;
      margin: 0 auto 1.5rem;
      opacity: 0;
      animation: rise 0.6s 0.2s cubic-bezier(0.22,1,0.36,1) forwards;
      box-shadow: 0 0 40px rgba(201,168,76,0.22), 0 0 80px rgba(201,168,76,0.08);
    }

    /* ── headline ── */
    h1 {
      font-family: var(--font-display);
      font-size: clamp(2.8rem, 6vw, 4.5rem);
      font-weight: 300;
      letter-spacing: -0.01em;
      text-align: center;
      color: #e8ecf0;
      line-height: 1.08;
      margin-bottom: 1rem;
      opacity: 0;
      animation: rise 0.7s 0.3s cubic-bezier(0.22,1,0.36,1) forwards;
    }
    h1 em {
      font-style: italic;
      color: var(--gold-lt);
    }

    /* ── sub ── */
    .sub {
      font-size: 14px;
      color: var(--text-dim);
      text-align: center;
      max-width: 400px;
      line-height: 1.7;
      margin-bottom: 3.5rem;
      opacity: 0;
      animation: rise 0.7s 0.4s cubic-bezier(0.22,1,0.36,1) forwards;
    }

    /* ── cards ── */
    .cards {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
      width: 100%;
      max-width: 680px;
      opacity: 0;
      animation: rise 0.7s 0.55s cubic-bezier(0.22,1,0.36,1) forwards;
    }

    .card {
      position: relative;
      border-radius: 16px;
      border: 1px solid var(--border);
      background: var(--bg-1);
      padding: 2rem 1.75rem 1.75rem;
      display: flex;
      flex-direction: column;
      gap: 0;
      text-decoration: none;
      transition: border-color 0.22s, transform 0.22s, box-shadow 0.22s;
      overflow: hidden;
      cursor: pointer;
    }

    .card::before {
      content: '';
      position: absolute;
      inset: 0;
      opacity: 0;
      transition: opacity 0.25s;
      border-radius: inherit;
    }

    /* secure card */
    .card-secure {
      --accent: var(--gold);
      --accent-dim: var(--gold-dim);
      --accent-border: var(--gold-border);
    }
    .card-secure::before {
      background: radial-gradient(ellipse at top left, rgba(201,168,76,0.07) 0%, transparent 65%);
    }
    .card-secure:hover {
      border-color: var(--gold-border);
      box-shadow: 0 0 0 1px var(--gold-border), 0 20px 60px rgba(201,168,76,0.10);
      transform: translateY(-3px);
    }

    /* vulnerable card */
    .card-vuln {
      --accent: var(--danger);
      --accent-dim: var(--danger-dim);
      --accent-border: var(--danger-border);
    }
    .card-vuln::before {
      background: radial-gradient(ellipse at top left, rgba(224,82,82,0.07) 0%, transparent 65%);
    }
    .card-vuln:hover {
      border-color: var(--danger-border);
      box-shadow: 0 0 0 1px var(--danger-border), 0 20px 60px rgba(224,82,82,0.10);
      transform: translateY(-3px);
    }

    .card:hover::before { opacity: 1; }

    /* card icon */
    .card-icon {
      width: 38px; height: 38px;
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      margin-bottom: 1.25rem;
      border: 1px solid var(--accent-border);
      background: var(--accent-dim);
      color: var(--accent);
      flex-shrink: 0;
    }

    .card-tag {
      font-family: var(--font-mono);
      font-size: 9px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 0.5rem;
    }

    .card-title {
      font-family: var(--font-display);
      font-size: 1.45rem;
      font-weight: 600;
      color: #e0e4ea;
      margin-bottom: 0.65rem;
      line-height: 1.2;
    }

    .card-desc {
      font-size: 12.5px;
      color: var(--text-dim);
      line-height: 1.65;
      flex: 1;
      margin-bottom: 1.5rem;
    }

    .card-features {
      list-style: none;
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-bottom: 1.75rem;
    }

    .card-features li {
      font-size: 11.5px;
      color: #6a7280;
      display: flex;
      align-items: center;
      gap: 7px;
    }

    .card-features li::before {
      content: '';
      width: 5px; height: 5px;
      border-radius: 50%;
      background: var(--accent);
      opacity: 0.6;
      flex-shrink: 0;
    }

    .card-btn {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 10px 14px;
      border-radius: 8px;
      background: var(--accent-dim);
      border: 1px solid var(--accent-border);
      font-size: 12px;
      font-weight: 600;
      color: var(--accent);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      transition: background 0.18s, color 0.18s;
    }

    .card:hover .card-btn {
      background: var(--accent);
      color: #000;
    }

    .card-btn svg { transition: transform 0.18s; }
    .card:hover .card-btn svg { transform: translateX(3px); }

    /* ── divider ── */
    .or-divider {
      display: flex;
      align-items: center;
      gap: 1rem;
      width: 100%;
      max-width: 680px;
      margin-top: 2.5rem;
      opacity: 0;
      animation: rise 0.6s 0.7s cubic-bezier(0.22,1,0.36,1) forwards;
    }
    .or-divider::before,
    .or-divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }
    .or-divider span {
      font-family: var(--font-mono);
      font-size: 10px;
      color: var(--text-dim);
      letter-spacing: 0.1em;
    }

    /* ── footer note ── */
    .footer-note {
      margin-top: 2.25rem;
      font-size: 11.5px;
      color: var(--text-dim);
      text-align: center;
      max-width: 420px;
      line-height: 1.6;
      opacity: 0;
      animation: rise 0.6s 0.8s cubic-bezier(0.22,1,0.36,1) forwards;
    }

    .footer-note strong { color: var(--danger-lt); font-weight: 500; }

    /* ── port chips ── */
    .port-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-family: var(--font-mono);
      font-size: 10px;
      padding: 2px 7px;
      border-radius: 4px;
      border: 1px solid var(--border);
      color: var(--text-dim);
      background: var(--bg-2);
      position: absolute;
      top: 14px; right: 14px;
    }
    .port-chip .dot {
      width: 5px; height: 5px;
      border-radius: 50%;
      background: var(--success);
      animation: pulse 2s ease-in-out infinite;
    }
    .card-vuln .port-chip .dot { background: var(--danger); animation-delay: 0.5s; }

    /* ── animations ── */
    @keyframes rise {
      from { opacity: 0; transform: translateY(18px); }
      to   { opacity: 1; transform: translateY(0); }
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.35; }
    }

    /* ── responsive ── */
    @media (max-width: 600px) {
      .cards { grid-template-columns: 1fr; max-width: 360px; }
      h1 { font-size: 2.4rem; }
    }
  </style>
</head>
<body>

<div class="top-line"></div>

<div class="stage">

  <div class="eyebrow">Security Lab &mdash; Choose Your Environment</div>

  <div class="logo-mark">8T</div>

  <h1>8Tech<em>Bank</em></h1>

  <p class="sub">
    Two identical banking interfaces — one hardened, one deliberately broken.
    Pick your environment to begin.
  </p>

  <div class="cards">

    <!-- SECURE -->
    <a class="card card-secure" href="{{ secure_url }}">
      <div class="port-chip">
        <span class="dot"></span>
        :5001
      </div>
      <div class="card-icon">
        <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
        </svg>
      </div>
      <div class="card-tag">Secure Build</div>
      <div class="card-title">Hardened App</div>
      <div class="card-desc">Production-grade security controls active. Use this to see what a properly secured banking app looks like.</div>
      <ul class="card-features">
        <li>Parameterised queries &amp; bcrypt</li>
        <li>CSRF tokens on all forms</li>
        <li>CSP with per-request nonces</li>
        <li>Rate limiting &amp; JWT auth</li>
      </ul>
      <div class="card-btn">
        Launch Secure App
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/>
        </svg>
      </div>
    </a>

    <!-- VULNERABLE -->
    <a class="card card-vuln" href="{{ vulnerable_url }}">
      <div class="port-chip">
        <span class="dot"></span>
        :5002
      </div>
      <div class="card-icon">
        <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.8">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
        </svg>
      </div>
      <div class="card-tag">Vulnerable Build</div>
      <div class="card-title">Intentionally Broken</div>
      <div class="card-desc">Deliberately insecure for penetration testing and education. Contains real, exploitable vulnerabilities.</div>
      <ul class="card-features">
        <li>SQL injection in login</li>
        <li>Stored XSS via transfer notes</li>
        <li>IDOR on account endpoints</li>
        <li>No CSRF protection</li>
      </ul>
      <div class="card-btn">
        Launch Vulnerable App
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"/>
        </svg>
      </div>
    </a>

  </div>

  <div class="or-divider"><span>environment info</span></div>

  <p class="footer-note">
    <strong>Warning:</strong> Never use real credentials in the vulnerable app.
    Both apps share the same UI — only the backend security posture differs.
    This launcher runs on port&nbsp;5000.
  </p>

</div>

</body>
</html>"""


@app.route('/')
def index():
    return render_template_string(
        LANDING_HTML,
        secure_url=SECURE_URL,
        vulnerable_url=VULNERABLE_URL
    )


if __name__ == '__main__':
    app.run(debug=False, port=5002)