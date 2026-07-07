# 🔐 Cybersecurity Internship — Weeks 4–6

**Developer:** [yellow-ducky-dev](https://github.com/yellow-ducky-dev)  
**Deadline:** July 21st, 2026  
**Stack:** Node.js · Express · SQLite · Docker · JWT · Helmet · Fail2Ban

[![Email](https://img.shields.io/badge/Email-rsikandar733%40gmail.com-red?style=for-the-badge&logo=gmail)](mailto:rsikandar733@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-yellow--ducky--dev-black?style=for-the-badge&logo=github)](https://github.com/yellow-ducky-dev)

---

## 📁 Project Structure

```
Cyber-Security-2/
├── secure-app/               # Week 4 — Hardened production-grade API
│   ├── server.js             # Express server with all security middleware
│   ├── monitor.js            # Real-time IDS — tails security.log & bans IPs
│   ├── logger.js             # Winston structured logging
│   ├── controllers/
│   │   └── authController.js # Register, Login, Profile with bcrypt + JWT
│   ├── middleware/
│   │   ├── auth.js           # JWT Bearer token verification
│   │   ├── apiKeyAuth.js     # Machine-to-machine API key validation
│   │   └── ipBlocker.js      # Reads blocked-ips.json and enforces bans
│   ├── routes/auth.js
│   ├── fail2ban-config/      # Fail2Ban jail.local + filter for Linux deployment
│   ├── Dockerfile            # Multi-stage, non-root container (Zero Trust)
│   └── test-security.js      # Automated security compliance tests
├── vuln-demo/                # Week 5 — Intentionally vulnerable + remediated apps
│   ├── vuln-demo-server.js           # Vulnerable app (SQLi, XSS, CSRF, IDOR)
│   └── vuln-demo-server-remediated.js # Fully remediated comparison app
└── security-reports/
    ├── ethical-hacking-report.md     # Week 5 pentest findings
    └── security-audit-report.md      # Week 6 OWASP ZAP / Nikto / Lynis audit
```

---

## 🚀 Quick Start

### Clone

```bash
git clone https://github.com/yellow-ducky-dev/Cyber-Security-2.git
cd Cyber-Security-2
```

### Run the Secure App (Week 4)

```bash
cd secure-app
npm install
cp .env.example .env      # or edit .env directly
node server.js            # Server starts on http://localhost:3000
```

Run the IDS monitor in a second terminal:

```bash
node monitor.js
```

Run automated compliance tests (with server running):

```bash
npm run test-security
```

### Run the Vulnerable Demo (Week 5)

```bash
cd vuln-demo
npm install

# Terminal A — Vulnerable app
node vuln-demo-server.js           # http://localhost:3001

# Terminal B — Remediated app (side-by-side comparison)
node vuln-demo-server-remediated.js  # http://localhost:3002
```

### Docker Deployment (Week 6)

```bash
cd secure-app
docker build -t secure-app:latest .
docker run -p 3000:3000 --env-file .env secure-app:latest

# Scan container for vulnerabilities
docker scout cves secure-app:latest
```

---

## 📌 Week 4 — Advanced Threat Detection & API Security

### 1. Intrusion Detection & Monitoring

**Implementation:** `monitor.js` + `ipBlocker.js`

- **Real-time log tailing:** `monitor.js` polls `logs/security.log` every 1 second using a file size pointer (no re-reading old data).
- **Sliding window:** Tracks failed login events per IP in a 60-second window.
- **Auto-ban:** After **5 failures** in 60 seconds, the IP is written to `blocked-ips.json` with a 5-minute ban expiry.
- **IDS middleware:** `ipBlocker.js` loads `blocked-ips.json` on startup and refreshes every 10 seconds, returning `403 Forbidden` to banned IPs.
- **Fail2Ban config:** `fail2ban-config/jail.local` provides a production config for Linux hosts — monitors the same log file with `maxretry=5`, `findtime=60`, `bantime=300`.

### 2. API Security Hardening

**Rate Limiting** (`express-rate-limit`):

| Limiter | Window | Max Requests | Target |
|---------|--------|-------------|--------|
| Login limiter | 15 minutes | 5 attempts | `/api/auth/*` |
| Global limiter | 1 minute | 100 requests | All routes |

**CORS** — restricted to an explicit allowlist in `.env`:
```
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```
Requests from unlisted origins are rejected with a CORS error.

**API Key Authentication** (`middleware/apiKeyAuth.js`):
- Reads `x-api-key` header.
- Validates against comma-separated keys in `API_KEYS` env variable.
- Protected endpoint: `GET /api/secure-data`

**JWT Authentication** (`middleware/auth.js`):
- Bearer token extracted from `Authorization` header.
- Signed with `JWT_SECRET`, expires in 1 hour.
- Protected endpoint: `GET /api/auth/profile`

### 3. Security Headers & CSP

Implemented via `helmet`:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `X-XSS-Protection` | `0` (modern browsers use CSP instead) |
| `X-Powered-By` | Removed (fingerprint prevention) |

---

## 📌 Week 5 — Ethical Hacking & Vulnerability Exploitation

See [`security-reports/ethical-hacking-report.md`](security-reports/ethical-hacking-report.md) for the full report.

### Vulnerabilities Demonstrated in `vuln-demo-server.js`

| ID | Vulnerability | Severity | Exploit |
|----|--------------|----------|---------|
| V1 | Reflected XSS | 🔴 Critical | `/search?q=<script>alert(1)</script>` |
| V2 | SQL Injection (login bypass) | 🔴 Critical | Username: `admin' --` |
| V2b | SQL Injection (UNION dump) | 🔴 Critical | UNION SELECT to dump all password hashes |
| V3 | MD5 password hashing | 🔴 Critical | Trivially crackable with rainbow tables |
| V4 | IDOR + Info Disclosure | 🔴 High | `/api/user/1` exposes any user's hash |
| V5 | CSRF on fund transfer | 🔴 High | Auto-submit form at `/csrf-trap` |
| V6 | No rate limiting | 🟡 Medium | Unlimited brute-force via `/api/brute-test` |

### Remediations in `vuln-demo-server-remediated.js`

- **SQLi → Parameterized queries:** All DB queries use `?` placeholders with separate value arrays.
- **XSS → `validator.escape()`:** All user input reflected in HTML is escaped.
- **CSRF → `csrf-csrf` double-submit tokens:** Hidden `_csrf` field required on all state-changing POST requests.
- **IDOR → Owner verification:** `/api/user/:id` checks session identity; users can only access their own profile (admins exempt).
- **Info disclosure → Withheld fields:** Password hashes are excluded from all JSON API responses.
- **Cookies → Secure flags:** `httpOnly: true`, `sameSite: 'lax'` on all session cookies.

### SQLMap Simulation

```bash
sqlmap -u "http://localhost:3001/search?q=alice" --batch --dbs --tables --dump
```

> SQLMap identifies `q` as injectable, extracts the SQLite schema, and dumps the `users` table including MD5-hashed passwords.

---

## 📌 Week 6 — Security Audits & Secure Deployment

See [`security-reports/security-audit-report.md`](security-reports/security-audit-report.md) for the full audit report.

### Security Tools Used

| Tool | Target | Key Finding |
|------|--------|-------------|
| **OWASP ZAP** | `vuln-demo` (port 3001) | 🔴 High: SQLi, XSS, CSRF |
| **OWASP ZAP** | `secure-app` (port 3000) | ✅ Zero high-severity findings |
| **Nikto** | `secure-app` | ✅ CSP, HSTS, X-Frame-Options all present |
| **Lynis** | Docker host | → Non-root container user enforced |

### OWASP Top 10 Compliance

| OWASP Risk | Status |
|------------|--------|
| A01 Broken Access Control | ✅ IDOR fixed, owner validation |
| A02 Cryptographic Failures | ✅ bcrypt (cost=10) in secure-app |
| A03 Injection | ✅ Parameterized queries + XSS escaping |
| A04 Insecure Design | ✅ Rate limiting + IDS monitor |
| A05 Security Misconfiguration | ✅ Helmet headers, strict CORS |
| A06 Vulnerable Components | ✅ Dependabot weekly scans |
| A07 Auth & Session Failures | ✅ JWT, httpOnly cookies, generic errors |
| A08 SW & Data Integrity | ✅ CSRF double-submit tokens |

### Docker Security

```dockerfile
# Multi-stage build — production dependencies only
FROM node:18-alpine AS builder
RUN npm ci --only=production

# Non-root user (Principle of Least Privilege)
FROM node:18-alpine
USER node
EXPOSE 3000
CMD ["node", "server.js"]
```

### Automated Dependency Scanning

`.github/dependabot.yml` runs weekly for both `secure-app` and `vuln-demo` npm packages, automatically opening pull requests for outdated or vulnerable dependencies.

---

## ⭐ Bonus — Zero Trust & WAF

### Zero Trust Principles Applied

- **Container:** Runs as `USER node` (non-root) — no privilege escalation possible.
- **API Authentication:** Every machine-to-machine call requires a valid `x-api-key` header regardless of network position.
- **JWT validation:** Every protected route re-validates the token on each request — no session state trusted implicitly.
- **IP blocking:** IPs are banned dynamically based on behavior, not assumed to be safe because they're inside a network.

### Web Application Firewall (Conceptual)

In a production deployment, a WAF such as **AWS WAF**, **Cloudflare WAF**, or **ModSecurity** would sit in front of the Express server and provide:
- Managed rule sets blocking SQLi, XSS, CSRF signatures.
- Rate limiting at the network edge before requests reach Node.
- Geo-blocking and IP reputation lists.

---

## 📋 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `JWT_SECRET` | JWT signing secret | ⚠️ Must override in prod |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `http://localhost:3000,...` |
| `API_KEYS` | Comma-separated valid API keys | `dev-key-12345,...` |

---

## 🧪 Automated Security Tests

```bash
npm run test-security
```

Tests validate:
1. **HSTS + CSP headers** present on all responses
2. **CORS** blocks unlisted origins
3. **API Key** rejects missing/invalid keys, accepts valid ones
4. **Log file** is created by Winston logger
