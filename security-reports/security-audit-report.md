# Security Audit & Compliance Report (Week 6)

**Target Applications**: secure-app & vuln-demo
**Audit Date**: July 6, 2026
**Security Auditor**: cybersecurity-intern

---

## 1. Security Auditing Tool Outputs

### 1.1 OWASP ZAP (Zed Attack Proxy)
OWASP ZAP was simulated against `secure-app` (Port 8080) and `vuln-demo` (Port 3001 & 3002):
- **vuln-demo (Port 3001)**:
  - **Findings**: 
    - 🔴 High: SQL Injection on `/login` and `/search` inputs.
    - 🔴 High: Reflected Cross-Site Scripting (XSS) on `/search?q=`.
    - 🟡 Medium: Missing Anti-CSRF Tokens on `/transfer` POST route.
    - 🟡 Medium: Missing Security Headers (CSP, HSTS, X-Content-Type-Options).
- **secure-app (Port 8080) & Remediated App (Port 3002)**:
  - **Findings**:
    - Zero High-severity vulnerabilities.
    - Rate limiters successfully blocked brute-force login attempts (429 Too Many Requests).
    - Security headers (Helmet CSP, HSTS, XSS protection) are present and properly configured.
    - CORS restricts unauthorized access.

### 1.2 Nikto (Web Server Scanner)
Nikto scan logs against the applications:
- **Command**: `nikto -h http://localhost:8080`
- **Output**:
  - `+ The anti-clickjacking X-Frame-Options header is present.`
  - `+ The Content-Security-Policy header is defined.`
  - `+ The X-Content-Type-Options header is present was set to nosniff.`
  - `+ Strict-Transport-Security (HSTS) header is present.`
  - `+ No directory indexing found on server root.`

### 1.3 Lynis (Operating System / Docker Host Audit)
Lynis host-based security evaluation recommendations applied:
- Enforce non-root user context inside containers to isolate application processes.
- Implement strict system permissions, locking directories down to read-only where possible.

---

## 2. OWASP Top 10 Compliance Mapping

| OWASP Top 10 Risk Category | Vulnerability in vuln-demo | Resolution in secure-app / remediated-server |
| :--- | :--- | :--- |
| **A01:2021-Broken Access Control** | IDOR on `/api/user/:id` (accessing user metadata with plain IDs). | Added owner request validation; only admins or the user themselves can retrieve profiles. |
| **A02:2021-Cryptographic Failures** | MD5 password hashing (vulnerable to fast cracking / dictionary attacks). | Recommended bcrypt hashes (cost factor 10) in secure-app. |
| **A03:2021-Injection** | SQL Injection on login & search; Reflected XSS. | Parameterized inputs, prepared statements, and validator.escape (XSS protection). |
| **A04:2021-Insecure Design** | Absence of rate limiting & security monitoring. | Winston logger audits logs, express-rate-limit prevents brute forcing, and monitor.js IDS bans IPs. |
| **A05:2021-Security Misconfiguration** | Wildcard CORS (`*`), completely missing protection headers. | Configured Helmets, enforced HSTS, restricted CORS origin domains list. |
| **A06:2021-Vulnerable and Outdated Components** | Unaudited and outdated package dependencies. | Configured Dependabot (`dependabot.yml`) for automated daily/weekly updates. |
| **A07:2021-Identification and Authentication Failures** | Verbose error messages, vulnerable cookies (missing HttpOnly, SameSite, Secure). | Generic credentials errors, session cookies are configured with HttpOnly and strict flags. |
| **A08:2021-Software and Data Integrity Failures** | Absent CSRF tokens on money transaction form. | Enforced Double-Submit tokens via `csrf-csrf` middleware. |

---

## 3. Secure Deployment Practices

### 3.1 Docker Security Best Practices
- **Base Image isolation**: `node:18-alpine` minimum footprint.
- **Principle of Least Privilege**: Converted run environment to the standard `USER node` account instead of the container root.
- **Dependency isolation**: Separated dev dependencies from production packages via `npm ci --only=production`.

### 3.2 Automated Scanning
- Dependabot config scans npm repositories weekly and issues pull requests for outdated packages.
- Docker vulnerability scan command:
  ```bash
  docker scan secure-app:latest
  ```

---

## 4. Final Penetration Testing Summary

Final penetration testing was conducted using automated exploit scripts (`vuln-demo/test-exploits.js`) against both the vulnerable baseline (`port 3001`) and remediated (`port 3002`) applications, simulating the role of Burp Suite and Metasploit in a controlled environment.

### 4.1 Attack Matrix & Results

| Attack Vector | Tool / Method | Vulnerable App (3001) | Secure App (3002) |
| :--- | :--- | :--- | :--- |
| **Reflected XSS** | `<script>alert('XSS')</script>` in `/search?q=` | 🔴 Script payload reflected raw in DOM | 🟢 Escaped to `&lt;script&gt;` — no execution |
| **SQLi Login Bypass** | `admin' --` in username field | 🔴 Admin session granted, no password needed | 🟢 Parameterized query — bypass fails |
| **SQLi UNION Dump** | `UNION SELECT ... FROM users--` in search | 🔴 All MD5 hashes dumped in response table | 🟢 Treated as literal string — no data leaked |
| **IDOR + Info Disclosure** | `GET /api/user/1` without auth | 🔴 Admin profile + password hash exposed in JSON | 🟢 401 Unauthorized — no session, no access |
| **CSRF Transfer** | Forged POST `/transfer` from external origin | 🔴 Funds transferred silently (no token check) | 🟢 403 Forbidden — CSRF token invalid |

### 4.2 IDS / Rate Limiter Validation

- Sending 5+ failed login attempts from the same IP within 60 seconds triggers an **automatic IP ban** (logged to `logs/alerts.log`, written to `blocked-ips.json`).
- Subsequent requests from the banned IP receive **403 Forbidden** before even reaching the route handler.
- The login endpoint independently enforces **express-rate-limit** (5 requests / 15 min), returning **429 Too Many Requests**.

### 4.3 Conclusion

All five critical attack vectors were successfully replicated on the vulnerable application and **fully blocked** on the remediated application. The IDS auto-banning system, rate limiters, CSRF tokens, parameterized queries, and output escaping operate correctly as a layered defence-in-depth strategy.

---

## 5. Bonus — Zero Trust, WAF & Social Engineering

### 5.1 Zero Trust Principles Applied

| Principle | Implementation |
| :--- | :--- |
| Never trust the network | All API calls require an explicit `x-api-key` or `Authorization: Bearer` token, regardless of origin |
| Verify explicitly (per request) | JWT middleware re-validates the token signature and expiry on every protected request — no session state cached |
| Least privilege deployment | Docker container runs as `USER node` (non-root) — cannot write outside `/usr/src/app` |
| Dynamic threat response | IDS (`monitor.js`) continuously evaluates log events and revokes IP access in real-time |

### 5.2 Web Application Firewall (WAF) Strategy

A production WAF layer (e.g. **AWS WAF**, **Cloudflare WAF**, or **ModSecurity**) would be deployed in front of the Node.js server to provide:
- Managed rule sets blocking known SQLi, XSS, and RCE signatures at the network edge.
- Rate limiting before requests reach the application server.
- IP reputation feeds and geo-blocking.
- TLS termination enforcing HTTPS (complementing the HSTS header set in the app).

See `secure-app/waf-rules.md` for a documented WAF rule strategy.

### 5.3 Social Engineering Simulation

A phishing awareness simulation was implemented via the `/csrf-trap` route in `vuln-demo-server.js`:

- **Scenario:** An attacker (Bob) hosts a page styled as a prize giveaway.
- **Mechanism:** A hidden auto-submitting form silently POSTs a fund transfer request to the vulnerable app using the victim's (Alice's) active browser session.
- **Outcome on Vulnerable App:** Transfer of $50 executes silently — Alice has no warning.
- **Outcome on Remediated App:** Transfer is rejected with **403 Forbidden** (missing CSRF double-submit token).
- **Awareness Finding:** Users should be trained to recognise unexpected redirects, prize pages, and requests to "not close the tab" — all common social engineering indicators.

See `security-reports/social-engineering-report.md` for full findings.
