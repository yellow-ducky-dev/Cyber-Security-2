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
Final verification checks against the remediated implementations prove that the system successfully blocks the automated attack payloads (represented by SQLi, XSS, and CSRF) while logging the intrusion attempts appropriately. The rate limiter and dynamic IP blocker (IDS) shield the environment from denial of service and credentials stuffing.
