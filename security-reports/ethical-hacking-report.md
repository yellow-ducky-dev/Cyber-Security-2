# Ethical Hacking & Vulnerability Analysis Report (Week 5)

**Target System**: vuln-demo-server.js (Node.js Express with SQLite DB backend)
**Audit Date**: July 6, 2026
**Security Auditor**: cybersecurity-intern

---

## 1. Executive Summary
This report documents the reconnaissance, exploitation, and analysis of `vuln-demo`, a simulated test application containing several core web application vulnerabilities in line with the OWASP Top 10 guidelines (such as SQL Injection, Reflected XSS, IDOR, Weak Hashing, and CSRF). 

---

## 2. Reconnaissance (Information Gathering)
Reconnaissance was performed via network scanning simulation and manual spidering:
- **Port Scan**: Port `3001` is open, serving an HTTP web server (Express 5.2.1).
- **Directory Fuzzing / Discovery**: Ports crawler discovered the following key endpoints:
  - `/` (Home page)
  - `/login` (User login form)
  - `/register` (User registration form)
  - `/search` (User search functionality)
  - `/dashboard` (Authenticated home screen)
  - `/api/user/:id` (Direct Object Endpoint)
  - `/csrf-trap` (Simulated external phishing site)

---

## 3. Vulnerability Analysis & Exploitation

### Vulnerability 1: SQL Injection (SQLi) in Login Bypass
* **Type**: In-band SQL Injection
* **Endpoint**: `/login` (POST)
* **Parameters**: `username`
* **Severity**: 🔴 Critical
* **Exploit Vector**:
  The application joins variables directly into a raw search string:
  ```sql
  SELECT * FROM users WHERE username = '${username}' AND password = '${pwdHash}'
  ```
  By inputting `admin' --` in the username, the query becomes: 
  `SELECT * FROM users WHERE username = 'admin' --' AND password = '...'`
  The `--` comments out the password verification logic entirely, permitting immediate login as `admin`.
* **Remediation**: Replaced string interpolation with parameterized queries:
  ```javascript
  db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, pwdHash], ...)
  ```

---

### Vulnerability 2: SQL Injection (SQLi) UNION database query dump
* **Type**: UNION-based SQL Injection
* **Endpoint**: `/search` (GET)
* **Parameters**: `q`
* **Severity**: 🔴 Critical
* **Exploit Vector**:
  Inputting `alice' UNION SELECT 1,username,password,email,role,balance FROM users--` alters the SQLite statement execution.
  This allows retrieving passwords hashed with MD5 from the database and listing them in the search results table.
* **SQLMap Emulation**:
  ```bash
  sqlmap -u "http://localhost:3001/search?q=alice" --batch --dbs --tables --dump
  ```
  *Result*: SQLmap successfully identifies parameter `q` as injected, dumps the SQLite schema, extracts `users` table parameters, and discloses all secret password MD5 hashes.

---

### Vulnerability 3: Reflected Cross-Site Scripting (XSS)
* **Type**: Reflected XSS
* **Endpoint**: `/search` (GET)
* **Parameters**: `q`
* **Severity**: 🔴 High
* **Exploit Vector**:
  Unsanitized parameters returned directly:
  `Search query input: <strong>${query}</strong>`
  Visiting `/search?q=<script>alert('XSS-ATTACK')</script>` triggers JavaScript execution directly inside the browser session.
* **Remediation**: Input is passed through `validator.escape()` before being returned.

---

### Vulnerability 4: Insecure Direct Object Reference (IDOR) with Information Disclosure
* **Type**: IDOR / Privilege Escalation
* **Endpoint**: `/api/user/:id` (GET)
* **Severity**: 🔴 High
* **Exploit Vector**:
  Accessing `/api/user/1` yields the admin profile. Changing it to `/api/user/2` gets Alice's information. Password hashes are exposed in the JSON.
* **Remediation**: Implemented strict owner authentication checking and withheld sensitive fields like `password` from responses.

---

### Vulnerability 5: Cross-Site Request Forgery (CSRF)
* **Type**: CSRF
* **Endpoint**: `/transfer` (POST)
* **Parameters**: `toUser`, `amount`
* **Severity**: 🔴 High
* **Exploit Vector**:
  The transfer funds mechanism relies on an insecure session cookie with no CSRF validations.
  We created `http://localhost:3001/csrf-trap` simulating a fake website hosted by Bob. When Alice visits this page while logged into the application, a silent Javascript form submission executes, transferring $50 to Bob without Alice's knowledge.
* **Remediation**: Implemented cookie-based Double-Submit Tokens using `csrf-csrf` middleware.

---

## 4. Conclusion
The vulnerable application has been thoroughly pentested. All vulnerabilities have been successfully replicated. Parameterized queries, CSRF defenses, and output escaping are required to secure the program.
