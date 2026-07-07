# WAF (Web Application Firewall) — Rule Strategy

**Application:** secure-app (Node.js / Express)  
**Recommended WAF Options:** AWS WAF | Cloudflare WAF | ModSecurity (NGINX/Apache)

---

## 1. Core Rule Groups to Enable

| Rule Group | Purpose |
|-----------|---------|
| `AWSManagedRulesCommonRuleSet` | Blocks OWASP Top 10 patterns (SQLi, XSS, CSRF, path traversal) |
| `AWSManagedRulesSQLiRuleSet` | Dedicated SQL Injection signature matching on all query params & body |
| `AWSManagedRulesKnownBadInputsRuleSet` | Blocks known malicious payloads (Log4Shell, Spring4Shell, etc.) |
| `AWSManagedRulesAmazonIpReputationList` | Blocks IPs from known botnet, scanner, and tor exit node lists |

---

## 2. Custom Rate-Limit Rule (Edge Layer)

```
Rule: LoginBruteForceProtection
  Match: URI path STARTS_WITH /api/auth/login   (POST only)
  Rate limit: 5 requests per 5 minutes per source IP
  Action: BLOCK → return 429 Too Many Requests
```

This complements the in-app `express-rate-limit` by stopping brute-force at the CDN/edge before requests reach the Node process.

---

## 3. Custom Geo-Blocking Rule (Optional)

```
Rule: GeoBlockHighRiskRegions
  Match: Originating country NOT IN [your-allowed-countries]
  Action: BLOCK
```

---

## 4. SQLi / XSS Signature Examples (ModSecurity)

```nginx
# Inline SQL Injection patterns
SecRule ARGS "@detectSQLi" \
  "id:1001,phase:2,block,msg:'SQL Injection Detected',logdata:'%{ARGS}'"

# XSS script tag patterns  
SecRule ARGS "@detectXSS" \
  "id:1002,phase:2,block,msg:'XSS Attack Detected',logdata:'%{ARGS}'"
```

---

## 5. TLS / HTTPS Enforcement

The WAF should terminate TLS and enforce HTTPS:

```
HTTP → HTTPS redirect: 301 Permanent
Minimum TLS version: TLS 1.2
Preferred: TLS 1.3
HSTS forwarded from app: max-age=31536000; includeSubDomains; preload
```

---

## 6. Logging & Alerting

- All WAF block events → centralised log sink (CloudWatch / Splunk / ELK).
- Alert thresholds: >20 blocks/min from a single IP → PagerDuty / Slack webhook.
- Daily WAF report → security team inbox.

---

## 7. Defence-in-Depth Layering

```
Internet
  │
  ▼
[WAF] ← Blocks SQLi, XSS, known bad IPs, enforces rate limit at edge
  │
  ▼
[NGINX / Load Balancer] ← TLS termination, keep-alive, proxy headers
  │
  ▼
[Node.js / Express] ← Helmet CSP/HSTS, CORS, express-rate-limit, apiKeyAuth, JWT
  │
  ▼
[IDS: monitor.js] ← Log-based IP banning, alert generation
  │
  ▼
[SQLite / DB] ← Parameterized queries only — no raw string SQL
```
