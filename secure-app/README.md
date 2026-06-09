# 🔐 Secured User Management System
**Cybersecurity Internship Task | Weeks 1–3**

## Quick Start
```bash
npm install
node server.js
# Visit http://localhost:3000
```

## Security Measures Implemented

| Layer | Tool/Method | Purpose |
|---|---|---|
| Password Storage | `bcrypt` (cost=10) | No plaintext/MD5 passwords |
| Authentication | `jsonwebtoken` (1h expiry) | Stateless, signed tokens |
| HTTP Headers | `helmet.js` + CSP | XSS, clickjacking, MIME sniffing |
| Rate Limiting | `express-rate-limit` | Brute-force protection |
| Input Validation | `validator` library | Email, alphanumeric, length checks |
| Input Sanitization | `validator.escape()` | XSS prevention |
| Logging | `winston` | Audit trail → `logs/security.log` |

## Vulnerabilities Fixed (from vuln-nodejs-app)

1. **MD5 Password Hashing** → Replaced with bcrypt
2. **No Input Sanitization** → Added validator + escape()
3. **No Rate Limiting** → 10 req/15 min on auth endpoints
4. **Missing Security Headers** → Helmet.js + CSP
5. **No Request Logging** → Winston logs all requests + errors
6. **JWT No Expiry** → Set to 1 hour
7. **Verbose Error Messages** → Generic "Invalid credentials" response
8. **No Input Length Limits** → Body size capped at 10kb

## Project Structure
```
secured-app/
├── server.js              # Express app, helmet, rate-limit, winston
├── controllers/
│   └── authController.js  # Register/login with bcrypt + JWT
├── middleware/
│   └── auth.js            # JWT verification middleware
├── routes/
│   └── auth.js            # /api/auth/* routes
├── public/
│   └── index.html         # Demo frontend
├── logs/
│   └── security.log       # Auto-generated
└── README.md
```

## Testing the API
```bash
# Register
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","email":"test@example.com","password":"securePass1"}'

# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"securePass1"}'

# Profile (use token from login)
curl http://localhost:3000/api/auth/profile \
  -H "Authorization: Bearer <token>"
```
