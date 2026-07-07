# Social Engineering Awareness — Phishing Simulation Report

**Date:** July 7, 2026  
**Simulated Attacker:** Bob (malicious insider / external threat actor)  
**Target:** Alice (authenticated user with $100 wallet balance)

---

## 1. Attack Scenario

### Scenario: Phishing Page ("Win Free Dollars!")

Bob creates a page at `/csrf-trap` styled as a prize giveaway to trick Alice into visiting it while logged into the application.

**Page content:**
```
🎁 Congratulations! You Won Free Dollars! 🎁
Processing your transfer parameters...
Do NOT close this tab.
```

Behind the scenes, the page auto-submits a hidden HTML form after 1.5 seconds:

```html
<form id="csrfForm" action="/transfer" method="POST">
  <input type="hidden" name="toUser" value="bob" />
  <input type="hidden" name="amount" value="50.00" />
</form>
<script>
  setTimeout(() => document.getElementById('csrfForm').submit(), 1500);
</script>
```

---

## 2. Attack Execution

### Step-by-step:
1. Alice logs into the vulnerable app (port 3001) as `alice / alice2024`.
2. Alice receives a link in a chat message: `"Click here to claim your reward!"`
3. Alice visits `/csrf-trap` while her browser still holds the session cookie `user=alice`.
4. The page auto-submits the form after 1.5 seconds.
5. The browser includes the session cookie automatically — the server sees it as a legitimate request.

### Result on Vulnerable App (Port 3001):
- ✅ Transfer of **$50 from Alice → Bob** executes silently.
- Alice is redirected to her dashboard showing reduced balance: **$50.00**.
- Alice never consented to or initiated the transaction.

### Result on Remediated App (Port 3002):
- ❌ Transfer **rejected with `403 Forbidden`**.
- The `csrf-csrf` middleware detects no valid CSRF token in the forged request.
- Alice's balance is unchanged.

---

## 3. Social Engineering Indicators (User Awareness Training)

Users should be trained to recognise these red flags:

| Indicator | Description |
|-----------|-------------|
| 🎁 Prize / urgency language | "You won!", "Claim now!", "Do not close this tab" |
| Auto-redirecting pages | Page loads then immediately moves without user action |
| Requests made to unfamiliar domains | URL in address bar doesn't match the service being used |
| Suspicious links in chat or email | Links from unknown senders or unexpected sources |
| Balance or state changes after browsing | Funds missing, settings changed after visiting an external page |

---

## 4. Countermeasures Implemented

| Countermeasure | Where | How It Helps |
|---------------|-------|--------------|
| CSRF double-submit tokens | `csrf-csrf` middleware | Forged requests lack the token → 403 |
| `SameSite=Lax` cookies | Session cookie flags | Browser won't send cookie on cross-site top-level POST |
| CORS allowlist | `server.js` | Prevents malicious origins from making API calls |
| Security awareness training | This report | Educates users to recognise phishing attempts |

---

## 5. Recommendations

1. **Deploy CSRF tokens on all state-changing routes** in production apps.
2. **Set cookies to `SameSite=Strict`** where login session cross-site navigation is not needed.
3. **Conduct phishing simulations quarterly** to measure employee awareness.
4. **Implement email / link-scanning tools** to flag suspicious URLs before users click.
