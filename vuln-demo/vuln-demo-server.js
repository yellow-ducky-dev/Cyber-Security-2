const express = require('express');
const md5 = require('md5');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// In-memory "database" with MD5 hashed passwords
const users = [
  { id: 1, username: 'admin',    password: md5('admin123'),  email: 'admin@site.com',  role: 'admin' },
  { id: 2, username: 'alice',    password: md5('alice2024'), email: 'alice@site.com',  role: 'user'  },
  { id: 3, username: 'bob',      password: md5('bob1234'),   email: 'bob@site.com',    role: 'user'  },
];

// ─── VULNERABILITY 1: No security headers (no helmet) ────────────────────────
// Nothing added — default Express headers are weak

// ─── PAGES ───────────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.send(homePage()));
app.get('/login', (req, res) => res.send(loginPage('')));
app.get('/register', (req, res) => res.send(registerPage('')));
app.get('/search', (req, res) => {
  // VULNERABILITY 2: Reflected XSS — query param rendered directly in HTML
  const query = req.query.q || '';
  res.send(searchPage(query));
});

// VULNERABILITY 3: SQL-style injection simulation (insecure string comparison)
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULN: No input sanitization, verbose error messages
  const user = users.find(u => u.username === username);
  if (!user) {
    // Verbose: tells attacker the username doesn't exist
    return res.send(loginPage(`<span style="color:#ef4444">❌ Username "${username}" not found.</span>`));
  }
  if (user.password !== md5(password)) {
    // Verbose: tells attacker username is correct but password is wrong
    return res.send(loginPage(`<span style="color:#ef4444">❌ Wrong password for "${username}".</span>`));
  }
  // No JWT, no session expiry — just a plain cookie with username
  res.setHeader('Set-Cookie', `user=${username}; Path=/`);
  res.redirect('/dashboard');
});

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  // VULN: No validation — accepts empty, special chars, anything
  // VULN: MD5 password hashing
  users.push({ id: Date.now(), username, email, password: md5(password), role: 'user' });
  res.send(registerPage(`<span style="color:#22c55e">✅ Registered! Password stored as MD5: <code style="background:#1e293b;padding:2px 6px;border-radius:4px">${md5(password)}</code></span>`));
});

app.get('/dashboard', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/user=([^;]+)/);
  if (!match) return res.redirect('/login');
  const username = match[1];
  const user = users.find(u => u.username === username);
  res.send(dashboardPage(user || { username, role: 'unknown' }));
});

// VULNERABILITY 4: IDOR — access any user's data by changing the ID
app.get('/api/user/:id', (req, res) => {
  const user = users.find(u => u.id == req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  // Returns password hash too — information disclosure
  res.json(user);
});

// VULNERABILITY 5: No rate limiting on login
app.post('/api/brute-test', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === md5(password));
  res.json({ success: !!user, message: user ? `Cracked! User: ${user.username}` : 'Wrong password' });
});

app.listen(3001, () => console.log('🚨 VULNERABLE app running on http://localhost:3001'));

// ─── HTML TEMPLATES ──────────────────────────────────────────────────────────
function layout(title, body) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${title} — VulnApp</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
    .topbar{background:#7f1d1d;padding:12px 24px;display:flex;align-items:center;gap:12px;border-bottom:2px solid #ef4444}
    .topbar h1{font-size:1rem;color:#fca5a5;font-weight:700}
    .badge{background:#ef4444;color:white;font-size:0.7rem;padding:2px 8px;border-radius:999px;font-weight:700}
    nav{background:#1e293b;padding:10px 24px;display:flex;gap:16px;border-bottom:1px solid #334155}
    nav a{color:#94a3b8;text-decoration:none;font-size:0.85rem;padding:4px 10px;border-radius:6px;transition:all .2s}
    nav a:hover{background:#334155;color:#e2e8f0}
    .container{max-width:960px;margin:0 auto;padding:32px 24px}
    .card{background:#1e293b;border-radius:12px;padding:24px;border:1px solid #334155;margin-bottom:20px}
    .card h2{font-size:1.1rem;margin-bottom:16px;color:#f8fafc}
    label{display:block;font-size:0.78rem;color:#94a3b8;margin-bottom:4px;margin-top:12px}
    input{width:100%;padding:8px 12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:0.9rem;outline:none}
    input:focus{border-color:#3b82f6}
    .btn{display:inline-block;margin-top:14px;padding:8px 20px;background:#3b82f6;color:white;border:none;border-radius:8px;font-size:0.9rem;font-weight:600;cursor:pointer;text-decoration:none}
    .btn-red{background:#ef4444}
    .btn-green{background:#16a34a}
    .vuln-box{background:#2d0a0a;border:1px solid #7f1d1d;border-radius:8px;padding:14px;margin-top:16px}
    .vuln-box h4{color:#f87171;font-size:0.8rem;margin-bottom:6px}
    .vuln-box p{color:#fca5a5;font-size:0.78rem;line-height:1.6}
    code{background:#0f172a;color:#a5f3fc;padding:1px 6px;border-radius:4px;font-size:0.82rem}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
    .msg{margin-top:10px;font-size:0.85rem}
    table{width:100%;border-collapse:collapse;font-size:0.82rem}
    th{background:#0f172a;color:#94a3b8;padding:8px 12px;text-align:left;border-bottom:1px solid #334155}
    td{padding:8px 12px;border-bottom:1px solid #1e293b;color:#cbd5e1}
    .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:0.7rem;font-weight:700}
    .tag-red{background:#7f1d1d;color:#fca5a5}
    .tag-yellow{background:#78350f;color:#fcd34d}
    .tag-green{background:#14532d;color:#86efac}
  </style></head><body>
  <div class="topbar">
    <h1>⚠️ VULNERABLE DEMO APPLICATION</h1>
    <span class="badge">FOR SECURITY TESTING ONLY</span>
  </div>
  <nav>
    <a href="/">🏠 Home</a>
    <a href="/login">🔑 Login</a>
    <a href="/register">📝 Register</a>
    <a href="/search?q=hello">🔍 Search (XSS)</a>
    <a href="/api/user/1">👤 User API (IDOR)</a>
    <a href="/dashboard">📊 Dashboard</a>
  </nav>
  <div class="container">${body}</div>
</body></html>`;
}

function homePage() {
  return layout('Home', `
    <h2 style="color:#f87171;margin-bottom:8px">🚨 Vulnerable Web Application</h2>
    <p style="color:#94a3b8;margin-bottom:24px;font-size:0.9rem">This app intentionally contains real security vulnerabilities for demonstration and testing purposes.</p>
    <div class="grid">
      <div class="card">
        <h2>🐛 Vulnerabilities in This App</h2>
        <table>
          <tr><th>ID</th><th>Vulnerability</th><th>Severity</th></tr>
          <tr><td>V1</td><td>Reflected XSS</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
          <tr><td>V2</td><td>MD5 Password Hashing</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
          <tr><td>V3</td><td>Verbose Error Messages</td><td><span class="tag tag-yellow">MEDIUM</span></td></tr>
          <tr><td>V4</td><td>IDOR — Insecure Direct Object Reference</td><td><span class="tag tag-red">HIGH</span></td></tr>
          <tr><td>V5</td><td>No Rate Limiting</td><td><span class="tag tag-yellow">MEDIUM</span></td></tr>
          <tr><td>V6</td><td>Missing Security Headers</td><td><span class="tag tag-yellow">MEDIUM</span></td></tr>
          <tr><td>V7</td><td>No Input Validation</td><td><span class="tag tag-red">HIGH</span></td></tr>
          <tr><td>V8</td><td>Information Disclosure in API</td><td><span class="tag tag-red">HIGH</span></td></tr>
        </table>
      </div>
      <div class="card">
        <h2>🧪 How to Test Each One</h2>
        <table>
          <tr><th>Attack</th><th>Where</th></tr>
          <tr><td>XSS</td><td><a href="/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;" style="color:#60a5fa">/search page</a></td></tr>
          <tr><td>Verbose Error</td><td><a href="/login" style="color:#60a5fa">/login page</a></td></tr>
          <tr><td>IDOR</td><td><a href="/api/user/1" style="color:#60a5fa">/api/user/1, 2, 3</a></td></tr>
          <tr><td>MD5 Exposed</td><td><a href="/register" style="color:#60a5fa">/register page</a></td></tr>
          <tr><td>No Headers</td><td>Dev Tools → Network tab</td></tr>
          <tr><td>Brute Force</td><td>PowerShell loop test</td></tr>
        </table>
        <div style="margin-top:16px">
          <a href="/login" class="btn">Start Testing →</a>
        </div>
      </div>
    </div>
  `);
}

function loginPage(msg) {
  return layout('Login', `
    <div class="card" style="max-width:420px">
      <h2>🔑 Login</h2>
      <form method="POST" action="/login">
        <label>Username</label>
        <input name="username" placeholder="Try: admin">
        <label>Password</label>
        <input name="password" type="password" placeholder="Try: wrongpassword">
        <button class="btn" type="submit">Login</button>
      </form>
      <div class="msg">${msg}</div>
      <div class="vuln-box">
        <h4>⚠️ VULNERABILITIES HERE</h4>
        <p><b>V3 — Verbose Errors:</b> Try username <code>admin</code> with wrong password. The error message reveals whether the username exists.<br><br>
        <b>V5 — No Rate Limit:</b> You can attempt login unlimited times. No lockout.</p>
      </div>
    </div>
    <div class="card" style="max-width:420px;margin-top:0">
      <h2>📋 Test Credentials</h2>
      <table>
        <tr><th>Username</th><th>Password</th><th>Role</th></tr>
        <tr><td>admin</td><td>admin123</td><td><span class="tag tag-red">admin</span></td></tr>
        <tr><td>alice</td><td>alice2024</td><td><span class="tag tag-green">user</span></td></tr>
        <tr><td>bob</td><td>bob1234</td><td><span class="tag tag-green">user</span></td></tr>
      </table>
    </div>
  `);
}

function registerPage(msg) {
  return layout('Register', `
    <div class="card" style="max-width:420px">
      <h2>📝 Register</h2>
      <form method="POST" action="/register">
        <label>Username</label>
        <input name="username" placeholder="Any username (no validation!)">
        <label>Email</label>
        <input name="email" placeholder="not-even-an-email works">
        <label>Password</label>
        <input name="password" type="password" placeholder="Any password">
        <button class="btn btn-green" type="submit">Register</button>
      </form>
      <div class="msg">${msg}</div>
      <div class="vuln-box">
        <h4>⚠️ VULNERABILITIES HERE</h4>
        <p><b>V2 — MD5 Hashing:</b> After registering, your MD5 hash is shown. MD5 can be cracked instantly using online tools.<br><br>
        <b>V7 — No Validation:</b> Try entering <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> as username or a fake email.</p>
      </div>
    </div>
  `);
}

function searchPage(query) {
  return layout('Search', `
    <div class="card">
      <h2>🔍 Search Users</h2>
      <form method="GET" action="/search">
        <label>Search Query</label>
        <input name="q" value="${query}" placeholder="Enter search term...">
        <button class="btn" type="submit">Search</button>
      </form>
      <!-- VULNERABILITY: query rendered without sanitization -->
      <div style="margin-top:16px;padding:12px;background:#0f172a;border-radius:8px;color:#94a3b8;font-size:0.9rem">
        Search results for: <strong style="color:#e2e8f0">${query}</strong>
      </div>
      <div class="vuln-box">
        <h4>⚠️ V1 — REFLECTED XSS</h4>
        <p>The search query is rendered directly in HTML with no sanitization.<br><br>
        <b>Test it:</b> Click this link or paste in browser URL bar:<br>
        <code>/search?q=&lt;img src=x onerror=alert('XSS-ATTACK')&gt;</code><br><br>
        Or try: <code>/search?q=&lt;b style="color:red"&gt;INJECTED HTML&lt;/b&gt;</code></p>
      </div>
    </div>
  `);
}

function dashboardPage(user) {
  return layout('Dashboard', `
    <div class="card">
      <h2>📊 Dashboard — Welcome, ${user.username}!</h2>
      <p style="color:#94a3b8;margin-bottom:16px">Role: <span class="tag ${user.role==='admin'?'tag-red':'tag-green'}">${user.role}</span></p>
      <p style="color:#94a3b8;font-size:0.85rem">You are logged in. Notice: no session expiry, no HTTPS, cookie has no HttpOnly flag.</p>
    </div>
    <div class="card">
      <h2>🔓 V4 — IDOR: Access Any User's Data</h2>
      <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:12px">The API exposes all user data including password hashes. Change the ID in the URL:</p>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <a href="/api/user/1" class="btn btn-red">User ID: 1 (admin)</a>
        <a href="/api/user/2" class="btn">User ID: 2 (alice)</a>
        <a href="/api/user/3" class="btn">User ID: 3 (bob)</a>
      </div>
    </div>
  `);
}
