const express = require('express');
const md5 = require('md5');
const path = require('path');
const fs = require('fs');
const { db, initDatabase } = require('./database');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── PAGES ───────────────────────────────────────────────────────────────────

app.get('/', (req, res) => res.send(homePage()));
app.get('/login', (req, res) => res.send(loginPage('')));
app.get('/register', (req, res) => res.send(registerPage('')));

// VULNERABILITY 2: SQL Injection & Reflected XSS in Search
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  
  if (!query) {
    return res.send(searchPage('', []));
  }

  // VULN: Raw string concatenation in SQL query
  const sql = `SELECT id, username, email, role, balance FROM users WHERE username LIKE '%${query}%' OR email LIKE '%${query}%'`;
  
  db.all(sql, (err, rows) => {
    if (err) {
      return res.send(searchPage(query, [], `<span style="color:#ef4444">❌ SQL Error: <code>${err.message}</code><br>Query executed: <code>${sql}</code></span>`));
    }
    res.send(searchPage(query, rows || []));
  });
});

// VULNERABILITY 3: SQL Injection (insecure string concatenation in login)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const pwdHash = md5(password);

  // VULN: Raw string concatenation - easily bypassed with ' OR '1'='1
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${pwdHash}'`;
  
  db.get(sql, (err, user) => {
    if (err) {
      return res.send(loginPage(`<span style="color:#ef4444">❌ DB Error: <code>${err.message}</code><br>Query executed: <code>${sql}</code></span>`));
    }
    if (!user) {
      // VULN: Verbose messages
      return res.send(loginPage(`<span style="color:#ef4444">❌ Invalid credentials.<br>Query executed: <code>${sql}</code></span>`));
    }
    
    // VULN: Insecure session cookie (no HttpOnly, no Secure)
    res.setHeader('Set-Cookie', `user=${user.username}; Path=/`);
    res.redirect('/dashboard');
  });
});

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  
  // VULN: No input validation
  const sql = `INSERT INTO users (username, password, email, role, balance) VALUES ('${username}', '${md5(password)}', '${email}', 'user', 100.0)`;
  
  db.run(sql, function(err) {
    if (err) {
      return res.send(registerPage(`<span style="color:#ef4444">❌ DB Error: <code>${err.message}</code></span>`));
    }
    res.send(registerPage(`<span style="color:#22c55e">✅ Registered successfully! SQL executed: <code>${sql}</code></span>`));
  });
});

app.get('/dashboard', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/user=([^;]+)/);
  if (!match) return res.redirect('/login');
  
  const username = match[1];
  
  // Get logged in user details
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) {
      return res.redirect('/login');
    }
    
    // Get all users to show in UI
    db.all(`SELECT id, username, role FROM users`, (err, allUsers) => {
      res.send(dashboardPage(user, allUsers || [], req.query.msg || ''));
    });
  });
});

// VULNERABILITY 4: IDOR — access any user's credentials by changing ID in URL
app.get('/api/user/:id', (req, res) => {
  // VULN: Raw parameterized concatenation (which allows sql injection in route) & no access checking
  const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;
  
  db.get(sql, (err, user) => {
    if (err) return res.status(500).json({ error: err.message, query: sql });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // VULN: Exposes hashed password
    res.json(user);
  });
});

// VULNERABILITY 5: CSRF Vulnerable Transfer Route
app.post('/transfer', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/user=([^;]+)/);
  if (!match) return res.status(401).send('<h1>401 Unauthorized</h1>');

  const senderUser = match[1];
  const { toUser, amount } = req.body;
  const amt = parseFloat(amount);

  if (!toUser || isNaN(amt) || amt <= 0) {
    return res.status(400).send('<h1>400 Bad Request: Invalid transfer inputs</h1>');
  }

  // Deduct from sender and add to recipient
  db.get(`SELECT * FROM users WHERE username = ?`, [senderUser], (err, sender) => {
    if (err || !sender) return res.status(500).send('<h1>Sender not found</h1>');
    
    if (sender.balance < amt) {
      return res.redirect(`/dashboard?msg=Insufficient%20funds!%20Your%20balance:%20$${sender.balance}`);
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [toUser], (err, recipient) => {
      if (err || !recipient) {
        return res.redirect(`/dashboard?msg=Recipient%20${toUser}%20not%20found!`);
      }

      // VULN: No CSRF token checking is done on this POST request!
      // Run transfer queries
      db.serialize(() => {
        db.run(`UPDATE users SET balance = balance - ${amt} WHERE username = '${senderUser}'`);
        db.run(`UPDATE users SET balance = balance + ${amt} WHERE username = '${toUser}'`);
        
        console.log(`[CSRF SUCCESS] Transferred $${amt} from ${senderUser} to ${toUser}`);
        res.redirect(`/dashboard?msg=Transferred%20$${amt}%20to%20${toUser}%20successfully.`);
      });
    });
  });
});

// CSRF Attack Demo Page (simulates a site bob hosted)
app.get('/csrf-trap', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Win Free Dollars!</title>
      <style>
        body { font-family: sans-serif; text-align: center; padding-top: 50px; background: #1a052e; color: #ff0055; }
        .gift-box { border: 3px dashed #ff0055; padding: 20px; display: inline-block; border-radius: 12px; }
      </style>
    </head>
    <body>
      <div class="gift-box">
        <h1>🎁 Congratulations! You Won Free Dollars! 🎁</h1>
        <p>Processing your transfer parameters...</p>
        <p>Do NOT close this tab.</p>
      </div>

      <!-- Silent Auto-Submitting Form sending request to vulnerable app domain -->
      <form id="csrfForm" action="/transfer" method="POST">
        <input type="hidden" name="toUser" value="bob" />
        <input type="hidden" name="amount" value="50.00" />
      </form>

      <script>
        // Auto submit the form in 1.5 seconds
        setTimeout(() => {
          document.getElementById('csrfForm').submit();
        }, 1500);
      </script>
    </body>
    </html>
  `);
});

// VULNERABILITY 6: No Rate Limit test
app.post('/api/brute-test', (req, res) => {
  const { username, password } = req.body;
  const pwdHash = md5(password);
  
  db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, pwdHash], (err, row) => {
    res.json({ success: !!row, message: row ? `Cracked! User: ${row.username}` : 'Wrong password' });
  });
});

// ─── RUN SERVER ──────────────────────────────────────────────────────────────
initDatabase().then(() => {
  const PORT = 3001;
  app.listen(PORT, () => {
    console.log(`🚨 VULNERABLE app running on http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error("Database initialization failed", err);
});

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
    <a href="/search?q=hello">🔍 Search (SQLi & XSS)</a>
    <a href="/api/user/1">👤 User API (IDOR + SQLi)</a>
    <a href="/dashboard">📊 Dashboard</a>
  </nav>
  <div class="container">${body}</div>
 </body></html>`;
}

function homePage() {
  return layout('Home', `
    <h2 style="color:#f87171;margin-bottom:8px">🚨 Vulnerable Web Application</h2>
    <p style="color:#94a3b8;margin-bottom:24px;font-size:0.9rem">This app intentionally contains real SQLite security vulnerabilities for demonstration and testing purposes.</p>
    <div class="grid">
      <div class="card">
        <h2>🐛 Vulnerabilities in This App</h2>
        <table>
          <tr><th>ID</th><th>Vulnerability</th><th>Severity</th></tr>
          <tr><td>V1</td><td>Reflected XSS (Search Field)</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
          <tr><td>V2</td><td>SQL Injection (Search & Login)</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
          <tr><td>V3</td><td>MD5 Password Weak Hashing</td><td><span class="tag tag-red">CRITICAL</span></td></tr>
          <tr><td>V4</td><td>IDOR & Info Disclosure</td><td><span class="tag tag-red">HIGH</span></td></tr>
          <tr><td>V5</td><td>Cross-Site Request Forgery (CSRF)</td><td><span class="tag tag-red">HIGH</span></td></tr>
          <tr><td>V6</td><td>No Rate Limiting & Verbose Errors</td><td><span class="tag tag-yellow">MEDIUM</span></td></tr>
        </table>
      </div>
      <div class="card">
        <h2>🧪 How to Test Each One</h2>
        <table>
          <tr><th>Attack</th><th>Where</th></tr>
          <tr><td>SQLi Login Bypass</td><td>Use Username: <code>admin' --</code> and any password on <a href="/login" style="color:#60a5fa">Login Page</a></td></tr>
          <tr><td>SQLi Union Dump</td><td>Use Search: <code>admin' UNION SELECT 1,username,password,email,role,balance FROM users--</code> on <a href="/search?q=admin" style="color:#60a5fa">Search</a></td></tr>
          <tr><td>XSS script run</td><td>Visit <a href="/search?q=<script>alert('XSS')</script>" style="color:#60a5fa">/search XSS</a></td></tr>
          <tr><td>CSRF Exploitation</td><td>Login as <code>alice</code>, then open <a href="/csrf-trap" style="color:#60a5fa">/csrf-trap (simulates malicious site)</a></td></tr>
          <tr><td>IDOR API Leak</td><td>Visit IDOR route <a href="/api/user/1" style="color:#60a5fa">/api/user/1</a> (alter 1 to 2, 3...)</td></tr>
        </table>
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
        <input name="username" placeholder="Try: admin' --">
        <label>Password</label>
        <input name="password" type="password" placeholder="Any password for bypass">
        <button class="btn" type="submit">Login</button>
      </form>
      <div class="msg">${msg}</div>
      <div class="vuln-box">
        <h4>⚠️ VULNERABILITIES HERE</h4>
        <p><b>SQL Injection Login Bypass:</b> Submit <code>admin' --</code> as the username with empty password. The server concatenates this to SQL which bypasses authorization checks.</p>
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
    </div>
  `);
}

function searchPage(query, rows, errorMsg = '') {
  let tableRows = '';
  if (rows && rows.length > 0) {
    tableRows = rows.map(r => `
      <tr>
        <td>${r.id}</td>
        <td>${r.username}</td>
        <td>${r.email}</td>
        <td>${r.role}</td>
        <td>$${r.balance || 0}</td>
      </tr>
    `).join('');
  } else if (query) {
    tableRows = `<tr><td colspan="5">No users found.</td></tr>`;
  }

  const resultsTable = query ? `
    <table style="margin-top: 16px;">
      <thead>
        <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Balance</th></tr>
      </thead>
      <tbody>
        ${tableRows}
      </tbody>
    </table>
  ` : '';

  return layout('Search', `
    <div class="card">
      <h2>🔍 Search Users (SQLi & XSS Vulnerable)</h2>
      <form method="GET" action="/search">
        <label>Search Query</label>
        <input name="q" value="${query}" placeholder="Enter search term...">
        <button class="btn" type="submit">Search</button>
      </form>
      
      <div style="margin-top:16px;padding:12px;background:#0f172a;border-radius:8px;color:#94a3b8;font-size:0.9rem">
        Search query input: <strong style="color:#e2e8f0">${query}</strong>
      </div>
      
      ${errorMsg}
      ${resultsTable}

      <div class="vuln-box">
        <h4>⚠️ V1 & V2 — XSS & SQL INJECTION MATCH</h4>
        <p><b>1. Reflected XSS:</b> Input <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> inside the box to trigger scripts.<br>
        <b>2. SQL Injection UNION Attack:</b> Input <code>alice' UNION SELECT 1,username,password,email,role,balance FROM users--</code> to dump all MD5 passwords directly in the UI table!</p>
      </div>
    </div>
  `);
}

function dashboardPage(user, allUsers, message = '') {
  let userRows = allUsers.map(u => `
    <tr>
      <td>${u.id}</td>
      <td>${u.username}</td>
      <td>${u.role}</td>
    </tr>
  `).join('');

  return layout('Dashboard', `
    <div class="card">
      <h2>📊 Dashboard — Welcome, ${user.username}!</h2>
      <p style="color:#22c55e;font-weight:bold;margin:10px 0">${message}</p>
      <p style="color:#cbd5e1;font-size:1.1rem;margin-bottom:8px">Your Wallet Balance: <strong style="color:#fcd34d">$${user.balance.toFixed(2)}</strong></p>
      <p style="color:#94a3b8;font-size:0.85rem">Logged in as: <span class="tag ${user.role==='admin'?'tag-red':'tag-green'}">${user.role}</span></p>
    </div>

    <div class="grid">
      <div class="card">
        <h2>💸 Transfer Funds (CSRF Vulnerable)</h2>
        <form method="POST" action="/transfer">
          <label>Recipient Username</label>
          <input name="toUser" placeholder="e.g. bob" required>
          <label>Amount ($)</label>
          <input name="amount" type="number" step="0.01" min="0.01" placeholder="e.g. 50.00" required>
          <button class="btn btn-green" type="submit">Verify & Transfer</button>
        </form>
        <div class="vuln-box" style="margin-top:20px">
          <h4>⚠️ V5 — CSRF WARNING</h4>
          <p>No anti-CSRF token exists on this transfer request. A hacker on a third-party website can force your browser to submit a fund transfer request without your consent.</p>
        </div>
      </div>

      <div class="card">
        <h2>👥 Available Users in System</h2>
        <table>
          <thead>
            <tr><th>User ID</th><th>Username</th><th>Role</th></tr>
          </thead>
          <tbody>
            ${userRows}
          </tbody>
        </table>
      </div>
    </div>
  `);
}
