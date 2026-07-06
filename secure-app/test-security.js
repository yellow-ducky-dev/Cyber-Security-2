const http = require('http');
const fs = require('fs');
const path = require('path');

const TARGET_URL = 'http://localhost:3000';

async function makeRequest(path, method = 'GET', headers = {}, body = null) {
  return new Promise((resolve) => {
    const postData = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : '';
    
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: method,
      headers: {
        ...headers
      }
    };

    if (body) {
      options.headers['Content-Type'] = 'application/json';
      options.headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: data
        });
      });
    });

    req.on('error', (err) => {
      resolve({
        status: 500,
        headers: {},
        data: 'ERROR: ' + err.message
      });
    });

    if (body) {
      req.write(postData);
    }
    req.end();
  });
}

console.log('🧪 =========================================');
console.log('🧪 SECURITY COMPLIANCE ENGINE: secure-app');
console.log('🧪 =========================================\n');

async function runTests() {
  // --- TEST 1: HELMET HEADERS & HSTS ---
  console.log('🛡️ [Test 1: HTTP Security Headers]');
  const res1 = await makeRequest('/');
  const hasHsts = !!res1.headers['strict-transport-security'];
  const hasCsp = !!res1.headers['content-security-policy'];
  const hasXssFilter = !!res1.headers['x-xss-protection'] || !res1.headers['x-powered-by'];
  
  console.log(`  - HSTS Header (Strict-Transport-Security): ${hasHsts ? '🟢 ACTIVE' : '🔴 MISSING'} (${res1.headers['strict-transport-security'] || 'none'})`);
  console.log(`  - CSP Header (Content-Security-Policy): ${hasCsp ? '🟢 ACTIVE' : '🔴 MISSING'}`);
  console.log(`  - Hide Express Powered-By: ${!res1.headers['x-powered-by'] ? '🟢 SECURED (Hidden)' : '🔴 VULNERABLE (Exposed)'}`);
  console.log();

  // --- TEST 2: CORS DOMAIN RESTRICTIONS ---
  console.log('🛡️ [Test 2: CORS Domain Restrictions]');
  const corsHeadersSafe = { 'Origin': 'http://localhost:3000' };
  const corsHeadersUnsafe = { 'Origin': 'http://attacker-site.com' };
  
  const resSafe = await makeRequest('/api/auth/profile', 'GET', corsHeadersSafe);
  console.log(`  - Approved Origin Request: Status ${resSafe.status} (Expected: 401 Unauthorized for profile, but connection allowed)`);
  
  const resUnsafe = await makeRequest('/api/auth/profile', 'GET', corsHeadersUnsafe);
  const corsBlocked = resUnsafe.data.includes('CORS') || resUnsafe.status === 500; // CORS middleware throws error
  console.log(`  - Malicious Origin Request: Status ${resUnsafe.status} | ${corsBlocked ? '🟢 SECURED (CORS Request Blocked)' : '🔴 VULNERABLE (CORS Allowed)'}`);
  console.log();

  // --- TEST 3: MACHINE-TO-MACHINE API KEY AUTH ---
  console.log('🛡️ [Test 3: API Key Access Validation]');
  const resNoKey = await makeRequest('/api/secure-data');
  console.log(`  - Request without API Key: Status ${resNoKey.status} (Expected: 401) | ${resNoKey.status === 401 ? '🟢 REJECTED' : '🔴 ACCEPTED'}`);

  const resWrongKey = await makeRequest('/api/secure-data', 'GET', { 'x-api-key': 'attacker-1234' });
  console.log(`  - Request with Invalid API Key: Status ${resWrongKey.status} (Expected: 403) | ${resWrongKey.status === 403 ? '🟢 REJECTED' : '🔴 ACCEPTED'}`);

  const resValidKey = await makeRequest('/api/secure-data', 'GET', { 'x-api-key': 'dev-key-12345' });
  const keyAllowed = resValidKey.status === 200 && resValidKey.data.includes('Zero-Trust');
  console.log(`  - Request with Valid API Key: Status ${resValidKey.status} (Expected: 200) | ${keyAllowed ? '🟢 AUTHORIZED' : '🔴 BLOCKED'}`);
  console.log();

  // --- TEST 4: COMPLIANT LOGGING FOR THREAT MONITORING ---
  console.log('🛡️ [Test 4: Threat Log Compliance]');
  // Clear file or check if logs exist
  const logPath = path.join(__dirname, 'logs', 'security.log');
  const logsExist = fs.existsSync(logPath);
  console.log(`  - Log File Existence (logs/security.log): ${logsExist ? '🟢 FOUND' : '🔴 NOT CREATED'}`);
  if (logsExist) {
    const stats = fs.statSync(logPath);
    console.log(`  - Log File Size: ${stats.size} Bytes`);
  }
}

runTests().then(() => {
  console.log('\n=========================================');
  console.log('🧪 SECURITY COMPLIANCE ENGINE RUN COMPLETE');
  console.log('=========================================');
});
