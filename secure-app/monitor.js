const fs = require('fs');
const path = require('path');

const logFile = path.join(__dirname, 'logs', 'security.log');
const alertsFile = path.join(__dirname, 'logs', 'alerts.log');
const blockedIpsFile = path.join(__dirname, 'blocked-ips.json');

const FAILED_LOGIN_THRESHOLD = 5;
const SLIDING_WINDOW_MS = 60 * 1000; // 1 minute
const BAN_DURATION_MS = 5 * 60 * 1000; // 5 minutes

let logFilePointer = 0;
const failureCounters = {}; // Schema: { ip: [timestamp1, timestamp2, ...] }

// Ensure files/folders exist
if (!fs.existsSync(path.join(__dirname, 'logs'))) {
  fs.mkdirSync(path.join(__dirname, 'logs'));
}
if (!fs.existsSync(blockedIpsFile)) {
  fs.writeFileSync(blockedIpsFile, '{}', 'utf8');
}

function getBlockedIps() {
  try {
    const data = fs.readFileSync(blockedIpsFile, 'utf8');
    return JSON.parse(data || '{}');
  } catch (err) {
    console.error('Error reading blocked IPs file:', err);
    return {};
  }
}

function saveBlockedIps(blocked) {
  try {
    fs.writeFileSync(blockedIpsFile, JSON.stringify(blocked, null, 2), 'utf8');
  } catch (err) {
    console.error('Error saving blocked IPs file:', err);
  }
}

function triggerAlert(ip, reason) {
  const timestamp = new Date().toISOString();
  const alertMsg = `[${timestamp}] ALERT - INTRUSION DETECTED: IP ${ip} banned. Reason: ${reason}\n`;
  console.log(`\x1b[41m\x1b[37m${alertMsg.trim()}\x1b[0m`);
  
  try {
    fs.appendFileSync(alertsFile, alertMsg, 'utf8');
  } catch (err) {
    console.error('Error writing to alerts log:', err);
  }
}

function blockIp(ip, reason) {
  const blocked = getBlockedIps();
  const expiry = Date.now() + BAN_DURATION_MS;
  blocked[ip] = expiry;
  saveBlockedIps(blocked);
  triggerAlert(ip, reason);
}

function parseLogLine(line) {
  // Regex to extract IP and message
  // Example lines:
  // [2026-07-06T00:00:00.000Z] WARN: Login failed - IP: 127.0.0.1
  // [2026-07-06T00:00:00.000Z] WARN: Rate limit hit: 127.0.0.1 on /api/auth/login
  
  if (line.includes('WARN: Login failed')) {
    const match = line.match(/IP:\s*([0-9a-fA-F.:]+)/);
    if (match) {
      registerFailure(match[1], 'Multiple failed login attempts');
    }
  } else if (line.includes('WARN: Rate limit hit')) {
    const match = line.match(/Rate limit hit:\s*([0-9a-fA-F.:]+)/);
    if (match) {
      registerFailure(match[1], 'Exceeded speed limits / API abuse');
    }
  }
}

function registerFailure(ip, reason) {
  const cleanIp = ip.replace('::ffff:', '');
  const now = Date.now();
  
  if (!failureCounters[cleanIp]) {
    failureCounters[cleanIp] = [];
  }
  
  // Add current event timestamp
  failureCounters[cleanIp].push(now);
  
  // Filter out older than the sliding window
  failureCounters[cleanIp] = failureCounters[cleanIp].filter(ts => now - ts < SLIDING_WINDOW_MS);
  
  const currentBlocked = getBlockedIps();
  if (currentBlocked[cleanIp] && currentBlocked[cleanIp] > now) {
    // Already blocked
    return;
  }
  
  if (failureCounters[cleanIp].length >= FAILED_LOGIN_THRESHOLD) {
    blockIp(cleanIp, `${reason} (${failureCounters[cleanIp].length} attempts in 1 min)`);
    delete failureCounters[cleanIp]; // clear once blocked
  }
}

// Start watching the file
function startMonitoring() {
  console.log(`🔍 [Intrusion Detection System] Monitoring security.log at ${logFile}...`);
  
  // Set pointer to the end of the file when starting so we only read new lines
  if (fs.existsSync(logFile)) {
    const stats = fs.statSync(logFile);
    logFilePointer = stats.size;
  }
  
  setInterval(() => {
    try {
      if (!fs.existsSync(logFile)) return;
      
      const stats = fs.statSync(logFile);
      if (stats.size > logFilePointer) {
        // Read new content
        const fd = fs.openSync(logFile, 'r');
        const bufferSize = stats.size - logFilePointer;
        const buffer = Buffer.alloc(bufferSize);
        
        fs.readSync(fd, buffer, 0, bufferSize, logFilePointer);
        fs.closeSync(fd);
        
        logFilePointer = stats.size;
        
        const newText = buffer.toString('utf8');
        const lines = newText.split(/\r?\n/);
        
        for (const line of lines) {
          if (line.trim()) {
            parseLogLine(line);
          }
        }
      } else if (stats.size < logFilePointer) {
        // File was truncated or rolled over
        logFilePointer = stats.size;
      }
    } catch (err) {
      console.error('Error tailing log file:', err);
    }
  }, 1000);
}

startMonitoring();
