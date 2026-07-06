const fs = require('fs');
const path = require('path');
const blockedIpsFile = path.join(__dirname, '..', 'blocked-ips.json');

// Memory cache for blocked IPs
let blockedIps = {};

function loadBlockedIps() {
  try {
    if (fs.existsSync(blockedIpsFile)) {
      const data = fs.readFileSync(blockedIpsFile, 'utf8');
      blockedIps = JSON.parse(data || '{}');
      
      // Clean up expired bans
      const now = Date.now();
      let modified = false;
      for (const ip in blockedIps) {
        if (blockedIps[ip] < now) {
          delete blockedIps[ip];
          modified = true;
        }
      }
      if (modified) {
        fs.writeFileSync(blockedIpsFile, JSON.stringify(blockedIps, null, 2), 'utf8');
      }
    }
  } catch (err) {
    console.error('Failed to load blocked-ips.json:', err.message);
  }
}

// Initial load
loadBlockedIps();

// Reload every 10 seconds to sync with monitor.js
setInterval(loadBlockedIps, 10000);

module.exports = function ipBlocker(req, res, next) {
  const clientIp = req.clientIp || req.ip || 'unknown';
  
  // Clean ip formatting (strip ipv6 mappings if needed, but monitor.js strips it too)
  const cleanIp = clientIp.replace('::ffff:', '');
  
  // Check if IP is banned
  const banExpiry = blockedIps[cleanIp];
  if (banExpiry) {
    if (banExpiry > Date.now()) {
      return res.status(403).json({ 
        error: 'Forbidden', 
        message: 'Your IP has been temporarily banned due to multiple suspicious activities.' 
      });
    } else {
      // Ban expired, remove it
      delete blockedIps[cleanIp];
      try {
        fs.writeFileSync(blockedIpsFile, JSON.stringify(blockedIps, null, 2), 'utf8');
      } catch (err) {
        console.error('Failed to update blocked-ips.json:', err.message);
      }
    }
  }
  
  next();
};
