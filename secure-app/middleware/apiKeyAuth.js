require('dotenv').config();

module.exports = function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'Unauthorized', message: 'API key is required in the x-api-key header.' });
  }

  // Load valid keys from env
  const validKeysEnv = process.env.API_KEYS || 'dev-key-12345,admin-api-key-999';
  const validKeys = validKeysEnv.split(',').map(key => key.trim());

  if (!validKeys.includes(apiKey)) {
    return res.status(403).json({ error: 'Forbidden', message: 'Invalid API key.' });
  }

  next();
};
