require('dotenv').config();

const bcrypt    = require('bcrypt');
const jwt       = require('jsonwebtoken');
const validator = require('validator');
const logger    = require('../logger');

// In-memory user store (replace with DB in production)
const users = new Map();

const SALT_ROUNDS  = 10;
const JWT_SECRET   = process.env.JWT_SECRET || 'change-this-in-production-use-env';
const JWT_EXPIRES  = '1h';

// ─── HELPERS ──────────────────────────────────────────────────────────────────

function sanitize(str) {
  // Strip HTML tags and trim whitespace
  return validator.escape(validator.trim(str || ''));
}

function issueToken(userId, username) {
  return jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

// ─── REGISTER ─────────────────────────────────────────────────────────────────

exports.register = async (req, res) => {
  try {
    const email    = sanitize(req.body.email    || '');
    const username = sanitize(req.body.username || '');
    const password = req.body.password || ''; // don't escape password before hashing

    // Input validation
    if (!validator.isEmail(email))
      return res.status(400).json({ error: 'Invalid email address.' });

    if (!validator.isAlphanumeric(username) || username.length < 3 || username.length > 30)
      return res.status(400).json({ error: 'Username must be 3-30 alphanumeric characters.' });

    if (password.length < 8)
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    if (users.has(username))
      return res.status(409).json({ error: 'Username already taken.' });

    // Hash password with bcrypt (cost factor 10)
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const userId = Date.now().toString();
    users.set(username, { id: userId, username, email, password: hashedPassword });

    const token = issueToken(userId, username);
    logger.info(`User registered successfully - Username: ${username} - IP: ${req.clientIp || 'unknown'}`);
    return res.status(201).json({ message: 'Registration successful.', token });

  } catch (err) {
    logger.error(`Registration failed: ${err.message}`);
    return res.status(500).json({ error: 'Registration failed.' });
  }
};

// ─── LOGIN ────────────────────────────────────────────────────────────────────

exports.login = async (req, res) => {
  try {
    const username = sanitize(req.body.username || '');
    const password = req.body.password || '';

    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required.' });

    const user = users.get(username);
    if (!user) {
      logger.warn(`Login failed - IP: ${req.clientIp || 'unknown'} - Username: ${username} (User not found)`);
      // Generic message — don't reveal whether username exists
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      logger.warn(`Login failed - IP: ${req.clientIp || 'unknown'} - Username: ${username} (Incorrect password)`);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = issueToken(user.id, user.username);
    logger.info(`Login successful - Username: ${user.username} - IP: ${req.clientIp || 'unknown'}`);
    return res.status(200).json({ message: 'Login successful.', token });

  } catch (err) {
    logger.error(`Login error: ${err.message}`);
    return res.status(500).json({ error: 'Login failed.' });
  }
};

// ─── PROFILE (protected) ──────────────────────────────────────────────────────

exports.profile = (req, res) => {
  const { id, username } = req.user; // set by auth middleware
  res.json({ id, username });
};
