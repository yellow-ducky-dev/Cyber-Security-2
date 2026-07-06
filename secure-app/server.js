require('dotenv').config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const logger = require("./logger");
const ipBlocker = require("./middleware/ipBlocker");
const apiKeyAuth = require("./middleware/apiKeyAuth");

const app = express();

// ─── TRUST PROXY ─────────────────────────────────────────────────────
app.set("trust proxy", 1);

// ─── IP EXTRACTION (MUST BE FIRST) ───────────────────────────────────
app.use((req, res, next) => {
  const forwarded = req.headers["x-forwarded-for"];
  const raw = forwarded ? forwarded.split(",")[0].trim() : req.socket?.remoteAddress || req.ip || "unknown";
  req.clientIp = raw.replace("::ffff:", "");
  next();
});

// ─── IP BLOCKER (IDS INTEGRATION) ────────────────────────────────────
app.use(ipBlocker);

// ─── CORS ─────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:8080,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:8080,http://127.0.0.1:3001').split(',').map(o => o.trim());
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or standard API clients)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ["GET", "POST"],
  credentials: true
}));

// ─── REQUEST LOGGING ─────────────────────────────────────────────────
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - IP: ${req.clientIp}`);
  next();
});

// ─── SECURITY HEADERS (Helmet & HSTS) ──────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        scriptSrcAttr: ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"], // ← this allows fetch() calls
      },
    },
    hsts: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true
    }
  }),
);

// ─── BODY PARSING ────────────────────────────────────────────────────
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// ─── STATIC FILES ────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ─── RATE LIMITING ───────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Tightened from 10 to 5
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
  message: { error: "Too many login attempts. Try again in 15 minutes." },
  handler: (req, res, next, options) => {
    logger.warn(`Rate limit hit: ${req.clientIp} on ${req.path}`);
    res.status(429).json(options.message);
  },
});

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { xForwardedForHeader: false },
});

app.use(globalLimiter);

// ─── SECURED API KEY ENDPOINT ────────────────────────────────────────
app.get("/api/secure-data", apiKeyAuth, (req, res) => {
  res.json({
    message: "This is a secured API endpoint accessible only with a valid API key.",
    timestamp: new Date().toISOString(),
    data: {
      status: "secure",
      message: "Zero-Trust API keys enforce machine-to-machine validation."
    }
  });
});

// ─── ROUTES ──────────────────────────────────────────────────────────
const authRoutes = require("./routes/auth");
app.use("/api/auth", loginLimiter, authRoutes);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─── GLOBAL ERROR HANDLER ────────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`);
  res.status(500).json({ error: "Internal server error" });
});

// ─── START SERVER ────────────────────────────────────────────────────
const PORT = process.env.PORT || 8080;
app.listen(PORT, "0.0.0.0", () => logger.info(`Secured app running on port ${PORT}`));

module.exports = { app, logger };
