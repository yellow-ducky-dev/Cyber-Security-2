require('dotenv').config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const winston = require("winston");
const path = require("path");
const fs = require("fs");

// ─── ENSURE LOGS DIRECTORY EXISTS ────────────────────────────────────
if (!fs.existsSync("logs")) fs.mkdirSync("logs");

const app = express();

// ─── TRUST PROXY ─────────────────────────────────────────────────────
app.set("trust proxy", 1);

// ─── CORS ─────────────────────────────────────────────────────────────
app.use(cors({ origin: "*", methods: ["GET", "POST"] }));

// ─── IP EXTRACTION (MUST BE FIRST) ───────────────────────────────────
app.use((req, res, next) => {
  const forwarded = req.headers["x-forwarded-for"];
  const raw = forwarded ? forwarded.split(",")[0].trim() : req.socket?.remoteAddress || req.ip || "unknown";
  req.clientIp = raw.replace("::ffff:", "");
  next();
});

// ─── LOGGER (Winston) ────────────────────────────────────────────────
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `[${timestamp}] ${level.toUpperCase()}: ${message}`),
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: "logs/security.log",
      lazy: false,
      options: { flags: "a" },
    }),
  ],
});

logger.on("error", (err) => console.error("Logger error:", err));
process.on("exit", () => logger.end());

// ─── REQUEST LOGGING ─────────────────────────────────────────────────
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - IP: ${req.clientIp}`);
  next();
});

// ─── SECURITY HEADERS (Helmet) ───────────────────────────────────────
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
  max: 10,
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
