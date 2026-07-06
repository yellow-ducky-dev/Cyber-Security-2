const winston = require('winston');
const fs = require('fs');

if (!fs.existsSync('logs')) {
  fs.mkdirSync('logs');
}

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => `[${timestamp}] ${level.toUpperCase()}: ${message}`)
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({
      filename: 'logs/security.log',
      lazy: false,
      options: { flags: 'a' }
    })
  ]
});

module.exports = logger;
