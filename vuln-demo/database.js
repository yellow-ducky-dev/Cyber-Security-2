const sqlite3 = require('sqlite3').verbose();
const md5 = require('md5');
const path = require('path');
const dbPath = path.join(__dirname, 'database.db');

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Initialize database
function initDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.run(`DROP TABLE IF EXISTS users`, (err) => {
        if (err) return reject(err);
      });
      
      db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        balance REAL DEFAULT 100.0
      )`, (err) => {
        if (err) return reject(err);
      });

      const stmt = db.prepare(`INSERT INTO users (username, password, email, role, balance) VALUES (?, ?, ?, ?, ?)`);
      stmt.run('admin', md5('admin123'), 'admin@site.com', 'admin', 5000.00);
      stmt.run('alice', md5('alice2024'), 'alice@site.com', 'user', 100.00);
      stmt.run('bob', md5('bob1234'), 'bob@site.com', 'user', 150.00);
      stmt.finalize((err) => {
        if (err) return reject(err);
        console.log('Database initialized with test users.');
        resolve();
      });
    });
  });
}

module.exports = { db, initDatabase };
