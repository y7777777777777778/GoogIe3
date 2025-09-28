// init-db.js
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const DB_FILE = './db.sqlite';
const db = new sqlite3.Database(DB_FILE);

async function run() {
  db.serialize(async () => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      device_code TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      is_banned INTEGER DEFAULT 0,
      ban_type TEXT DEFAULT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    const adminName = 'admin';
    const adminPassword = 'adminpass'; // 必要なら変更してください
    const deviceCode = '0000';

    // check if admin exists
    db.get(`SELECT id FROM users WHERE username = ?`, [adminName], async (err, row) => {
      if (err) return console.error(err);
      if (row) {
        console.log('Admin already exists');
        db.close();
      } else {
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(adminPassword, salt);
        db.run(
          `INSERT INTO users (username, password_hash, device_code, role) VALUES (?, ?, ?, 'admin')`,
          [adminName, hash, deviceCode],
          function (err) {
            if (err) console.error(err);
            else console.log(`Admin user created: ${adminName} / password: ${adminPassword}`);
            db.close();
          }
        );
      }
    });
  });
}

run();
