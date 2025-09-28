// server.js
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const { customAlphabet } = require('nanoid');
const cookieParser = require('cookie-parser');
const path = require('path');

const DB_FILE = './db.sqlite';
const db = new sqlite3.Database(DB_FILE);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
  secret: 'replace_with_secure_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1日
}));

// static files
app.use(express.static(path.join(__dirname, 'public')));

// Helpers
const nano4 = customAlphabet('0123456789', 4);
const randomDeviceCode = () => nano4();

// Middleware: load user from session
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    db.get(`SELECT id, username, role, is_banned, ban_type, device_code FROM users WHERE id = ?`, [req.session.userId], (err, row) => {
      if (err) { console.error(err); next(); }
      else {
        req.user = row || null;
        // If banned, respond immediately (redirect)
        if (req.user && req.user.is_banned) {
          if (req.user.ban_type === 'plus') {
            // redirect to internal banned_plus page
            return res.redirect('/banned_plus.html');
          } else {
            // normal ban -> redirect to google
            return res.redirect('https://google.com');
          }
        }
        next();
      }
    });
  } else {
    next();
  }
});

// API: register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  const device_code = randomDeviceCode();
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(password, salt);

  db.run(`INSERT INTO users (username, password_hash, device_code) VALUES (?, ?, ?)`, [username, hash, device_code], function (err) {
    if (err) {
      if (err.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ error: 'username exists' });
      return res.status(500).json({ error: 'db error' });
    }
    req.session.userId = this.lastID;
    return res.json({ ok: true, device_code });
  });
});

// API: login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  db.get(`SELECT id, username, password_hash FROM users WHERE username = ?`, [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(401).json({ error: 'invalid credentials' });
    const match = await bcrypt.compare(password, row.password_hash);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });
    req.session.userId = row.id;
    res.json({ ok: true });
  });
});

// API: logout
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

// API: me
app.get('/api/me', (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: { id: req.user.id, username: req.user.username, role: req.user.role, device_code: req.user.device_code } });
});

// Admin-check middleware
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  return next();
}

// API: get users (admin)
app.get('/api/users', requireAdmin, (req, res) => {
  db.all(`SELECT id, username, device_code, role, is_banned, ban_type, created_at FROM users ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json({ users: rows });
  });
});

// API: ban user (admin)
app.post('/api/users/:id/ban', requireAdmin, (req, res) => {
  const uid = Number(req.params.id);
  const { type } = req.body; // 'normal' or 'plus' or 'unban'
  if (!['normal','plus','unban'].includes(type)) return res.status(400).json({ error: 'invalid type' });

  if (type === 'unban') {
    db.run(`UPDATE users SET is_banned = 0, ban_type = NULL WHERE id = ?`, [uid], function(err) {
      if (err) return res.status(500).json({ error: 'db error' });
      return res.json({ ok: true });
    });
  } else {
    const is_banned = 1;
    const ban_type = type === 'plus' ? 'plus' : 'normal';
    db.run(`UPDATE users SET is_banned = ?, ban_type = ? WHERE id = ?`, [is_banned, ban_type, uid], function(err) {
      if (err) return res.status(500).json({ error: 'db error' });
      return res.json({ ok: true });
    });
  }
});

// API: set auth mode (admin) - simple switch stored in memory for demo
let AUTH_MODE = 'free'; // 'free' or 'approval'
app.post('/api/settings/auth-mode', requireAdmin, (req, res) => {
  const { mode } = req.body;
  if (!['free','approval'].includes(mode)) return res.status(400).json({ error: 'invalid' });
  AUTH_MODE = mode;
  res.json({ ok: true, mode: AUTH_MODE });
});

app.get('/api/settings/auth-mode', requireAdmin, (req, res) => {
  res.json({ mode: AUTH_MODE });
});

// Serve kanri only if admin session
app.get('/kanri.html', (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    // not admin: redirect to root
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'kanri.html'));
});

// If not admin and accessing banned_plus, redirect to page
app.get('/banned_plus.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'banned_plus.html'));
});

// Simple search endpoint: if body.q equals admin password, redirect to admin page
// For demo we'll consider admin password stored as env or default
const ADMIN_PASS = process.env.ADMIN_PASS || 'supersecretpass';
app.post('/search', (req, res) => {
  // Accept application/x-www-form-urlencoded or json
  const q = req.body.q || req.query.q || '';
  if (q === ADMIN_PASS) {
    // require admin session — if current user is admin allow, else ask to login
    if (req.user && req.user.role === 'admin') {
      return res.redirect('/kanri.html');
    } else {
      // redirect to login first, then admin
      return res.redirect('/login.html?next=/kanri.html');
    }
  }
  // Normal behavior: for demo we just redirect to google error url
  return res.redirect('https://google.com/a');
});

// Root serves index (public)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
