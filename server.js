const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
let db;

// Initialize DB
(async () => {
  try {
    db = await open({
      filename: './db.sqlite',
      driver: sqlite3.Database
    });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        "from" TEXT NOT NULL,
        "to" TEXT NOT NULL,
        subject TEXT,
        body TEXT,
        type TEXT CHECK(type IN ('internal', 'external-draft')),
        status TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Database ready');
  } catch (err) {
    console.error('❌ DB setup failed:', err);
  }
})();

app.use(express.json());
app.use(express.static('.'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-ultra-secure-jwt-secret-here';

// 🔐 Login / Register
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !email.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk allowed' });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    let user = await db.get('SELECT * FROM users WHERE email = ?', email);

    if (!user) {
      const hashed = await bcrypt.hash(password, 10);
      await db.run('INSERT INTO users (email, password) VALUES (?, ?)', email, hashed);
      user = await db.get('SELECT * FROM users WHERE email = ?', email);
    } else {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: user.email });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// 📨 Send Message
app.post('/api/send', async (req, res) => {
  const auth = req.headers.authorization?.split(' ')[1];
  try { jwt.verify(auth, JWT_SECRET); } catch { return res.status(401).json({ error: 'Unauthorized' }); }

  const { from, to, subject, body } = req.body;
  if (from !== jwt.verify(auth, JWT_SECRET).email) {
    return res.status(403).json({ error: 'Invalid sender' });
  }

  if (!to || !subject || !body) {
    return res.status(400).json({ error: 'All fields required' });
  }

  try {
    if (to.endsWith('@unfiltereduk.co.uk')) {
      await db.run(
        'INSERT INTO messages ("from", "to", subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
        from, to, subject, body, 'internal', 'delivered'
      );
      res.json({ message: '📬 Message delivered inside the network' });
    } else {
      await db.run(
        'INSERT INTO messages ("from", "to", subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
        from, to, subject, body, 'external-draft', 'ready-to-forward'
      );
      res.json({
        message: '📎 External message saved. Please forward manually from your personal email.',
        externalAction: true
      });
    }
  } catch (err) {
    res.status(500).json({ error: 'Send failed' });
  }
});

// 📥 Inbox
app.get('/api/inbox', async (req, res) => {
  const auth = req.headers.authorization?.split(' ')[1];
  try { jwt.verify(auth, JWT_SECRET); } catch { return res.status(401).json({ error: 'Unauthorized' }); }

  const to = req.query.to;
  if (!to) return res.status(400).json({ error: 'Missing "to"' });

  try {
    const msgs = await db.all(
      'SELECT "from", "to", subject, body, type, status, createdAt FROM messages WHERE "to" = ? ORDER BY createdAt DESC',
      to
    );
    res.json(msgs);
  } catch (err) {
    res.status(500).json({ error: 'Load failed' });
  }
});

// 🏁 Start
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🔥 Unfiltered Mail Core running on port ${PORT}`);
});
