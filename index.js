const express = require('express');
const sqlite = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
let db;

// Init DB
(async () => {
  db = await sqlite.open({ filename: './db.sqlite', driver: sqlite3.Database });
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      email TEXT UNIQUE,
      password TEXT
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY,
      from TEXT,
      to TEXT,
      subject TEXT,
      body TEXT,
      type TEXT,
      status TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
})();

app.use(express.json());
app.use(express.static('.'));

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-to-a-very-long-random-string';

// 🔐 Login / Register
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk allowed' });
  }

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
});

// 📨 Send Message (Your Routing Logic)
app.post('/api/send', async (req, res) => {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { from, to, subject, body } = req.body;
  if (from !== payload.email) return res.status(403).json({ error: 'Invalid sender' });

  if (to.endsWith('@unfiltereduk.co.uk')) {
    // ✅ INTERNAL: Fully within your network
    await db.run(
      'INSERT INTO messages (from, to, subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
      from, to, subject, body, 'internal', 'delivered'
    );
    res.json({ 
      message: '📬 Message delivered inside the Unfiltered Network',
      externalAction: false 
    });
  } else {
    // 🌐 EXTERNAL: Do NOT send via third party
    // Instead: Let user send it themselves
    await db.run(
      'INSERT INTO messages (from, to, subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
      from, to, subject, body, 'external-draft', 'ready-to-forward'
    );

    res.json({
      message: '📬 Message saved. Please forward it from your personal email.',
      externalAction: true,
      forwardInstructions: `To deliver this message:\n\n1. Open your email (Gmail, Outlook, etc.)\n2. Compose a new message to ${to}\n3. Copy and paste:\n\nSubject: ${subject}\n\n${body}\n\nSent via @unfiltereduk.co.uk`
    });
  }
});

// 📥 Inbox
app.get('/api/inbox', async (req, res) => {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];
  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const to = req.query.to;
  const msgs = await db.all(
    'SELECT * FROM messages WHERE to = ? ORDER BY createdAt DESC', 
    to
  );
  res.json(msgs);
});

// 🏁 Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Unfiltered Mail Core running on port ${PORT}`);
});
