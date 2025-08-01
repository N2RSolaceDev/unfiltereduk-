const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
let db;

// Initialize database and tables
(async () => {
  try {
    db = await open({
      filename: './db.sqlite',
      driver: sqlite3.Database
    });

    // Create tables - using "from" and "to" in quotes (reserved keywords)
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
        type TEXT CHECK(type IN ('internal', 'external-draft')) NOT NULL,
        status TEXT NOT NULL,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Database initialized: users and messages tables ready');
  } catch (err) {
    console.error('❌ Database setup failed:', err.message);
    process.exit(1); // Crash early if DB fails
  }
})();

// Middleware
app.use(express.json());
app.use(express.static('.')); // Serve index.html, style.css, script.js

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secure-jwt-secret-change-in-production';

// 🔐 Login / Register
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  // Enforce domain
  if (!email || !email.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk email addresses are allowed.' });
  }

  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }

  try {
    let user = await db.get('SELECT * FROM users WHERE email = ?', email);

    if (!user) {
      // Register new user
      const hashed = await bcrypt.hash(password, 10);
      await db.run('INSERT INTO users (email, password) VALUES (?, ?)', email, hashed);
      user = await db.get('SELECT * FROM users WHERE email = ?', email);
      console.log(`🆕 Registered new user: ${email}`);
    } else {
      // Validate password
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid password.' });
      }
    }

    // Generate JWT
    const token = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    console.log(`🔐 Login successful: ${email}`);
    res.json({ token, email: user.email });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 📨 Send Message – Your Routing Engine
app.post('/api/send', async (req, res) => {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];

  // Verify auth
  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }

  const { from, to, subject, body } = req.body;

  // Validate sender
  if (from !== payload.email) {
    return res.status(403).json({ error: 'You can only send from your own address.' });
  }

  // Validate input
  if (!to || !subject || !body) {
    return res.status(400).json({ error: 'All fields (to, subject, body) are required.' });
  }

  try {
    if (to.endsWith('@unfiltereduk.co.uk')) {
      // ✅ INTERNAL: Save directly in network
      await db.run(
        'INSERT INTO messages ("from", "to", subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
        from, to, subject, body, 'internal', 'delivered'
      );
      console.log(`📬 Internal message: ${from} → ${to}`);
      res.json({ message: 'Message delivered within the Unfiltered Network.' });
    } else {
      // 🌐 EXTERNAL: Save as draft – user must forward manually
      await db.run(
        'INSERT INTO messages ("from", "to", subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
        from, to, subject, body, 'external-draft', 'ready-to-forward'
      );
      console.log(`📤 External draft saved: ${from} → ${to}`);
      res.json({
        message: 'This message is external. Please forward it from your personal email.',
        externalAction: true,
        instructions: `Copy and send this from your email:\n\nTo: ${to}\nSubject: ${subject}\n\n${body}`
      });
    }
  } catch (err) {
    console.error('Send error:', err);
    res.status(500).json({ error: 'Failed to save message.' });
  }
});

// 📥 Inbox – View Messages for Current User
app.get('/api/inbox', async (req, res) => {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];

  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  const to = req.query.to;
  if (!to) {
    return res.status(400).json({ error: 'Query parameter "to" is required.' });
  }

  try {
    const messages = await db.all(
      'SELECT "from", "to", subject, body, type, status, createdAt FROM messages WHERE "to" = ? ORDER BY createdAt DESC',
      to
    );
    res.json(messages);
  } catch (err) {
    console.error('Inbox error:', err);
    res.status(500).json({ error: 'Failed to load inbox.' });
  }
});

// 🏁 Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🔥 Unfiltered Mail Core running on port ${PORT}`);
  console.log(`📦 Database: ./db.sqlite`);
  console.log(`🌐 Visit: https://unfiltereduk.co.uk`);
});
