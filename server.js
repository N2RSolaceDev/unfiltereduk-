require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const { Server: WebSocketServer } = require('ws');
const http = require('http');

const app = express();

// ✅ Fix: Trust proxy for X-Forwarded-For (Render, Heroku, etc.)
app.set('trust proxy', 1);

// Rate Limiters
const rateLimit = require('express-rate-limit');
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const adminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: { error: 'Too many admin requests.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply limiters
app.use('/api/auth/', authLimiter);
app.use('/api/admin/', adminLimiter);
app.use('/api/', apiLimiter);

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static('public'));

// Create HTTP + WebSocket server
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Track connected users: email → Set of WebSocket clients
const clients = new Map();

// Broadcast to all clients of a user
function broadcastToUser(email, data) {
  const userClients = clients.get(email);
  if (userClients) {
    userClients.forEach(ws => {
      if (ws.readyState === ws.OPEN) {
        ws.send(JSON.stringify(data));
      }
    });
  }
}

// Handle WebSocket connections
wss.on('connection', (ws, req) => {
  const token = req.headers.authorization?.split(' ')[1] ||
                new URLSearchParams(req.url.split('?')[1]).get('token');

  if (!token) {
    ws.close(1008, 'Authentication required');
    return;
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      ws.close(1008, 'Invalid or expired token');
      return;
    }

    const email = user.email;

    // Add client to user's list
    if (!clients.has(email)) {
      clients.set(email, new Set());
    }
    clients.get(email).add(ws);
    console.log(`✅ WebSocket connected: ${email}`);

    ws.on('close', () => {
      const userClients = clients.get(email);
      if (userClients) {
        userClients.delete(ws);
        if (userClients.size === 0) {
          clients.delete(email);
        }
      }
      console.log(`🔌 WebSocket disconnected: ${email}`);
    });
  });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ DB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { 
    type: String, 
    required: true,
    lowercase: true,
    match: [/^[^\s@]+@unfiltereduk\.co\.uk$/, 'Invalid email format']
  },
  password: { type: String, required: true },
  fullName: { type: String, required: true },
  avatar: String,
  createdAt: { type: Date, default: Date.now }
});
userSchema.index({ email: 1 }, { unique: true });
const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  subject: String,
  body: String,
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);

// API Key Schema
const apiKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  createdBy: { type: String, required: true },
  partnerName: { type: String, required: true },
  permissions: { type: [String], default: ['send'] },
  expiresAt: Date,
  revoked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const ApiKey = mongoose.model('ApiKey', apiKeySchema);

// Middleware: Authenticate Token
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}

// Helper: Is Admin?
function isAdmin(email) {
  return email === 'solace@unfiltereduk.co.uk';
}

// 🔐 Register
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  if (!email || !email.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ 
      error: 'Only @unfiltereduk.co.uk email addresses are allowed.' 
    });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ 
      error: 'Password must be at least 6 characters.' 
    });
  }
  if (!fullName || fullName.trim().length === 0) {
    return res.status(400).json({ 
      error: 'Full name is required.' 
    });
  }
  try {
    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      return res.status(400).json({ 
        error: 'An account with this email already exists.' 
      });
    }
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ 
      email: email.toLowerCase(), 
      password: hashed, 
      fullName: fullName.trim() 
    });
    await user.save();
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ 
      token, 
      email: user.email,
      message: 'Account created successfully.' 
    });
  } catch (err) {
    if (err.code === 11000 || (err.name === 'MongoServerError' && err.message.includes('duplicate key'))) {
      return res.status(400).json({ 
        error: 'An account with this email already exists.' 
      });
    }
    console.error('Registration error:', err);
    res.status(500).json({ 
      error: 'Registration failed. Please try again.' 
    });
  }
});

// 🔐 Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return res.status(400).json({ error: 'Invalid credentials.' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials.' });
  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

// 📥 Get Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email }).select('-password');
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(user);
});

// 📝 Update Profile
app.post('/api/profile', authenticateToken, async (req, res) => {
  const { fullName, avatar } = req.body;
  await User.updateOne({ email: req.user.email }, { $set: { fullName, avatar } });
  res.json({ message: 'Profile updated successfully.' });
});

// 📨 Send Message
app.post('/api/send', authenticateToken, async (req, res) => {
  const { to, subject, body } = req.body;
  const from = req.user.email;
  if (!to || !body) {
    return res.status(400).json({ 
      error: 'Recipient and message body are required.' 
    });
  }
  try {
    const msg = new Message({ from, to, subject, body });
    await msg.save();

    // 🔔 Notify recipient in real time
    broadcastToUser(to, {
      type: 'new_message',
      message: {
        id: msg._id,
        from,
        to,
        subject,
        body,
        read: false,
        createdAt: msg.createdAt
      }
    });

    res.json({ message: 'Message sent successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send message.' });
  }
});

// 📥 Inbox
app.get('/api/inbox', authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({ to: req.user.email })
      .sort({ createdAt: -1 })
      .limit(100);
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load inbox.' });
  }
});

// 📧 Get Single Email
app.get('/api/email/:id', authenticateToken, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    if (!message) return res.status(404).json({ error: 'Message not found.' });
    if (message.to !== req.user.email) return res.status(403).json({ error: 'Access denied.' });
    message.read = true;
    await message.save();
    res.json(message);
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// 🗑️ Delete Message
app.delete('/api/delete/:id', authenticateToken, async (req, res) => {
  try {
    const result = await Message.deleteOne({
      _id: req.params.id,
      to: req.user.email
    });
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Message not found or access denied.' });
    }
    res.json({ message: 'Message deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed.' });
  }
});

// 🚨 Delete Account
app.delete('/api/delete-account', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    await Message.deleteMany({
      $or: [{ from: req.user.email }, { to: req.user.email }]
    }, { session });
    await User.deleteOne({ email: req.user.email }, { session });
    await session.commitTransaction();
    session.endSession();
    res.json({ message: 'Account and all messages deleted permanently.' });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    console.error('Account deletion error:', err);
    res.status(500).json({ error: 'Account deletion failed.' });
  }
});

// 🔍 Get User by Email
app.get('/api/user/email/:email', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.params.email }).select('fullName avatar');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// 🔑 Generate API Key (Admin Only)
app.post('/api/admin/generate-key', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  const { partnerName, expiresDays } = req.body;
  if (!partnerName || !partnerName.trim()) {
    return res.status(400).json({ error: 'Partner name is required.' });
  }
  const cleanName = partnerName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .substring(0, 20);
  if (!cleanName) {
    return res.status(400).json({ error: 'Partner name must contain letters or numbers.' });
  }
  const key = 'ukapi_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = expiresDays ? new Date(Date.now() + expiresDays * 86400000) : null;
  const apiKey = new ApiKey({
    key,
    createdBy: req.user.email,
    partnerName: cleanName,
    expiresAt,
    permissions: ['send']
  });
  await apiKey.save();
  res.json({ 
    message: 'API key generated.', 
    key, 
    fromEmail: `${cleanName}@unfiltereduk.co.uk`,
    expiresAt 
  });
});

// 📋 List API Keys
app.get('/api/admin/keys', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  const keys = await ApiKey.find({ revoked: false }).sort({ createdAt: -1 });
  res.json(keys);
});

// 🚫 Revoke API Key
app.post('/api/admin/revoke-key', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  const { key } = req.body;
  const result = await ApiKey.updateOne({ key }, { revoked: true });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Key not found.' });
  res.json({ message: 'API key revoked.' });
});

// 🤖 Send Automated Email
app.post('/api/automated-send', async (req, res) => {
  const { key, to, subject, body } = req.body;
  if (!key || !to || !subject || !body) {
    return res.status(400).json({ error: 'API key and all fields required.' });
  }
  const apiKey = await ApiKey.findOne({ key });
  if (!apiKey) return res.status(403).json({ error: 'Invalid API key.' });
  if (apiKey.revoked) return res.status(403).json({ error: 'API key revoked.' });
  if (apiKey.expiresAt && new Date() > apiKey.expiresAt) {
    return res.status(403).json({ error: 'API key expired.' });
  }
  const from = `${apiKey.partnerName}@unfiltereduk.co.uk`;
  const msg = new Message({ from, to, subject, body });
  await msg.save();

  // 🔔 Notify recipient in real time
  broadcastToUser(to, {
    type: 'new_message',
    message: {
      id: msg._id,
      from,
      to,
      subject,
      body,
      read: false,
      createdAt: msg.createdAt
    }
  });

  res.json({ message: 'Automated email sent.', from });
});

// 🔐 Logout
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out.' });
});

// 🏁 Start Server (with WebSocket support)
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log(`🔥 unfiltereduk.co.uk running on port ${PORT}`);
});
