require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve HTML, CSS, JS

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
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

// Enforce unique email
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
  createdBy: { type: String, required: true }, // admin email
  partnerName: { type: String, required: true }, // used for "from" email
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
  if (!token) return res.status(401).json({ error: 'No token provided.' });

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
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk allowed.' });
  }

  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already registered.' });

  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, fullName });
    await user.save();

    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, email: user.email });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Email already exists.' });
    }
    res.status(500).json({ error: 'Registration failed.' });
  }
});

// 🔐 Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
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
  res.json({ message: 'Profile updated.' });
});

// 📨 Send Message (User Auth)
app.post('/api/send', authenticateToken, async (req, res) => {
  const { to, subject, body } = req.body;
  const from = req.user.email;

  if (!to || !body) return res.status(400).json({ error: 'All fields required.' });

  const msg = new Message({ from, to, subject, body });
  await msg.save();
  res.json({ message: 'Sent' });
});

// 📥 Inbox
app.get('/api/inbox', authenticateToken, async (req, res) => {
  const messages = await Message.find({ to: req.user.email }).sort({ createdAt: -1 });
  res.json(messages);
});

// 📧 Get Single Email
app.get('/api/email/:id', authenticateToken, async (req, res) => {
  const message = await Message.findById(req.params.id);
  if (!message || message.to !== req.user.email) return res.status(404).json({ error: 'Not found.' });
  message.read = true;
  await message.save();
  res.json(message);
});

// 🗑️ Delete Message
app.delete('/api/delete/:id', authenticateToken, async (req, res) => {
  const result = await Message.deleteOne({ _id: req.params.id, to: req.user.email });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Not found.' });
  res.json({ message: 'Deleted' });
});

// 🚨 Delete Account
app.delete('/api/delete-account', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    await Message.deleteMany({ $or: [{ from: req.user.email }, { to: req.user.email }] }, { session });
    await User.deleteOne({ email: req.user.email }, { session });
    await session.commitTransaction();
    session.endSession();
    res.json({ message: 'Account deleted.' });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    res.status(500).json({ error: 'Delete failed.' });
  }
});

// 🔍 Get User by Email (for Avatar)
app.get('/api/user/email/:email', async (req, res) => {
  const user = await User.findOne({ email: req.params.email }).select('fullName avatar');
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(user);
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

  // Clean partnerName for email use
  const cleanName = partnerName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '') // Remove special chars
    .substring(0, 20); // Max 20 chars

  if (!cleanName) {
    return res.status(400).json({ error: 'Partner name must contain letters or numbers.' });
  }

  // Generate secure key
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

// 📋 List API Keys (Admin Only)
app.get('/api/admin/keys', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const keys = await ApiKey.find({ revoked: false }).sort({ createdAt: -1 });
  res.json(keys);
});

// 🚫 Revoke API Key (Admin Only)
app.post('/api/admin/revoke-key', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const { key } = req.body;
  const result = await ApiKey.updateOne({ key }, { revoked: true });
  if (result.matchedCount === 0) return res.status(404).json({ error: 'Key not found.' });
  res.json({ message: 'API key revoked.' });
});

// 🤖 Send Automated Email (via API Key)
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

  // ✅ Set sender as {partnerName}@unfiltereduk.co.uk
  const from = `${apiKey.partnerName}@unfiltereduk.co.uk`;

  const msg = new Message({
    from,
    to,
    subject,
    body
  });

  await msg.save();
  res.json({ 
    message: 'Automated email sent.',
    from // Confirm sender
  });
});

// 🔐 Logout
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out.' });
});

// 🏁 Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🔥 unfiltereduk.co.uk running on port ${PORT}`);
});
