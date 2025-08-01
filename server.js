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
app.use(express.static('public'));

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

// Unique index on email
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

// API Key Schema (with customFrom)
const apiKeySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true }, // ukapi_...
  createdBy: { type: String, required: true }, // admin email
  partnerName: { type: String, required: true }, // for @unfiltereduk.co.uk
  customFrom: { 
    type: String,
    validate: {
      validator: function(v) {
        if (!v) return true; // optional
        return /^[^\s@]+@([^\s@.,]+\.)+[^\s@.,]+$/.test(v);
      },
      message: props => `${props.value} is not a valid email address.`
    }
  },
  permissions: { type: [String], default: ['send'] },
  expiresAt: Date,
  revoked: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Unique constraints
apiKeySchema.index({ partnerName: 1 }, { unique: true });
apiKeySchema.index({ customFrom: 1 }, { sparse: true, unique: true }); // only if set

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

// 🔐 Check if email is taken by user OR API
async function isEmailTaken(email) {
  const normalized = email.toLowerCase().trim();
  const localPart = normalized.split('@')[0];

  // Check user
  const user = await User.findOne({ email: normalized });
  if (user) return true;

  // Check API: partnerName match or customFrom
  const apiKey = await ApiKey.findOne({
    $or: [
      { partnerName: localPart },
      { customFrom: normalized }
    ]
  });

  return !!apiKey;
}

// 🔐 Register
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  const normalizedEmail = email.toLowerCase().trim();

  if (!normalizedEmail.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ 
      error: 'Only @unfiltereduk.co.uk email addresses are allowed.' 
    });
  }

  if (await isEmailTaken(normalizedEmail)) {
    return res.status(400).json({ 
      error: 'This email or identity is already taken.' 
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
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ 
      email: normalizedEmail, 
      password: hashed, 
      fullName: fullName.trim() 
    });

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
  res.json({ message: 'Profile updated.' });
});

// 📨 Send Message
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

// 🔍 Get User by Email
app.get('/api/user/email/:email', async (req, res) => {
  const user = await User.findOne({ email: req.params.email }).select('fullName avatar');
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(user);
});

// 🔑 Generate API Key (Admin Only) – with ukapi_ prefix
app.post('/api/admin/generate-key', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.email)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  const { partnerName, customFrom, expiresDays } = req.body;

  if (!partnerName || !partnerName.trim()) {
    return res.status(400).json({ error: 'Partner name is required.' });
  }

  // Clean partnerName
  const cleanName = partnerName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .substring(0, 20);

  if (!cleanName) {
    return res.status(400).json({ error: 'Partner name must contain letters or numbers.' });
  }

  // Validate customFrom if provided
  let fromEmail = `${cleanName}@unfiltereduk.co.uk`;
  if (customFrom && customFrom.trim()) {
    const normalized = customFrom.trim().toLowerCase();
    if (!/^[^\s@]+@([^\s@.,]+\.)+[^\s@.,]+$/.test(normalized)) {
      return res.status(400).json({ error: 'Invalid custom email format.' });
    }

    if (await isEmailTaken(normalized)) {
      return res.status(400).json({ error: `The email ${normalized} is already taken.` });
    }

    fromEmail = normalized;
  }

  // ✅ Keep ukapi_ prefix
  const key = 'ukapi_' + crypto.randomBytes(32).toString('hex');
  const expiresAt = expiresDays ? new Date(Date.now() + expiresDays * 86400000) : null;

  const apiKey = new ApiKey({
    key,
    createdBy: req.user.email,
    partnerName: cleanName,
    customFrom: fromEmail !== `${cleanName}@unfiltereduk.co.uk` ? fromEmail : undefined,
    expiresAt,
    permissions: ['send']
  });

  try {
    await apiKey.save();
    res.json({ 
      message: 'API key generated.', 
      key, 
      fromEmail,
      expiresAt 
    });
  } catch (err) {
    if (err.code === 11000) {
      const field = err.keyPattern.customFrom ? 'custom email' : 'partner name';
      return res.status(400).json({ error: `This ${field} is already in use.` });
    }
    res.status(500).json({ error: 'Key generation failed.' });
  }
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

  // Use customFrom if set, else default
  const from = apiKey.customFrom || `${apiKey.partnerName}@unfiltereduk.co.uk`;

  const msg = new Message({ from, to, subject, body });
  await msg.save();
  res.json({ message: 'Automated email sent.', from });
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
