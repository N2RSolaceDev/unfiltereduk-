require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

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
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  fullName: String,
  avatar: String,
  createdAt: { type: Date, default: Date.now }
});

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

// Middleware: Authenticate Token
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  const token = auth?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// 🔐 Register
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body;

  if (!email.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ error: 'Only @unfiltereduk.co.uk allowed' });
  }

  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ email, password: hashed, fullName });
  await user.save();

  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

// 🔐 Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, email: user.email });
});

// 📥 Get Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// 📝 Update Profile
app.post('/api/profile', authenticateToken, async (req, res) => {
  const { fullName, avatar } = req.body;
  await User.updateOne({ email: req.user.email }, { fullName, avatar });
  res.json({ message: 'Profile updated' });
});

// 📨 Send Message
app.post('/api/send', authenticateToken, async (req, res) => {
  const { to, subject, body } = req.body;
  const from = req.user.email;

  const msg = new Message({ from, to, subject, body });
  await msg.save();
  res.json({ message: 'Sent' });
});

// 📥 Inbox
app.get('/api/inbox', authenticateToken, async (req, res) => {
  const messages = await Message.find({ to: req.user.email }).sort({ createdAt: -1 });
  res.json(messages);
});

// 🔐 Logout (client-side only)
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out' });
});

// 🏁 Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🔥 unfiltereduk.co.uk running on port ${PORT}`);
});
