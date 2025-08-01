require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.static('public')); // Serve HTML, CSS, JS

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

// Enforce unique email index
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

// 🔐 Register
app.post('/api/register', async (req, res) => {
  const { email, password, fullName } = req.body;

  // Validate email domain
  if (!email || !email.endsWith('@unfiltereduk.co.uk')) {
    return res.status(400).json({ 
      error: 'Only @unfiltereduk.co.uk email addresses are allowed.' 
    });
  }

  // Validate format
  if (!/^[^\s@]+@unfiltereduk\.co\.uk$/.test(email)) {
    return res.status(400).json({ 
      error: 'Invalid email format.' 
    });
  }

  // Validate password
  if (!password || password.length < 6) {
    return res.status(400).json({ 
      error: 'Password must be at least 6 characters.' 
    });
  }

  // Validate full name
  if (!fullName || fullName.trim().length === 0) {
    return res.status(400).json({ 
      error: 'Full name is required.' 
    });
  }

  try {
    // Check if user already exists
    const existing = await User.findOne({ email }).exec();
    if (existing) {
      return res.status(400).json({ 
        error: 'An account with this email already exists.' 
      });
    }

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({ 
      email: email.toLowerCase(), 
      password: hashed, 
      fullName: fullName.trim() 
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ 
      token, 
      email: user.email,
      message: 'Account created successfully.' 
    });

  } catch (err) {
    // Handle duplicate key error (MongoDB)
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
  await User.updateOne(
    { email: req.user.email },
    { $set: { fullName, avatar } }
  );
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
    res.json({ message: 'Message sent successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send message.' });
  }
});

// 📥 Inbox - Get All Messages
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

    // Mark as read
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

// 🚨 Delete Account (and all messages)
app.delete('/api/delete-account', authenticateToken, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Delete all messages (sent and received)
    await Message.deleteMany({
      $or: [{ from: req.user.email }, { to: req.user.email }]
    }, { session });

    // Delete user account
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

// 🔐 Logout (client-side only)
app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out successfully.' });
});

// 🏁 Start Server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🔥 unfiltereduk.co.uk running on port ${PORT}`);
  console.log(`🔗 Visit: https://your-app.onrender.com`);
});
