const axios = require('axios');

// Your Routing Engine
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

  // ✅ 1. INTERNAL: To another @unfiltereduk.co.uk
  if (to.endsWith('@unfiltereduk.co.uk')) {
    await db.run(
      'INSERT INTO messages (from, to, subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
      from, to, subject, body, 'internal', 'delivered'
    );
    return res.json({ message: '📬 Message delivered internally' });
  }

  // ✅ 2. EXTERNAL: Send via Mailgun API (NOT Gmail)
  try {
    await axios({
      method: 'POST',
      url: `https://api.mailgun.net/v3/unfiltereduk.co.uk/messages`,
      auth: {
        username: 'api',
        password: process.env.MAILGUN_API_KEY
      },
      data: {
        from: `"${from.split('@')[0]}" <${from}>`,
        to: to,
        subject: subject,
        text: body
      }
    });

    await db.run(
      'INSERT INTO messages (from, to, subject, body, type, status) VALUES (?, ?, ?, ?, ?, ?)',
      from, to, subject, body, 'external', 'sent'
    );

    return res.json({ message: '📤 Email sent via Mailgun — your rules' });
  } catch (err) {
    console.error('Mailgun Error:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Failed to send' });
  }
});
