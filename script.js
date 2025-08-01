// DOM Helpers
function show(id) {
  document.querySelectorAll('.panel').forEach(el => el.style.display = 'none');
  if (id) document.getElementById(id).style.display = 'block';
}

// Nav Links
function updateNav() {
  const user = localStorage.getItem('user');
  document.getElementById('navLogin').style.display = user ? 'none' : 'inline';
  document.getElementById('navDash').style.display = user ? 'inline' : 'none';
  document.getElementById('navLogout').style.display = user ? 'inline' : 'none';
  if (user) {
    document.getElementById('userEmail').textContent = user;
  }
}

// Register or Login
async function registerOrLogin() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  if (!email.endsWith('@unfiltereduk.co.uk')) {
    alert('Only @unfiltereduk.co.uk emails are allowed');
    return;
  }

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (res.ok) {
    localStorage.setItem('user', data.email);
    localStorage.setItem('token', data.token);
    updateNav();
    show('dashboard');
    loadInbox();
  } else {
    alert('Error: ' + data.error);
  }
}

// Send Message
async function sendMessage() {
  const to = document.getElementById('to').value;
  const subject = document.getElementById('subject').value;
  const body = document.getElementById('body').value;
  const from = localStorage.getItem('user');
  const token = localStorage.getItem('token');

  const res = await fetch('/api/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token
    },
    body: JSON.stringify({ from, to, subject, body })
  });

  const data = await res.json();
  if (res.ok) {
    alert(data.message);
    document.getElementById('to').value = '';
    document.getElementById('subject').value = '';
    document.getElementById('body').value = '';
    loadInbox();
  } else {
    alert('Error: ' + data.error);
  }
}

// Load Inbox
async function loadInbox() {
  const user = localStorage.getItem('user');
  const token = localStorage.getItem('token');
  if (!user || !token) return;

  const res = await fetch(`/api/inbox?to=${encodeURIComponent(user)}`, {
    headers: { 'Authorization': token }
  });

  if (!res.ok) {
    document.getElementById('inbox').innerHTML = '<p>Failed to load inbox.</p>';
    return;
  }

  const messages = await res.json();
  const inbox = document.getElementById('inbox');
  if (messages.length === 0) {
    inbox.innerHTML = '<p>No messages yet.</p>';
    return;
  }

  inbox.innerHTML = '';
  messages.forEach(msg => {
    const div = document.createElement('div');
    div.className = 'msg';
    div.innerHTML = `
      <strong>${msg["from"]}</strong>
      <div>${msg.subject}</div>
      <small>on ${new Date(msg.createdAt).toLocaleString()}</small>
      <p style="margin-top:8px;padding-top:8px;border-top:1px solid #eee;">${msg.body}</p>
    `;
    inbox.appendChild(div);
  });
}

// Logout
document.getElementById('navLogout')?.addEventListener('click', (e) => {
  e.preventDefault();
  localStorage.removeItem('user');
  localStorage.removeItem('token');
  updateNav();
  show('login');
});

// On Load
window.onload = () => {
  const path = window.location.hash.slice(1) || 'home';
  if (['home', 'login', 'dashboard'].includes(path)) {
    if (path === 'dashboard' && localStorage.getItem('user')) {
      show('dashboard');
    } else {
      show(path);
    }
  } else {
    show('home');
  }
  updateNav();
};
