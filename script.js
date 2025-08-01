// DOM Helpers
function show(id) {
  document.querySelectorAll('.panel').forEach(el => el.style.display = 'none');
  if (id) document.getElementById(id).style.display = 'block';
}

function setStatus(msg, isError = false) {
  const el = document.getElementById('statusMsg');
  el.textContent = msg;
  el.className = `status ${isError ? 'error' : 'success'}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 5000);
}

function setSendStatus(msg, isError = false) {
  const el = document.getElementById('sendStatus');
  el.textContent = msg;
  el.className = `status ${isError ? 'error' : 'success'}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 4000);
}

// Nav Update
function updateNav() {
  const user = localStorage.getItem('user');
  document.getElementById('navLogin').style.display = user ? 'none' : 'inline';
  document.getElementById('navDash').style.display = user ? 'inline' : 'none';
  document.getElementById('navLogout').style.display = user ? 'inline' : 'none';
  if (user) {
    document.getElementById('userEmail').textContent = user;
  }
}

// Step 1: Enter Email
function nextToPassword() {
  const email = document.getElementById('setupEmail').value;
  if (!email) return setStatus('Please enter your email.', true);
  if (!email.endsWith('@unfiltereduk.co.uk')) {
    return setStatus('Only @unfiltereduk.co.uk addresses allowed.', true);
  }

  // Show password step
  document.getElementById('stepEmail').style.display = 'none';
  document.getElementById('stepPassword').style.display = 'block';
  document.getElementById('statusMsg').classList.add('hidden');
}

// Password Strength Feedback
document.getElementById('setupPassword')?.addEventListener('input', function () {
  const pwd = this.value;
  const feedback = document.getElementById('passwordFeedback');
  if (pwd.length === 0) {
    feedback.textContent = '';
    return;
  }
  if (pwd.length < 6) {
    feedback.textContent = 'Too short';
    feedback.className = 'password-strength weak';
  } else if (pwd.length < 10) {
    feedback.textContent = 'Medium strength';
    feedback.className = 'password-strength medium';
  } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(pwd)) {
    feedback.textContent = 'Add uppercase, lowercase, number';
    feedback.className = 'password-strength medium';
  } else {
    feedback.textContent = 'Strong password';
    feedback.className = 'password-strength strong';
  }
});

// Step 2: Finish Setup (Login/Register)
async function finishSetup() {
  const email = document.getElementById('setupEmail').value;
  const password = document.getElementById('setupPassword').value;

  if (password.length < 6) {
    return setStatus('Password must be at least 6 characters.', true);
  }

  setStatus('Setting up...', false);
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (res.ok) {
    localStorage.setItem('user', data.email);
    localStorage.setItem('token', data.token);
    setStatus('✅ Setup complete! Redirecting...', false);
    updateNav();
    setTimeout(() => {
      show('dashboard');
      loadInbox();
    }, 1000);
  } else {
    setStatus('Error: ' + data.error, true);
  }
}

// Go back to email
function goBackToEmail() {
  document.getElementById('stepPassword').style.display = 'none';
  document.getElementById('stepEmail').style.display = 'block';
  document.getElementById('setupPassword').value = '';
  document.getElementById('passwordFeedback').textContent = '';
}

// Send Message
async function sendMessage() {
  const to = document.getElementById('to').value;
  const subject = document.getElementById('subject').value;
  const body = document.getElementById('body').value;
  const from = localStorage.getItem('user');
  const token = localStorage.getItem('token');

  if (!to || !subject || !body) {
    return setSendStatus('All fields are required.', true);
  }

  setSendStatus('Sending...', false);
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
    setSendStatus(data.message);
    document.getElementById('to').value = '';
    document.getElementById('subject').value = '';
    document.getElementById('body').value = '';
    setTimeout(loadInbox, 1000); // Refresh inbox
  } else {
    setSendStatus('Error: ' + data.error, true);
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

  const inbox = document.getElementById('inbox');
  if (!res.ok) {
    inbox.innerHTML = '<p class="error">Failed to load inbox.</p>';
    return;
  }

  const messages = await res.json();
  if (messages.length === 0) {
    inbox.innerHTML = '<p>You have no messages yet.</p>';
    return;
  }

  inbox.innerHTML = '';
  messages.forEach(msg => {
    const div = document.createElement('div');
    div.className = 'msg';
    div.innerHTML = `
      <div class="msg-header">
        <strong>From:</strong> ${msg["from"]} 
        <span class="msg-date">${new Date(msg.createdAt).toLocaleString()}</span>
      </div>
      <div><strong>Subject:</strong> ${msg.subject}</div>
      <p>${msg.body}</p>
    `;
    inbox.appendChild(div);
  });
}

// Logout
document.getElementById('navLogout')?.addEventListener('click', (e) => {
  e.preventDefault();
  localStorage.removeItem('user');
  localStorage.removeItem('token');
  document.getElementById('setupEmail').value = '';
  document.getElementById('setupPassword').value = '';
  document.getElementById('passwordFeedback').textContent = '';
  document.getElementById('statusMsg').classList.add('hidden');
  setStatus('You’ve been logged out.', false);
  setTimeout(() => show('login'), 1000);
  updateNav();
});

// Auto-load
window.onload = () => {
  updateNav();
  const hash = window.location.hash.slice(1) || 'home';
  if (hash === 'dashboard' && localStorage.getItem('user')) {
    show('dashboard');
    loadInbox();
  } else if (hash === 'login') {
    show('login');
  } else {
    show('home');
  }
};
