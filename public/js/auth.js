function setStatus(msg, error = false) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = error ? 'status error' : 'status success';
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 5000);
}

async function register() {
  const fullName = document.getElementById('fullName').value;
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, fullName })
  });

  const data = await res.json();
  if (res.ok) {
    localStorage.setItem('token', data.token);
    localStorage.setItem('email', data.email);
    location.href = 'inbox.html';
  } else {
    setStatus(data.error, true);
  }
}

async function login() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (res.ok) {
    localStorage.setItem('token', data.token);
    localStorage.setItem('email', data.email);
    location.href = 'inbox.html';
  } else {
    setStatus(data.error, true);
  }
}

function logout() {
  localStorage.removeItem('token');
  localStorage.removeItem('email');
  location.href = 'index.html';
}
