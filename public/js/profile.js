const token = localStorage.getItem('token');
if (!token) location.href = 'login.html';

async function loadProfile() {
  const res = await fetch('/api/profile', {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) return logout();

  const user = await res.json();
  document.getElementById('fullName').value = user.fullName || '';
  document.getElementById('avatar').value = user.avatar || '';
  document.getElementById('avatarPreview').src = user.avatar || 'https://via.placeholder.com/100';
  document.getElementById('userEmail').textContent = user.email;
}

async function saveProfile() {
  const fullName = document.getElementById('fullName').value;
  const avatar = document.getElementById('avatar').value;

  const res = await fetch('/api/profile', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ fullName, avatar })
  });

  if (res.ok) {
    document.getElementById('avatarPreview').src = avatar || 'https://via.placeholder.com/100';
    setStatus('Profile saved!');
  } else {
    setStatus('Save failed.', true);
  }
}

function setStatus(msg, error = false) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = error ? 'status error' : 'status success';
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 4000);
}

function logout() {
  localStorage.clear();
  location.href = 'index.html';
}

window.onload = loadProfile;
