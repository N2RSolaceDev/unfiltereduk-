const token = localStorage.getItem('token');
if (!token) location.href = 'login.html';

async function loadSettings() {
  const res = await fetch('/api/profile', {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) return logout();

  const user = await res.json();
  document.getElementById('userEmail').textContent = user.email;
  document.getElementById('createdAt').textContent = new Date(user.createdAt).toLocaleString();
}

function confirmLogout() {
  if (confirm('Log out of all devices?')) {
    localStorage.clear();
    alert('You have been logged out.');
    location.href = 'index.html';
  }
}

function logout() {
  localStorage.clear();
  location.href = 'index.html';
}

window.onload = loadSettings;
