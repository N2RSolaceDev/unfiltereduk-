// settings.js
const token = localStorage.getItem('token');
if (!token) location.href = 'login.html';

// Load user data
async function loadSettings() {
  try {
    const res = await fetch('/api/profile', {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!res.ok) return logout();

    const user = await res.json();
    document.getElementById('userEmail').textContent = user.email;
    document.getElementById('createdAt').textContent = new Date(user.createdAt).toLocaleDateString();
  } catch (err) {
    console.error('Failed to load profile:', err);
    setStatus('Could not load settings.', true);
  }
}

// Confirm and delete account
function confirmDelete() {
  if (confirm('⚠️ Are you sure?\n\nThis will permanently delete your account and all messages.\n\nThis action cannot be undone.')) {
    deleteAccount();
  }
}

// Send delete request
async function deleteAccount() {
  const res = await fetch('/api/delete-account', {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  const data = await res.json();

  if (res.ok) {
    setStatus('Account deleted successfully.', false);
    setTimeout(() => {
      localStorage.clear();
      location.href = 'index.html';
    }, 1500);
  } else {
    setStatus('Delete failed: ' + data.error, true);
  }
}

// Show status message
function setStatus(msg, isError = true) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = `status ${isError ? 'error' : 'success'}`;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 5000);
}

// Logout
function logout() {
  localStorage.clear();
  location.href = 'index.html';
}

// On load
window.onload = loadSettings;
