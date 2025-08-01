const token = localStorage.getItem('token');
if (!token) location.href = 'login.html';

async function loadInbox() {
  const res = await fetch('/api/inbox', {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) return (location.href = 'login.html');

  const messages = await res.json();
  const inbox = document.getElementById('inbox');
  inbox.innerHTML = messages.length ? '' : '<p>No messages yet.</p>';

  messages.forEach(m => {
    const div = document.createElement('div');
    div.className = 'msg';
    div.innerHTML = `
      <strong>${m.from}</strong>
      <span>${m.subject || '(no subject)'}</span>
      <small>${new Date(m.createdAt).toLocaleString()}</small>
      <p>${m.body}</p>
    `;
    inbox.appendChild(div);
  });
}

function logout() {
  localStorage.clear();
  location.href = 'index.html';
}

window.onload = loadInbox;
