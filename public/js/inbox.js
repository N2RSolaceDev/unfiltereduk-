const token = localStorage.getItem('token');
if (!token) location.href = 'login.html';

let ws = null;
const inbox = document.getElementById('inbox');

// Load inbox from API
async function loadInbox() {
  const res = await fetch('/api/inbox', {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) return (location.href = 'login.html');

  const messages = await res.json();
  renderInbox(messages);
}

// Render all messages
function renderInbox(messages) {
  inbox.innerHTML = messages.length ? '' : '<p>No messages yet.</p>';
  messages.forEach(addMessageToDOM);
}

// Add a single message to DOM
function addMessageToDOM(message) {
  const div = document.createElement('div');
  div.className = 'msg';
  div.dataset.id = message._id;
  div.innerHTML = `
    <strong>${message.from}</strong>
    <span>${message.subject || '(no subject)'}</span>
    <small>${new Date(message.createdAt).toLocaleString()}</small>
    <p>${message.body}</p>
  `;
  inbox.prepend(div); // New on top
}

// Connect to WebSocket
function connectWebSocket() {
  // Use query string to pass token (since headers not allowed in browser WS)
  ws = new WebSocket(`ws://${window.location.host}?token=${encodeURIComponent(token)}`);

  ws.onopen = () => console.log('🟢 WebSocket connected');

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'new_message') {
        console.log('📬 New message received:', data.message);
        addMessageToDOM(data.message);
        // Optional: play sound or notification
        // new Notification("New Message", { body: `From: ${data.message.from}` });
      }
    } catch (e) {
      console.error('Invalid WebSocket message:', e);
    }
  };

  ws.onerror = (err) => console.error('WebSocket error:', err);

  ws.onclose = () => {
    console.log('🟡 WebSocket closed. Reconnecting...');
    setTimeout(connectWebSocket, 3000); // Reconnect
  };
}

function logout() {
  localStorage.clear();
  location.href = 'index.html';
}

// On load
window.onload = () => {
  loadInbox();
  connectWebSocket();
};
