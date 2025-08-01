async function sendMessage() {
  const to = document.getElementById('to').value;
  const subject = document.getElementById('subject').value;
  const body = document.getElementById('body').value;
  const from = localStorage.getItem('user');

  const res = await fetch('/api/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': localStorage.getItem('token')
    },
    body: JSON.stringify({ from, to, subject, body })
  });

  const data = await res.json();
  if (res.ok) {
    if (data.externalAction) {
      alert("This is an external message.\n\n" + data.forwardInstructions);
    } else {
      alert("Message delivered internally.");
    }
    loadInbox();
  } else {
    alert("Error: " + data.error);
  }
}
