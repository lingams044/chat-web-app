// client.js — auth via JWT in localStorage
const token = localStorage.getItem('chat_token');
const usernameLocal = localStorage.getItem('chat_username');
const isAdmin = localStorage.getItem('chat_isAdmin') === '1';

const meNameEl = document.getElementById('meName');
const logoutBtn = document.getElementById('logout');
const adminLink = document.getElementById('adminLink');
const loginLink = document.getElementById('loginLink');

if (!token) {
  // Not logged in, send to login page
  loginLink.style.display = '';
  document.getElementById('logout').style.display = 'none';
} else {
  meNameEl.textContent = usernameLocal;
  if (!isAdmin) adminLink.style.display = 'none';
}

const socket = token ? io({ auth: { token } }) : null;

const usersEl = document.getElementById('users'); // not used in simplified UI
const recipientSelect = document.getElementById('recipient-select');
const userCountEl = document.getElementById('user-count');
const userMaxEl = document.getElementById('user-max');
const messagesEl = document.getElementById('messages');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const fileBtn = document.getElementById('file-btn');
const fileInput = document.getElementById('file-input');
const emojiToggle = document.getElementById('emoji-toggle');

function formatTime(iso) {
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString();
  } catch (e) { return ''; }
}
function addMessage(msg, prepend=false) {
  const li = document.createElement('li');
  const isPrivate = !!msg.to;
  const isFromMe = msg.user === usernameLocal;
  li.className = isPrivate ? 'private' : 'public';
  const header = document.createElement('div');
  header.textContent = `${msg.user}${isFromMe ? ' (you)' : ''} ${isPrivate ? `→ ${msg.to}` : ''} • ${formatTime(msg.time)}`;
  li.appendChild(header);

  if (msg.type === 'file') {
    const a = document.createElement('a');
    a.textContent = `${msg.filename} — Download`;
    a.href = msg.fileDataUrl;
    a.download = msg.filename;
    a.target = '_blank';
    li.appendChild(a);
  } else if (msg.type === 'emoji') {
    const span = document.createElement('div');
    span.style.fontSize = '24px';
    span.textContent = msg.text;
    li.appendChild(span);
  } else {
    const div = document.createElement('div');
    div.textContent = msg.text;
    li.appendChild(div);
  }

  if (prepend) messagesEl.insertBefore(li, messagesEl.firstChild);
  else messagesEl.appendChild(li);

  // ensure latest messages visible after append
  requestAnimationFrame(() => { messagesEl.scrollTop = messagesEl.scrollHeight; });
}

if (socket) {
  socket.on('connect_error', (err) => {
    console.error('socket connect error', err.message);
    // if auth error, redirect to login
    if (err && err.message && err.message.includes('Authentication')) {
      alert('Authentication failed. Please login again.');
      localStorage.removeItem('chat_token');
      localStorage.removeItem('chat_username');
      localStorage.removeItem('chat_isAdmin');
      location.href = '/login.html';
    }
  });

  socket.on('your_name', (name) => {
    // name is available; already set from login
    meNameEl.textContent = name;
  });

  socket.on('message_history', (arr) => {
    // arr is in chronological ascending order (oldest -> newest)
    messagesEl.innerHTML = '';
    // Render all and scroll to bottom so latest visible
    arr.forEach(m => addMessage(m, false));
    requestAnimationFrame(() => { messagesEl.scrollTop = messagesEl.scrollHeight; });

    // populate recipient list (everyone + online users)
    // We'll request user_list event to get current online users
    socket.emit('request_admin_list'); // not harmful; admin sockets will ignore
    // server will also emit 'user_list' soon after connection
  });

  socket.on('system_message', (m) => {
    addMessage({ user: 'System', text: m.text, type: 'text', time: m.time });
  });

  socket.on('message', (m) => addMessage(m));

  socket.on('user_list', ({ users, count, max }) => {
    // populate recipient select and status
    recipientSelect.innerHTML = '<option value="">Everyone</option>';
    users.forEach(u => {
      const opt = document.createElement('option');
      opt.value = u;
      opt.textContent = u;
      recipientSelect.appendChild(opt);
    });
    userCountEl.textContent = count;
    userMaxEl.textContent = max;
  });

  // admin user list response (for admin interface)
  socket.on('admin_user_list', (arr) => {
    // admin UI will request this when on admin page; no-op here
    // keep for compatibility
    console.log('admin_user_list', arr);
  });
}

// Send message
messageForm.addEventListener('submit', (e) => {
  e.preventDefault();
  if (!socket) { alert('Not connected'); return; }
  const text = messageInput.value.trim();
  const to = recipientSelect.value || null;
  if (!text) return;
  const payload = { type: 'text', text, to };
  socket.emit('send_message', payload);
  messageInput.value = '';
});

// File attachments: keep handling for allowed types
fileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
  const file = e.target.files && e.target.files[0];
  fileInput.value = '';
  if (!file) return;
  const maxBytes = 10 * 1024 * 1024;
  if (file.size > maxBytes) { alert('File too large (max 10MB).'); return; }
  const allowed = ['application/pdf', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'text/plain'];
  if (!allowed.includes(file.type) && !file.name.match(/\.(pdf|pptx?|txt)$/i)) {
    alert('Unsupported file type. Allowed: pdf, ppt, pptx, txt');
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const dataUrl = reader.result;
    const to = recipientSelect.value || null;
    socket.emit('send_message', { type: 'file', fileDataUrl: dataUrl, filename: file.name, mime: file.type || 'application/octet-stream', to });
  };
  reader.readAsDataURL(file);
});

// Logout
logoutBtn.addEventListener('click', () => {
  if (socket) socket.emit('logout');
  localStorage.removeItem('chat_token');
  localStorage.removeItem('chat_username');
  localStorage.removeItem('chat_isAdmin');
  location.href = '/login.html';
});