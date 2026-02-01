const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, { /* default options */ });

const PORT = process.env.PORT || 3000;
const MAX_USERS = 64;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024; // still defined but images removed client-side
const FILE_MAX_BYTES = 10 * 1024 * 1024; // 10 MB for attachments

const MONGODB_URI = process.env.MONGODB_URI; // e.g. "mongodb+srv://user:pass@cluster0..."
const JWT_SECRET = process.env.JWT_SECRET || 'replace_me';
const ADMIN_NAME = process.env.ADMIN_NAME || 'teacher';
const ADMIN_PASS = process.env.ADMIN_PASS || 'adminpass';

// Connect to MongoDB
if (!MONGODB_URI) {
  console.error('MONGODB_URI is not set. Set it in your environment.');
  process.exit(1);
}


mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log("✅ MongoDB connected successfully");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error", err);
  });

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, maxlength: 30 },
  email: { type: String, required: true, unique: true, maxlength: 254 },
  passwordHash: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, default: null }, // null => broadcast
  type: { type: String, enum: ['text','emoji','file'], default: 'text' },
  text: { type: String, default: '' },
  filename: { type: String },
  fileDataUrl: { type: String }, // NOTE: storing large base64 in DB is not ideal for production
  mime: { type: String },
  time: { type: Date, default: Date.now },
}, { timestamps: true });
const Message = mongoose.model('Message', messageSchema);

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

// Simple helpers
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// API: Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    if (username.length > 30) return res.status(400).json({ error: 'Username too long' });

    const existing = await User.findOne({ $or: [{ username }, { email }] });
    if (existing) return res.status(400).json({ error: 'Username or email already taken' });

    const hash = await bcrypt.hash(password, 10);
    const isAdmin = (username === ADMIN_NAME && password === ADMIN_PASS);
    const user = await User.create({ username, email, passwordHash: hash, isAdmin });
    const token = signToken({ id: user._id.toString(), username: user.username, isAdmin: !!isAdmin });
    res.json({ token, username: user.username, isAdmin: !!isAdmin });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// API: Login
app.post('/api/login', async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: 'Missing fields' });

    // Admin special-case fallback: if username matches ADMIN_NAME and password matches ADMIN_PASS,
    // ensure an admin user exists and let them login even if not in DB.
    if (usernameOrEmail === ADMIN_NAME && password === ADMIN_PASS) {
      let adminUser = await User.findOne({ username: ADMIN_NAME });
      if (!adminUser) {
        const hash = await bcrypt.hash(ADMIN_PASS, 10);
        adminUser = await User.create({ username: ADMIN_NAME, email: `${ADMIN_NAME}@local`, passwordHash: hash, isAdmin: true });
      }
      const token = signToken({ id: adminUser._id.toString(), username: adminUser.username, isAdmin: true });
      return res.json({ token, username: adminUser.username, isAdmin: true });
    }

    const user = await User.findOne({
      $or: [
        { username: usernameOrEmail },
        { email: usernameOrEmail }
      ]
    });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = signToken({ id: user._id.toString(), username: user.username, isAdmin: !!user.isAdmin });
    res.json({ token, username: user.username, isAdmin: !!user.isAdmin });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// No-IP admin list: return list of online users (for admin UI polling or socket flow)
app.get('/api/online-users', (req, res) => {
  // This endpoint is not used by sockets; just a convenience if needed
  const arr = Object.values(connectedUsers); // filled later
  res.json({ users: arr });
});

// In-memory maps for socket connections
const connectedUsers = {}; // socketId -> username
const nameToSocket = {}; // username -> socketId

// Helper to build admin_user_list (no IPs)
function buildAdminUserList() {
  return Object.entries(connectedUsers).map(([sid, username]) => ({ name: username }));
}

// Socket auth middleware: client must provide token in handshake auth
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) {
    // reject connection if not authenticated
    return next(new Error('Authentication required'));
  }
  const payload = verifyToken(token);
  if (!payload) return next(new Error('Invalid token'));
  socket.user = {
    id: payload.id,
    username: payload.username,
    isAdmin: !!payload.isAdmin
  };
  return next();
});

io.on('connection', async (socket) => {
  const username = socket.user.username;
  // prevent exceeding MAX_USERS
  if (Object.keys(connectedUsers).length >= MAX_USERS && !socket.user.isAdmin) {
    socket.emit('room_full');
    socket.disconnect(true);
    return;
  }

  connectedUsers[socket.id] = username;
  nameToSocket[username] = socket.id;

  // Inform this socket of final name
  socket.emit('your_name', username);

  // Send recent chat history (last 200 messages)
  try {
    const messages = await Message.find({})
      .sort({ time: 1 })
      .limit(200)
      .lean()
      .exec();
    // send as an array of messages
    socket.emit('message_history', messages.map(m => ({
      user: m.from,
      to: m.to,
      type: m.type,
      text: m.text,
      filename: m.filename,
      fileDataUrl: m.fileDataUrl,
      mime: m.mime,
      time: m.time.toISOString()
    })));
  } catch (e) {
    console.error('Failed to load history', e);
  }

  // Notify everyone
  io.emit('system_message', {
    text: `${username} joined the chat.`,
    time: new Date().toISOString()
  });
  io.emit('user_list', {
    users: Object.values(connectedUsers),
    count: Object.keys(connectedUsers).length,
    max: MAX_USERS
  });

  // If any admin sockets connected, send admin user list to them
  for (const [id, sock] of io.sockets.sockets) {
    if (sock.user && sock.user.isAdmin) {
      sock.emit('admin_user_list', buildAdminUserList());
    }
  }

  // Handle client sending message
  socket.on('send_message', async (payload) => {
    if (!socket.user || !socket.user.username) return;
    const time = new Date();
    const type = payload.type || 'text';
    const to = payload.to || null;

    if (type === 'file') {
      const dataUrl = String(payload.fileDataUrl || '');
      const filename = String(payload.filename || 'file');
      const mime = String(payload.mime || 'application/octet-stream');
      // Size checks left up to client
      const msgDoc = await Message.create({
        from: socket.user.username,
        to,
        type: 'file',
        filename,
        fileDataUrl: dataUrl,
        mime,
        time
      });
      const msg = {
        user: msgDoc.from,
        type: msgDoc.type,
        filename: msgDoc.filename,
        fileDataUrl: msgDoc.fileDataUrl,
        mime: msgDoc.mime,
        time: msgDoc.time.toISOString(),
        to: msgDoc.to
      };
      if (to && nameToSocket[to]) {
        io.to(nameToSocket[to]).emit('message', msg);
        socket.emit('message', msg);
      } else {
        io.emit('message', msg);
      }
      return;
    }

    // text/emoji
    const textRaw = String(payload.text || '').slice(0, 2000);
    const text = textRaw.trim();
    if (!text) return;

    const msgDoc = await Message.create({
      from: socket.user.username,
      to,
      type: type === 'emoji' ? 'emoji' : 'text',
      text,
      time
    });

    const msg = {
      user: msgDoc.from,
      type: msgDoc.type,
      text: msgDoc.text,
      time: msgDoc.time.toISOString(),
      to: msgDoc.to
    };

    if (to && nameToSocket[to]) {
      io.to(nameToSocket[to]).emit('message', msg);
      socket.emit('message', msg);
    } else {
      io.emit('message', msg);
    }
  });

  // Admin actions (kick)
  socket.on('admin_action', (action) => {
    if (!socket.user || !socket.user.isAdmin) {
      socket.emit('system_message', { text: 'Not authorized.', time: new Date().toISOString() });
      return;
    }
    if (action.type === 'kick') {
      const targetName = action.targetName;
      const sid = nameToSocket[targetName];
      if (sid) {
        const tSock = io.sockets.sockets.get(sid);
        if (tSock) {
          tSock.emit('system_message', { text: 'You were kicked by admin.', time: new Date().toISOString() });
          tSock.disconnect(true);
        }
      }
      // refresh admin lists
      setTimeout(() => {
        for (const [id, sock] of io.sockets.sockets) {
          if (sock.user && sock.user.isAdmin) {
            sock.emit('admin_user_list', buildAdminUserList());
          }
        }
      }, 50);
    }
  });

  // Admin can request admin list
  socket.on('request_admin_list', () => {
    if (!socket.user || !socket.user.isAdmin) return;
    socket.emit('admin_user_list', buildAdminUserList());
  });

  // Logout handler: client can emit 'logout', we disconnect socket
  socket.on('logout', () => {
    socket.disconnect(true);
  });

  socket.on('disconnect', () => {
    // cleanup
    delete nameToSocket[username];
    delete connectedUsers[socket.id];

    io.emit('system_message', {
      text: `${username} left the chat.`,
      time: new Date().toISOString()
    });
    io.emit('user_list', {
      users: Object.values(connectedUsers),
      count: Object.keys(connectedUsers).length,
      max: MAX_USERS
    });

    // update admins
    for (const [id, sock] of io.sockets.sockets) {
      if (sock.user && sock.user.isAdmin) {
        sock.emit('admin_user_list', buildAdminUserList());
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`Chat server listening on port ${PORT}`);
});