const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'lab3-secret-change-in-production';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

let users = [];
let nextId = 1;

// Default admin account
users.push({
  id: nextId++,
  username: 'admin',
  password: bcrypt.hashSync('admin123', 10),
  role: 'admin'
});

// Auth middleware
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: 'No token provided' });

  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' });
  }
}

// Admin-only middleware
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin only' });
  }
  next();
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'REST API is running' });
});

// Get all users (admin only)
app.get('/api/users', auth, adminOnly, (req, res) => {
  const safeUsers = users.map(user => ({
    id: user.id,
    username: user.username,
    role: user.role
  }));
  res.json(safeUsers);
});

// Get single user by ID
app.get('/api/users/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const user = users.find(u => u.id === id);

  if (!user) return res.status(404).json({ message: 'User not found' });
  if (req.user.id !== user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }

  res.json({ id: user.id, username: user.username, role: user.role });
});

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(409).json({ message: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: nextId++, username, password: hashedPassword, role: 'user' };
  users.push(newUser);

  res.status(201).json({
    message: 'User registered successfully',
    user: { id: newUser.id, username: newUser.username, role: newUser.role }
  });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: '1h' }
  );

  res.json({
    message: 'Login successful',
    token,
    user: { id: user.id, username: user.username, role: user.role }
  });
});

// Update user
app.put('/api/users/:id', auth, async (req, res) => {
  const id = Number(req.params.id);
  const user = users.find(u => u.id === id);

  if (!user) return res.status(404).json({ message: 'User not found' });
  if (req.user.id !== user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Forbidden' });
  }

  const { username, password, role } = req.body;
  if (username) user.username = username;
  if (password) user.password = await bcrypt.hash(password, 10);
  if (role && req.user.role === 'admin') user.role = role;

  res.json({
    message: 'User updated successfully',
    user: { id: user.id, username: user.username, role: user.role }
  });
});

// Delete user
app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const index = users.findIndex(u => u.id === id);

  if (index === -1) return res.status(404).json({ message: 'User not found' });

  const deletedUser = users.splice(index, 1)[0];
  res.json({
    message: 'User deleted successfully',
    user: { id: deletedUser.id, username: deletedUser.username }
  });
});

// Get own profile
app.get('/api/profile', auth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  res.json({ id: user.id, username: user.username, role: user.role });
});

// Root redirect
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});