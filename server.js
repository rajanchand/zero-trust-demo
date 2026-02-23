// Zero Trust demo – Express server (UWS dissertation)
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

app.use(helmet({
  contentSecurityPolicy: false,         // allow inline scripts for demo
  crossOriginEmbedderPolicy: false,     // allow embedding in VS Code browser
  crossOriginResourcePolicy: false,     // allow cross-origin resource loading
  crossOriginOpenerPolicy: false        // allow cross-origin popups
}));
app.use((req, res, next) => {
  res.removeHeader('X-Frame-Options');
  next();
});

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many authentication attempts. Try again later.' }
});
app.use('/api/auth/', authLimiter);

app.use(express.static(path.join(__dirname, 'public')));

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const deviceRoutes = require('./routes/devices');
const adminRoutes = require('./routes/admin');

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/admin', adminRoutes);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

const bcryptSeed = require('bcryptjs');
const UserSeed = require('./models/User');
app.get('/api/seed-demo', async (req, res) => {
  try {
    const users = [
      { email: 'rajanchand48@gmail.com', password: 'Password@123', role: 'superadmin' },
      { email: 'superadmin@demo.com', password: 'Password@123', role: 'superadmin' },
      { email: 'admin@demo.com', password: 'Password@123', role: 'admin' },
      { email: 'supervisor@demo.com', password: 'Password@123', role: 'supervisor' },
      { email: 'user@demo.com', password: 'Password@123', role: 'user' }
    ];
    const results = [];
    for (const u of users) {
      const exists = await UserSeed.findOne({ email: u.email });
      if (exists) { results.push(u.email + ' already exists'); continue; }
      const hash = await bcryptSeed.hash(u.password, 12);
      await UserSeed.create({ email: u.email, passwordHash: hash, role: u.role, status: 'active' });
      results.push('Created ' + u.email + ' (' + u.role + ')');
    }
    res.json({ message: 'Seed complete', results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('[Server Error]', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/zero_trust_demo';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(PORT, HOST, () => {
      console.log('');
      console.log('Zero Trust Demo – http://' + HOST + ':' + PORT);
      console.log('');
    });
  })
  .catch((err) => {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  });

module.exports = app;
