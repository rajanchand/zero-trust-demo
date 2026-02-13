/**
 * Zero Trust Security Demo – Main Server
 * ========================================
 * MSc Dissertation – University of the West of Scotland (UWS)
 *
 * This Express server demonstrates Zero Trust principles:
 *  - Strong authentication (password + OTP)
 *  - Role-Based Access Control (RBAC)
 *  - Device fingerprinting & approval workflow
 *  - Network/location context awareness
 *  - Risk scoring engine
 *  - Centralized policy engine (ALLOW / DENY / STEP_UP)
 *  - Continuous verification on every request
 *  - Comprehensive audit logging
 */
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// ─── Security Headers ───────────────────────────────────
// Helmet adds sensible security headers. We relax some for dev/demo.
app.use(helmet({
  contentSecurityPolicy: false,         // allow inline scripts for demo
  crossOriginEmbedderPolicy: false,     // allow embedding in VS Code browser
  crossOriginResourcePolicy: false,     // allow cross-origin resource loading
  crossOriginOpenerPolicy: false        // allow cross-origin popups
}));
// Allow iframe embedding (needed for VS Code Simple Browser & demos)
app.use((req, res, next) => {
  res.removeHeader('X-Frame-Options');
  next();
});

// ─── CORS ───────────────────────────────────────────────
app.use(cors({
  origin: true,
  credentials: true
}));

// ─── Body Parsing ───────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── Trust proxy (for correct IP behind reverse proxy) ──
app.set('trust proxy', 1);

// ─── Rate Limiting ──────────────────────────────────────
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

// Stricter rate limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many authentication attempts. Try again later.' }
});
app.use('/api/auth/', authLimiter);

// ─── Serve Static Frontend ─────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ─── API Routes ─────────────────────────────────────────
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const deviceRoutes = require('./routes/devices');
const adminRoutes = require('./routes/admin');

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/devices', deviceRoutes);
app.use('/api/admin', adminRoutes);

// ─── Health Check ───────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── Catch-all: serve frontend for any non-API route ────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Error Handler ──────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Server Error]', err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// ─── Connect to MongoDB & Start Server ──────────────────
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/zero_trust_demo';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
    app.listen(PORT, HOST, () => {
      console.log('');
      console.log('══════════════════════════════════════════════════');
      console.log('  Zero Trust Security Demo Server');
      console.log(`  Running on http://${HOST}:${PORT}`);
      console.log('  MSc Dissertation – University of the West of Scotland');
      console.log('══════════════════════════════════════════════════');
      console.log('');
    });
  })
  .catch((err) => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

module.exports = app;
