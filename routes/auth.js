/**
 * Auth Routes
 * ---
 * POST /api/auth/login       – Step 1: email + password → sends OTP
 * POST /api/auth/verify-otp  – Step 2: verify OTP → issue JWT + refresh token
 * POST /api/auth/refresh     – Refresh access token (token rotation)
 * POST /api/auth/logout      – Revoke refresh token
 * POST /api/auth/step-up     – Step-up OTP generation for sensitive actions
 * POST /api/auth/verify-step-up – Verify step-up OTP
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const router = express.Router();

const User = require('../models/User');
const Device = require('../models/Device');
const OTP = require('../models/OTP');
const RefreshToken = require('../models/RefreshToken');
const { logAudit } = require('../utils/auditLogger');
const { getClientIP, parseBrowser, parseOS, generateOTP, checkImpossibleTravel, detectProxy } = require('../utils/helpers');
const { geoLookup } = require('../utils/geoLookup');
const { calculateRisk } = require('../utils/riskScorer');
const { authenticate } = require('../middleware/auth');

// ─────────────────────────────────────────────────────────
// POST /api/auth/login – Step 1
// ─────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password, deviceFingerprint } = req.body;
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || '';
    const browser = parseBrowser(ua);

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      await logAudit({ actor: email, action: 'LOGIN_FAIL', ip, browser, metadata: { reason: 'User not found' } });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is locked
    if (user.isLocked) {
      await logAudit({ actor: email, action: 'LOGIN_FAIL', ip, browser, metadata: { reason: 'Account locked' } });
      return res.status(423).json({
        error: 'Account is locked due to too many failed attempts. Try again later.',
        lockUntil: user.lockUntil
      });
    }

    // Check if account is disabled
    if (user.status === 'disabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      // Increment failed attempts
      user.failedLoginAttempts += 1;
      const maxFailed = parseInt(process.env.MAX_FAILED_LOGINS) || 5;
      if (user.failedLoginAttempts >= maxFailed) {
        const lockMinutes = parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 15;
        user.lockUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
      }
      await user.save();

      await logAudit({
        actor: email, action: 'LOGIN_FAIL', ip, browser,
        metadata: { reason: 'Wrong password', attempts: user.failedLoginAttempts }
      });

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Password is correct – generate OTP
    const otpPlain = generateOTP();
    const otpHash = await bcrypt.hash(otpPlain, 10);
    const expiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES) || 5;

    // Remove any previous unused OTPs for this user
    await OTP.deleteMany({ userId: user._id, used: false });

    await OTP.create({
      userId: user._id,
      otpHash,
      purpose: 'login',
      expiresAt: new Date(Date.now() + expiryMinutes * 60 * 1000)
    });

    // In a real system, send OTP via email/SMS.
    // For this demo, we print it to the server console.
    console.log('');
    console.log('══════════════════════════════════════════');
    console.log(`  OTP for ${user.email}: ${otpPlain}`);
    console.log(`  Purpose: login | Expires in ${expiryMinutes} min`);
    console.log('══════════════════════════════════════════');
    console.log('');

    await logAudit({
      actor: email, actorRole: user.role, action: 'OTP_SENT', ip, browser,
      metadata: { purpose: 'login' }
    });

    // Return a temporary token so the OTP verify endpoint knows which user
    const otpToken = jwt.sign(
      { userId: user._id.toString(), purpose: 'otp-verify' },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '10m' }
    );

    return res.json({
      message: 'OTP sent. Check the server console (demo).',
      otpToken,
      expiresIn: expiryMinutes * 60,
      demoOTP: otpPlain  // Demo only: show OTP in response for cloud deployment
    });

  } catch (err) {
    console.error('[Login Error]', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/verify-otp – Step 2
// ─────────────────────────────────────────────────────────
router.post('/verify-otp', async (req, res) => {
  try {
    const { otp, otpToken, deviceFingerprint } = req.body;
    const ip = getClientIP(req);
    const ua = req.headers['user-agent'] || '';
    const browser = parseBrowser(ua);

    if (!otp || !otpToken) {
      return res.status(400).json({ error: 'OTP and token are required' });
    }

    // Verify the temporary OTP token
    let decoded;
    try {
      decoded = jwt.verify(otpToken, process.env.JWT_ACCESS_SECRET);
    } catch (e) {
      return res.status(401).json({ error: 'OTP session expired. Please login again.' });
    }

    if (decoded.purpose !== 'otp-verify') {
      return res.status(401).json({ error: 'Invalid token purpose' });
    }

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    // Find the latest unused OTP for this user
    const otpRecord = await OTP.findOne({
      userId: user._id,
      purpose: 'login',
      used: false,
      expiresAt: { $gt: new Date() }
    }).sort({ createdAt: -1 });

    if (!otpRecord) {
      await logAudit({
        actor: user.email, action: 'OTP_VERIFY_FAIL', ip, browser,
        metadata: { reason: 'No valid OTP found' }
      });
      return res.status(401).json({ error: 'OTP expired or not found. Please login again.' });
    }

    // Compare OTP
    const isOtpValid = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isOtpValid) {
      await logAudit({
        actor: user.email, action: 'OTP_VERIFY_FAIL', ip, browser,
        metadata: { reason: 'Wrong OTP' }
      });
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    // Mark OTP as used
    otpRecord.used = true;
    await otpRecord.save();

    // --- Geo lookup ---
    const geo = await geoLookup(ip);

    // --- Device handling ---
    let device = null;
    let isNewDevice = false;
    if (deviceFingerprint) {
      device = await Device.findOne({ userId: user._id, fingerprint: deviceFingerprint });
      if (!device) {
        // Register new device as PENDING
        isNewDevice = true;
        device = await Device.create({
          userId: user._id,
          fingerprint: deviceFingerprint,
          browser,
          os: parseOS(ua),
          status: 'PENDING'
        });
      } else {
        device.lastSeen = new Date();
        device.browser = browser;
        await device.save();
      }
    }

    // --- Risk assessment at login ---
    const isNewCountry = user.lastLoginCountry
      ? (geo.country !== user.lastLoginCountry && geo.country !== 'Local')
      : false;
    const impossibleTravel = checkImpossibleTravel(user.lastLoginAt, user.lastLoginCountry, geo.country);
    const proxySuspected = detectProxy(req, geo.proxy);

    const risk = calculateRisk({
      isNewDevice,
      deviceTrusted: device ? device.status === 'TRUSTED' : false,
      isNewCountry,
      failedLogins: user.failedLoginAttempts,
      proxySuspected,
      impossibleTravel
    });

    // --- Reset failed attempts on successful login ---
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    user.lastLoginIP = ip;
    user.lastLoginCountry = geo.country;
    user.lastLoginAt = new Date();
    await user.save();

    // --- Issue JWT access token ---
    const accessToken = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
    );

    // --- Issue refresh token (with rotation) ---
    const refreshTokenPlain = crypto.randomUUID();
    const refreshTokenHash = crypto.createHash('sha256').update(refreshTokenPlain).digest('hex');
    const refreshExpiry = process.env.JWT_REFRESH_EXPIRY || '7d';
    const refreshExpiresAt = new Date(Date.now() + parseDuration(refreshExpiry));

    await RefreshToken.create({
      userId: user._id,
      tokenHash: refreshTokenHash,
      deviceFingerprint: deviceFingerprint || null,
      expiresAt: refreshExpiresAt
    });

    await logAudit({
      actor: user.email, actorRole: user.role,
      action: 'LOGIN_SUCCESS', ip, country: geo.country,
      browser, deviceFingerprint: deviceFingerprint || null,
      riskScore: risk.score, riskLevel: risk.level,
      metadata: { factors: risk.factors, isNewDevice, deviceStatus: device?.status }
    });

    await logAudit({
      actor: user.email, actorRole: user.role,
      action: 'OTP_VERIFIED', ip, browser,
      metadata: { purpose: 'login' }
    });

    return res.json({
      message: 'Login successful',
      accessToken,
      refreshToken: refreshTokenPlain,
      user: {
        id: user._id,
        email: user.email,
        role: user.role
      },
      device: device ? { fingerprint: device.fingerprint, status: device.status } : null,
      risk: { score: risk.score, level: risk.level, factors: risk.factors }
    });

  } catch (err) {
    console.error('[OTP Verify Error]', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/refresh – Token rotation
// ─────────────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

    const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
    const stored = await RefreshToken.findOne({ tokenHash, revoked: false });

    if (!stored || stored.expiresAt < new Date()) {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    // Revoke old token (rotation)
    stored.revoked = true;
    await stored.save();

    const user = await User.findById(stored.userId);
    if (!user || user.status === 'disabled') {
      return res.status(401).json({ error: 'User not found or disabled' });
    }

    // Issue new access token
    const accessToken = jwt.sign(
      { userId: user._id.toString(), email: user.email, role: user.role },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m' }
    );

    // Issue new refresh token
    const newRefreshPlain = crypto.randomUUID();
    const newRefreshHash = crypto.createHash('sha256').update(newRefreshPlain).digest('hex');
    const refreshExpiry = process.env.JWT_REFRESH_EXPIRY || '7d';
    const refreshExpiresAt = new Date(Date.now() + parseDuration(refreshExpiry));

    await RefreshToken.create({
      userId: user._id,
      tokenHash: newRefreshHash,
      deviceFingerprint: stored.deviceFingerprint,
      expiresAt: refreshExpiresAt
    });

    return res.json({ accessToken, refreshToken: newRefreshPlain });

  } catch (err) {
    console.error('[Refresh Error]', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/logout
// ─────────────────────────────────────────────────────────
router.post('/logout', authenticate, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) {
      const tokenHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      await RefreshToken.updateOne({ tokenHash }, { revoked: true });
    }

    await logAudit({
      actor: req.user.email, actorRole: req.user.role,
      action: 'LOGOUT', ip: getClientIP(req)
    });

    return res.json({ message: 'Logged out' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/step-up – Generate step-up OTP
// ─────────────────────────────────────────────────────────
router.post('/step-up', authenticate, async (req, res) => {
  try {
    const otpPlain = generateOTP();
    const otpHash = await bcrypt.hash(otpPlain, 10);
    const expiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES) || 5;

    await OTP.deleteMany({ userId: req.user.userId, purpose: 'step-up', used: false });

    await OTP.create({
      userId: req.user.userId,
      otpHash,
      purpose: 'step-up',
      expiresAt: new Date(Date.now() + expiryMinutes * 60 * 1000)
    });

    console.log('');
    console.log('══════════════════════════════════════════');
    console.log(`  STEP-UP OTP for ${req.user.email}: ${otpPlain}`);
    console.log(`  Purpose: step-up | Expires in ${expiryMinutes} min`);
    console.log('══════════════════════════════════════════');
    console.log('');

    await logAudit({
      actor: req.user.email, actorRole: req.user.role,
      action: 'OTP_SENT', ip: getClientIP(req),
      metadata: { purpose: 'step-up' }
    });

    return res.json({ message: 'Step-up OTP sent. Check server console.', demoOTP: otpPlain });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─────────────────────────────────────────────────────────
// POST /api/auth/verify-step-up
// ─────────────────────────────────────────────────────────
router.post('/verify-step-up', authenticate, async (req, res) => {
  try {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ error: 'OTP required' });

    const otpRecord = await OTP.findOne({
      userId: req.user.userId,
      purpose: 'step-up',
      used: false,
      expiresAt: { $gt: new Date() }
    }).sort({ createdAt: -1 });

    if (!otpRecord) {
      return res.status(401).json({ error: 'No valid step-up OTP found' });
    }

    const valid = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    otpRecord.used = true;
    await otpRecord.save();

    // Issue a short-lived step-up token (5 minutes)
    const stepUpToken = jwt.sign(
      { userId: req.user.userId, purpose: 'step-up' },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '5m' }
    );

    await logAudit({
      actor: req.user.email, actorRole: req.user.role,
      action: 'STEP_UP_VERIFIED', ip: getClientIP(req)
    });

    return res.json({ message: 'Step-up verified', stepUpToken });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─── Helper: parse duration string like '7d', '15m' to ms ───
function parseDuration(str) {
  const match = str.match(/^(\d+)(m|h|d)$/);
  if (!match) return 7 * 24 * 60 * 60 * 1000; // default 7 days
  const val = parseInt(match[1]);
  const unit = match[2];
  if (unit === 'm') return val * 60 * 1000;
  if (unit === 'h') return val * 60 * 60 * 1000;
  if (unit === 'd') return val * 24 * 60 * 60 * 1000;
  return 7 * 24 * 60 * 60 * 1000;
}

module.exports = router;
