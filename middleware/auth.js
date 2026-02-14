/**
 * Authentication Middleware
 * ---
 * Verifies the JWT access token on protected routes.
 * Attaches user info to req.user for downstream handlers.
 * Enforces max 1 active session per user.
 * Checks for suspicious activity temporary lock.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User');
const { logAudit } = require('../utils/auditLogger');
const { getClientIP } = require('../utils/helpers');

async function authenticate(req, res, next) {
  try {
    // Get token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const token = authHeader.split(' ')[1];

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    // Fetch user from DB to ensure they still exist and are active
    const user = await User.findById(decoded.userId).lean();
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    if (user.status === 'disabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }

    // Check suspicious activity temporary lock
    if (user.suspiciousLockUntil && user.suspiciousLockUntil > new Date()) {
      const remainingMs = user.suspiciousLockUntil - new Date();
      const remainingMin = Math.ceil(remainingMs / 60000);
      return res.status(423).json({
        error: `Account temporarily locked due to suspicious activity. Try again in ${remainingMin} minute(s).`,
        code: 'SUSPICIOUS_LOCK',
        lockUntil: user.suspiciousLockUntil
      });
    }

    // Enforce max 1 active session: validate session token hash
    if (user.activeSessionHash) {
      const currentTokenHash = crypto.createHash('sha256').update(token).digest('hex');
      if (user.activeSessionHash !== currentTokenHash) {
        const ip = getClientIP(req);
        await logAudit({
          actor: user.email, actorRole: user.role,
          action: 'SESSION_INVALIDATED',
          ip,
          metadata: { reason: 'Another session is active – this session was invalidated' }
        });
        return res.status(401).json({
          error: 'Session expired. You have been logged in from another location.',
          code: 'SESSION_REPLACED'
        });
      }
    }

    // Attach user info to request (including session context for continuous verify)
    req.user = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      lastLoginIP: user.lastLoginIP,
      lastLoginCountry: user.lastLoginCountry,
      lastLoginAt: user.lastLoginAt,
      failedLoginAttempts: user.failedLoginAttempts,
      activeSessionIP: user.activeSessionIP,
      activeSessionCountry: user.activeSessionCountry,
      suspiciousEventCount: user.suspiciousEventCount || 0
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = { authenticate };
