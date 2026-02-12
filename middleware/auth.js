/**
 * Authentication Middleware
 * ---
 * Verifies the JWT access token on protected routes.
 * Attaches user info to req.user for downstream handlers.
 */
const jwt = require('jsonwebtoken');
const User = require('../models/User');

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

    // Attach user info to request
    req.user = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      lastLoginIP: user.lastLoginIP,
      lastLoginCountry: user.lastLoginCountry,
      lastLoginAt: user.lastLoginAt,
      failedLoginAttempts: user.failedLoginAttempts
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
