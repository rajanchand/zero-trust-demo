/**
 * User Model
 * ---
 * Stores user credentials, role, and lockout info.
 * Roles: user | supervisor | admin | superadmin
 */
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['user', 'supervisor', 'admin', 'superadmin'],
    default: 'user'
  },
  status: {
    type: String,
    enum: ['active', 'disabled'],
    default: 'active'
  },
  // --- Account lockout ---
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  // --- Active session enforcement (max 1 session per user) ---
  activeSessionHash: { type: String, default: null },
  activeSessionIP: { type: String, default: null },
  activeSessionCountry: { type: String, default: null },
  activeSessionStartedAt: { type: Date, default: null },
  // --- Suspicious activity tracking ---
  suspiciousEventCount: { type: Number, default: 0 },
  suspiciousLockUntil: { type: Date, default: null },
  lastSuspiciousEvent: { type: String, default: null },
  // --- Location context ---
  lastLoginIP: { type: String, default: null },
  lastLoginCountry: { type: String, default: null },
  lastLoginAt: { type: Date, default: null }
}, { timestamps: true });

/**
 * Virtual: check if account is currently locked
 */
userSchema.virtual('isLocked').get(function () {
  return this.lockUntil && this.lockUntil > new Date();
});

/**
 * Virtual: check if account is temporarily locked due to suspicious activity
 */
userSchema.virtual('isSuspiciousLocked').get(function () {
  return this.suspiciousLockUntil && this.suspiciousLockUntil > new Date();
});

module.exports = mongoose.model('User', userSchema);
