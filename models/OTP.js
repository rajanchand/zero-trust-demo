/**
 * OTP Model
 * ---
 * Stores one-time passwords for login verification and step-up auth.
 * OTP is hashed before storage. Documents auto-expire.
 */
const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  otpHash: {
    type: String,
    required: true
  },
  purpose: {
    type: String,
    enum: ['login', 'step-up'],
    default: 'login'
  },
  used: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true }
}, { timestamps: true });

// Auto-expire after the OTP's expiry time
otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('OTP', otpSchema);
