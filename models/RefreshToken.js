/**
 * RefreshToken Model
 * ---
 * Stores hashed refresh tokens for token rotation.
 * When a refresh token is used, it is revoked and a new one is issued.
 */
const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  tokenHash: {
    type: String,
    required: true
  },
  deviceFingerprint: { type: String, default: null },
  expiresAt: { type: Date, required: true },
  revoked: { type: Boolean, default: false }
}, { timestamps: true });

// Auto-expire documents after their expiresAt date
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
