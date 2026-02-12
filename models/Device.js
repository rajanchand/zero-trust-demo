/**
 * Device Model
 * ---
 * Tracks devices per user. New devices start as PENDING and must
 * be approved by a supervisor/admin/superadmin before they become TRUSTED.
 */
const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fingerprint: {
    type: String,
    required: true
  },
  browser: { type: String, default: 'Unknown' },
  os: { type: String, default: 'Unknown' },
  status: {
    type: String,
    enum: ['PENDING', 'TRUSTED', 'BLOCKED'],
    default: 'PENDING'
  },
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now }
}, { timestamps: true });

// Compound index: one fingerprint per user
deviceSchema.index({ userId: 1, fingerprint: 1 }, { unique: true });

module.exports = mongoose.model('Device', deviceSchema);
