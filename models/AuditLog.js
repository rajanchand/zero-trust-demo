/**
 * AuditLog Model
 * ---
 * Central audit trail for all significant events:
 * logins, OTP events, policy decisions, admin actions, etc.
 */
const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  actor: { type: String, default: 'system' },           // email or 'system'
  actorRole: { type: String, default: null },
  action: { type: String, required: true },              // e.g. 'LOGIN_SUCCESS', 'POLICY_DENY'
  endpoint: { type: String, default: null },             // e.g. '/api/auth/login'
  decision: {
    type: String,
    enum: ['ALLOW', 'DENY', 'STEP_UP', 'N/A'],
    default: 'N/A'
  },
  riskScore: { type: Number, default: null },
  riskLevel: { type: String, default: null },
  matchedRule: { type: String, default: null },          // which policy rule triggered
  ip: { type: String, default: null },
  country: { type: String, default: 'Unknown' },
  deviceFingerprint: { type: String, default: null },
  browser: { type: String, default: null },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  timestamp: { type: Date, default: Date.now }
});

// Index for efficient querying on the dashboard
auditLogSchema.index({ timestamp: -1 });
auditLogSchema.index({ actor: 1 });
auditLogSchema.index({ action: 1 });

module.exports = mongoose.model('AuditLog', auditLogSchema);
