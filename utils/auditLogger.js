/**
 * Audit Logger Utility
 * ---
 * Central function to write audit log entries to MongoDB.
 * Called from routes and middleware throughout the app.
 */
const AuditLog = require('../models/AuditLog');

/**
 * Write an audit log entry.
 * @param {Object} entry - Log data
 */
async function logAudit(entry) {
  try {
    await AuditLog.create({
      actor: entry.actor || 'system',
      actorRole: entry.actorRole || null,
      action: entry.action,
      endpoint: entry.endpoint || null,
      decision: entry.decision || 'N/A',
      riskScore: entry.riskScore ?? null,
      riskLevel: entry.riskLevel || null,
      matchedRule: entry.matchedRule || null,
      ip: entry.ip || null,
      country: entry.country || 'Unknown',
      deviceFingerprint: entry.deviceFingerprint || null,
      browser: entry.browser || null,
      metadata: entry.metadata || {},
      timestamp: new Date()
    });
  } catch (err) {
    // Audit logging should never crash the app
    console.error('[AuditLog] Failed to write log:', err.message);
  }
}

module.exports = { logAudit };
