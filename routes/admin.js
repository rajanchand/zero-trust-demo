/**
 * Admin / Dashboard Routes
 * ---
 * GET /api/admin/logs         – Audit logs with filtering
 * GET /api/admin/stats        – Dashboard statistics
 * GET /api/admin/policy-rules – Current policy rules
 */
const express = require('express');
const router = express.Router();

const AuditLog = require('../models/AuditLog');
const User = require('../models/User');
const Device = require('../models/Device');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { continuousVerify } = require('../middleware/continuousVerify');
const { getPolicyRules } = require('../utils/policyEngine');

// ─── GET /api/admin/logs ────────────────────────────────
router.get('/logs',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('admin'),
  async (req, res) => {
    try {
      const { actor, action, decision, from, to, page = 1, limit = 50 } = req.query;

      // Build filter
      const filter = {};
      if (actor) filter.actor = new RegExp(actor, 'i');
      if (action) filter.action = new RegExp(action, 'i');
      if (decision && decision !== 'all') filter.decision = decision;
      if (from || to) {
        filter.timestamp = {};
        if (from) filter.timestamp.$gte = new Date(from);
        if (to) filter.timestamp.$lte = new Date(to);
      }

      const skip = (parseInt(page) - 1) * parseInt(limit);
      const total = await AuditLog.countDocuments(filter);
      const logs = await AuditLog.find(filter)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean();

      return res.json({ logs, total, page: parseInt(page), limit: parseInt(limit) });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── GET /api/admin/stats ───────────────────────────────
router.get('/stats',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('admin'),
  async (req, res) => {
    try {
      const totalUsers = await User.countDocuments();
      const activeUsers = await User.countDocuments({ status: 'active' });
      const totalDevices = await Device.countDocuments();
      const pendingDevices = await Device.countDocuments({ status: 'PENDING' });
      const trustedDevices = await Device.countDocuments({ status: 'TRUSTED' });
      const blockedDevices = await Device.countDocuments({ status: 'BLOCKED' });

      // Recent log stats (last 24 hours)
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const recentLogs = await AuditLog.countDocuments({ timestamp: { $gte: since } });
      const recentDenials = await AuditLog.countDocuments({
        timestamp: { $gte: since }, decision: 'DENY'
      });
      const recentLogins = await AuditLog.countDocuments({
        timestamp: { $gte: since }, action: 'LOGIN_SUCCESS'
      });
      const recentFailedLogins = await AuditLog.countDocuments({
        timestamp: { $gte: since }, action: 'LOGIN_FAIL'
      });

      // Role breakdown
      const roles = await User.aggregate([
        { $group: { _id: '$role', count: { $sum: 1 } } }
      ]);

      return res.json({
        users: { total: totalUsers, active: activeUsers, roles },
        devices: { total: totalDevices, pending: pendingDevices, trusted: trustedDevices, blocked: blockedDevices },
        last24h: { logs: recentLogs, denials: recentDenials, logins: recentLogins, failedLogins: recentFailedLogins }
      });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── GET /api/admin/stats/details ───────────────────────
// Returns detailed records for a given stat type (clickable stat cards)
router.get('/stats/details',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('admin'),
  async (req, res) => {
    try {
      const { type } = req.query;
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

      switch (type) {
        case 'total-users': {
          const users = await User.find().select('-passwordHash').sort({ createdAt: -1 }).lean();
          return res.json({ title: 'All Users', columns: ['Email', 'Role', 'Status', 'Last Login', 'Last IP', 'Last Country'], rows: users.map(u => [u.email, u.role, u.status, u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never', u.lastLoginIP || '—', u.lastLoginCountry || '—']) });
        }
        case 'active-users': {
          const users = await User.find({ status: 'active' }).select('-passwordHash').sort({ createdAt: -1 }).lean();
          return res.json({ title: 'Active Users', columns: ['Email', 'Role', 'Last Login', 'Last IP', 'Last Country'], rows: users.map(u => [u.email, u.role, u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : 'Never', u.lastLoginIP || '—', u.lastLoginCountry || '—']) });
        }
        case 'total-devices': {
          const devices = await Device.find().populate('userId', 'email').sort({ lastSeen: -1 }).lean();
          return res.json({ title: 'All Devices', columns: ['User', 'Fingerprint', 'Status', 'Browser', 'OS', 'Last Seen'], rows: devices.map(d => [d.userId?.email || '—', d.fingerprint, d.status, d.browser || '—', d.os || '—', new Date(d.lastSeen).toLocaleString()]) });
        }
        case 'pending-devices': {
          const devices = await Device.find({ status: 'PENDING' }).populate('userId', 'email').sort({ lastSeen: -1 }).lean();
          return res.json({ title: 'Pending Devices', columns: ['User', 'Fingerprint', 'Browser', 'OS', 'First Seen'], rows: devices.map(d => [d.userId?.email || '—', d.fingerprint, d.browser || '—', d.os || '—', new Date(d.firstSeen || d.createdAt).toLocaleString()]) });
        }
        case 'trusted-devices': {
          const devices = await Device.find({ status: 'TRUSTED' }).populate('userId', 'email').populate('approvedBy', 'email').sort({ lastSeen: -1 }).lean();
          return res.json({ title: 'Trusted Devices', columns: ['User', 'Fingerprint', 'Browser', 'OS', 'Approved By', 'Last Seen'], rows: devices.map(d => [d.userId?.email || '—', d.fingerprint, d.browser || '—', d.os || '—', d.approvedBy?.email || '—', new Date(d.lastSeen).toLocaleString()]) });
        }
        case 'blocked-devices': {
          const devices = await Device.find({ status: 'BLOCKED' }).populate('userId', 'email').sort({ lastSeen: -1 }).lean();
          return res.json({ title: 'Blocked Devices', columns: ['User', 'Fingerprint', 'Browser', 'OS', 'Last Seen'], rows: devices.map(d => [d.userId?.email || '—', d.fingerprint, d.browser || '—', d.os || '—', new Date(d.lastSeen).toLocaleString()]) });
        }
        case 'logins-24h': {
          const logs = await AuditLog.find({ timestamp: { $gte: since }, action: 'LOGIN_SUCCESS' }).sort({ timestamp: -1 }).lean();
          return res.json({ title: 'Successful Logins (Last 24h)', columns: ['Time', 'User', 'Role', 'IP', 'Country', 'Browser', 'Device FP'], rows: logs.map(l => [new Date(l.timestamp).toLocaleString(), l.actor, l.actorRole || '—', l.ip || '—', l.country || '—', l.browser || '—', l.deviceFingerprint ? l.deviceFingerprint.slice(0, 12) : '—']) });
        }
        case 'failed-logins-24h': {
          const logs = await AuditLog.find({ timestamp: { $gte: since }, action: 'LOGIN_FAIL' }).sort({ timestamp: -1 }).lean();
          return res.json({ title: 'Failed Logins (Last 24h)', columns: ['Time', 'User', 'IP', 'Browser', 'Reason'], rows: logs.map(l => [new Date(l.timestamp).toLocaleString(), l.actor, l.ip || '—', l.browser || '—', l.metadata?.reason || '—']) });
        }
        case 'denials-24h': {
          const logs = await AuditLog.find({ timestamp: { $gte: since }, decision: 'DENY' }).sort({ timestamp: -1 }).lean();
          return res.json({ title: 'Policy Denials (Last 24h)', columns: ['Time', 'User', 'Role', 'Endpoint', 'Rule', 'Risk', 'IP', 'Country'], rows: logs.map(l => [new Date(l.timestamp).toLocaleString(), l.actor, l.actorRole || '—', l.endpoint || '—', l.matchedRule || '—', l.riskScore != null ? l.riskScore : '—', l.ip || '—', l.country || '—']) });
        }
        case 'events-24h': {
          const logs = await AuditLog.find({ timestamp: { $gte: since } }).sort({ timestamp: -1 }).limit(100).lean();
          return res.json({ title: 'All Events (Last 24h, latest 100)', columns: ['Time', 'User', 'Action', 'Decision', 'IP', 'Country', 'Browser'], rows: logs.map(l => [new Date(l.timestamp).toLocaleString(), l.actor, l.action, l.decision, l.ip || '—', l.country || '—', l.browser || '—']) });
        }
        default:
          return res.status(400).json({ error: 'Invalid stat type' });
      }
    } catch (err) {
      console.error('[Stats Detail Error]', err);
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── GET /api/admin/policy-rules ────────────────────────
router.get('/policy-rules',
  authenticate,
  authorize('superadmin'),
  continuousVerify('superadmin'),
  async (req, res) => {
    try {
      const rules = getPolicyRules();
      return res.json({ rules });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

module.exports = router;
