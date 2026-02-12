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
