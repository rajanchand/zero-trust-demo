/**
 * Device Management Routes
 * ---
 * GET  /api/devices           – List all devices (supervisor+)
 * GET  /api/devices/pending   – List pending devices (supervisor+)
 * PUT  /api/devices/:id/approve – Approve a device (supervisor+)
 * PUT  /api/devices/:id/block   – Block a device (admin+)
 */
const express = require('express');
const router = express.Router();

const Device = require('../models/Device');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { continuousVerify } = require('../middleware/continuousVerify');
const { logAudit } = require('../utils/auditLogger');
const { getClientIP } = require('../utils/helpers');

// ─── GET /api/devices ───────────────────────────────────
router.get('/',
  authenticate,
  authorize('supervisor', 'admin', 'superadmin'),
  continuousVerify('supervisor'),
  async (req, res) => {
    try {
      const devices = await Device.find()
        .populate('userId', 'email role')
        .populate('approvedBy', 'email')
        .sort({ createdAt: -1 })
        .lean();
      return res.json({ devices });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── GET /api/devices/pending ───────────────────────────
router.get('/pending',
  authenticate,
  authorize('supervisor', 'admin', 'superadmin'),
  continuousVerify('supervisor'),
  async (req, res) => {
    try {
      const devices = await Device.find({ status: 'PENDING' })
        .populate('userId', 'email role')
        .sort({ createdAt: -1 })
        .lean();
      return res.json({ devices });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── PUT /api/devices/:id/approve ───────────────────────
router.put('/:id/approve',
  authenticate,
  authorize('supervisor', 'admin', 'superadmin'),
  continuousVerify('supervisor'),
  async (req, res) => {
    try {
      const device = await Device.findById(req.params.id);
      if (!device) return res.status(404).json({ error: 'Device not found' });

      device.status = 'TRUSTED';
      device.approvedBy = req.user.userId;
      await device.save();

      // Get user email for the log
      const targetUser = await User.findById(device.userId).select('email').lean();

      await logAudit({
        actor: req.user.email, actorRole: req.user.role,
        action: 'DEVICE_APPROVED', ip: getClientIP(req),
        deviceFingerprint: device.fingerprint,
        metadata: { targetUser: targetUser?.email, deviceId: device._id }
      });

      return res.json({ message: 'Device approved', device });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── PUT /api/devices/:id/block ─────────────────────────
router.put('/:id/block',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('admin'),
  async (req, res) => {
    try {
      const device = await Device.findById(req.params.id);
      if (!device) return res.status(404).json({ error: 'Device not found' });

      device.status = 'BLOCKED';
      await device.save();

      await logAudit({
        actor: req.user.email, actorRole: req.user.role,
        action: 'DEVICE_BLOCKED', ip: getClientIP(req),
        deviceFingerprint: device.fingerprint,
        metadata: { deviceId: device._id }
      });

      return res.json({ message: 'Device blocked', device });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

module.exports = router;
