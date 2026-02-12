/**
 * User Management Routes
 * ---
 * CRUD operations for users. Access controlled by RBAC + policy engine.
 *
 * GET    /api/users          – List users (supervisor+)
 * POST   /api/users          – Create user (supervisor+)
 * PUT    /api/users/:id      – Update user (admin+)
 * PUT    /api/users/:id/role – Change role (admin+)
 * DELETE /api/users/:id      – Delete user (admin+ with step-up)
 * GET    /api/users/me       – Get own profile (any authenticated)
 */
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

const User = require('../models/User');
const Device = require('../models/Device');
const { authenticate } = require('../middleware/auth');
const { authorize } = require('../middleware/rbac');
const { continuousVerify } = require('../middleware/continuousVerify');
const { logAudit } = require('../utils/auditLogger');
const { validatePassword } = require('../utils/passwordPolicy');
const { getClientIP } = require('../utils/helpers');

// ─── GET /api/users/me ─────────────────────────────────
router.get('/me', authenticate, continuousVerify('normal'), async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-passwordHash').lean();
    if (!user) return res.status(404).json({ error: 'User not found' });

    const devices = await Device.find({ userId: user._id }).lean();

    return res.json({
      user,
      devices,
      riskContext: req.riskContext
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ─── GET /api/users ─────────────────────────────────────
router.get('/',
  authenticate,
  authorize('supervisor', 'admin', 'superadmin'),
  continuousVerify('supervisor'),
  async (req, res) => {
    try {
      const users = await User.find()
        .select('-passwordHash')
        .sort({ createdAt: -1 })
        .lean();
      return res.json({ users });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── POST /api/users ────────────────────────────────────
router.post('/',
  authenticate,
  authorize('supervisor', 'admin', 'superadmin'),
  continuousVerify('supervisor'),
  async (req, res) => {
    try {
      const { email, password, role } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
      }

      // Validate password policy
      const pwCheck = validatePassword(password);
      if (!pwCheck.valid) {
        return res.status(400).json({ error: 'Password policy violation', details: pwCheck.errors });
      }

      // Supervisors can only create 'user' role
      const assignedRole = role || 'user';
      if (req.user.role === 'supervisor' && assignedRole !== 'user') {
        return res.status(403).json({ error: 'Supervisors can only create users with "user" role' });
      }

      // Check for existing email
      const existing = await User.findOne({ email: email.toLowerCase().trim() });
      if (existing) {
        return res.status(409).json({ error: 'Email already exists' });
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const user = await User.create({
        email: email.toLowerCase().trim(),
        passwordHash,
        role: assignedRole
      });

      await logAudit({
        actor: req.user.email, actorRole: req.user.role,
        action: 'USER_CREATED', ip: getClientIP(req),
        endpoint: '/api/users',
        metadata: { targetEmail: user.email, targetRole: user.role }
      });

      return res.status(201).json({
        message: 'User created',
        user: { id: user._id, email: user.email, role: user.role }
      });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── PUT /api/users/:id ─────────────────────────────────
router.put('/:id',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('admin'),
  async (req, res) => {
    try {
      const { email, status } = req.body;
      const updates = {};
      if (email) updates.email = email.toLowerCase().trim();
      if (status) updates.status = status;

      const user = await User.findByIdAndUpdate(req.params.id, updates, { new: true })
        .select('-passwordHash');
      if (!user) return res.status(404).json({ error: 'User not found' });

      await logAudit({
        actor: req.user.email, actorRole: req.user.role,
        action: 'USER_UPDATED', ip: getClientIP(req),
        metadata: { targetId: req.params.id, updates }
      });

      return res.json({ message: 'User updated', user });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── PUT /api/users/:id/role ────────────────────────────
router.put('/:id/role',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('admin'),
  async (req, res) => {
    try {
      const { role } = req.body;
      const validRoles = ['user', 'supervisor', 'admin', 'superadmin'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
      }

      // Only superadmin can promote to superadmin
      if (role === 'superadmin' && req.user.role !== 'superadmin') {
        return res.status(403).json({ error: 'Only superadmin can assign superadmin role' });
      }

      const user = await User.findByIdAndUpdate(req.params.id, { role }, { new: true })
        .select('-passwordHash');
      if (!user) return res.status(404).json({ error: 'User not found' });

      await logAudit({
        actor: req.user.email, actorRole: req.user.role,
        action: 'ROLE_CHANGED', ip: getClientIP(req),
        metadata: { targetId: req.params.id, newRole: role }
      });

      return res.json({ message: 'Role updated', user });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

// ─── DELETE /api/users/:id ──────────────────────────────
router.delete('/:id',
  authenticate,
  authorize('admin', 'superadmin'),
  continuousVerify('destructive'),
  async (req, res) => {
    try {
      // Require step-up token for destructive actions
      const stepUpToken = req.headers['x-step-up-token'];
      if (stepUpToken) {
        try {
          const decoded = jwt.verify(stepUpToken, process.env.JWT_ACCESS_SECRET);
          if (decoded.purpose !== 'step-up') throw new Error('wrong purpose');
        } catch (e) {
          return res.status(403).json({ error: 'Invalid step-up token', code: 'STEP_UP_REQUIRED' });
        }
      }

      // Prevent deleting yourself
      if (req.params.id === req.user.userId) {
        return res.status(400).json({ error: 'Cannot delete your own account' });
      }

      const user = await User.findByIdAndDelete(req.params.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      // Clean up devices and tokens
      await Device.deleteMany({ userId: req.params.id });

      await logAudit({
        actor: req.user.email, actorRole: req.user.role,
        action: 'USER_DELETED', ip: getClientIP(req),
        metadata: { targetEmail: user.email }
      });

      return res.json({ message: 'User deleted' });
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  }
);

module.exports = router;
