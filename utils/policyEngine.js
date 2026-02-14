/**
 * Zero Trust Policy Engine
 * ---
 * Central decision maker: ALLOW / DENY / STEP_UP
 *
 * Every API request passes through this engine.
 * Decisions are based on:
 *   - User role
 *   - Device trust status
 *   - Risk score
 *   - Endpoint sensitivity
 *
 * This is the heart of the Zero Trust architecture.
 */

// ─── Policy Rules ──────────────────────────────────────────
// Each rule is checked in order. First match wins.
const POLICY_RULES = [
  // --- Suspicious activity lock: temporary account lock ---
  {
    id: 'SUSPICIOUS_ACTIVITY_LOCK',
    description: 'Deny access if account is temporarily locked due to repeated suspicious activity',
    match: (ctx) => ctx.isSuspiciousLocked === true,
    decision: 'DENY',
    reason: 'Account temporarily locked due to repeated suspicious activity'
  },

  // --- Session hijack / IP change mid-session ---
  {
    id: 'SESSION_COUNTRY_CHANGE',
    description: 'Deny if country changed mid-session (possible session hijack)',
    match: (ctx) => ctx.countryChangedMidSession === true && ctx.role !== 'superadmin',
    decision: 'DENY',
    reason: 'Country changed mid-session – possible session hijack'
  },
  {
    id: 'SESSION_IP_CHANGE_HIGH_RISK',
    description: 'Step-up OTP if IP changed mid-session with elevated risk',
    match: (ctx) => ctx.ipChangedMidSession === true && ctx.riskScore >= 50,
    decision: 'STEP_UP',
    reason: 'IP address changed mid-session – re-verify your identity'
  },
  {
    id: 'SESSION_IP_CHANGE',
    description: 'Step-up OTP if IP changed mid-session',
    match: (ctx) => ctx.ipChangedMidSession === true,
    decision: 'STEP_UP',
    reason: 'IP address changed mid-session – step-up authentication required'
  },

  // --- Super-sensitive: Admin panel access ---
  {
    id: 'ADMIN_PANEL_HIGH_RISK',
    description: 'Deny admin panel if risk is HIGH',
    match: (ctx) => ctx.endpointSensitivity === 'admin' && ctx.riskLevel === 'HIGH',
    decision: 'DENY',
    reason: 'Risk too high for admin panel access'
  },
  {
    id: 'ADMIN_PANEL_UNTRUSTED_DEVICE',
    description: 'Deny admin panel from untrusted device (superadmin exempt)',
    match: (ctx) => ctx.endpointSensitivity === 'admin' && !ctx.deviceTrusted && ctx.role !== 'superadmin',
    decision: 'DENY',
    reason: 'Admin panel requires a trusted device'
  },
  {
    id: 'ADMIN_PANEL_ROLE_CHECK',
    description: 'Only admin/superadmin can access admin panel',
    match: (ctx) => ctx.endpointSensitivity === 'admin' && !['admin', 'superadmin'].includes(ctx.role),
    decision: 'DENY',
    reason: 'Insufficient role for admin panel'
  },

  // --- Destructive actions (delete user, change role) ---
  {
    id: 'DESTRUCTIVE_HIGH_RISK',
    description: 'Step-up auth for destructive actions at medium+ risk',
    match: (ctx) => ctx.endpointSensitivity === 'destructive' && ctx.riskScore >= 40,
    decision: 'STEP_UP',
    reason: 'Elevated risk requires OTP re-verification for this action'
  },
  {
    id: 'DESTRUCTIVE_ROLE_CHECK',
    description: 'Only admin/superadmin can perform destructive actions',
    match: (ctx) => ctx.endpointSensitivity === 'destructive' && !['admin', 'superadmin'].includes(ctx.role),
    decision: 'DENY',
    reason: 'Insufficient role for destructive actions'
  },

  // --- Supervisor actions (create user, approve device) ---
  {
    id: 'SUPERVISOR_ROLE_CHECK',
    description: 'Supervisor+ can create users and approve devices',
    match: (ctx) => ctx.endpointSensitivity === 'supervisor' && !['supervisor', 'admin', 'superadmin'].includes(ctx.role),
    decision: 'DENY',
    reason: 'Requires supervisor role or higher'
  },

  // --- Security dashboard (superadmin only) ---
  {
    id: 'SECURITY_DASH_ROLE',
    description: 'Only superadmin can view security dashboard & policy settings',
    match: (ctx) => ctx.endpointSensitivity === 'superadmin' && ctx.role !== 'superadmin',
    decision: 'DENY',
    reason: 'Only superadmin can access this resource'
  },

  // --- General: very high risk on any endpoint ---
  {
    id: 'GENERAL_EXTREME_RISK',
    description: 'Deny any request with risk score ≥ 80',
    match: (ctx) => ctx.riskScore >= 80,
    decision: 'DENY',
    reason: 'Extreme risk score – access denied'
  },

  // --- General: high risk requires step-up ---
  {
    id: 'GENERAL_HIGH_RISK_STEPUP',
    description: 'Step-up auth when risk score is 60–79',
    match: (ctx) => ctx.riskScore >= 60 && ctx.endpointSensitivity !== 'public',
    decision: 'STEP_UP',
    reason: 'High risk detected – verify your identity via OTP'
  },

  // --- Device pending: limited access ---
  {
    id: 'DEVICE_PENDING_BLOCK',
    description: 'Block most actions from pending devices (superadmin exempt)',
    match: (ctx) => ctx.deviceStatus === 'PENDING' && ctx.endpointSensitivity !== 'public' && ctx.role !== 'superadmin',
    decision: 'DENY',
    reason: 'Device is pending approval'
  }
];

/**
 * Evaluate the policy engine.
 * @param {Object} ctx
 * @param {string} ctx.role              - User role
 * @param {boolean} ctx.deviceTrusted    - Is device approved?
 * @param {string} ctx.deviceStatus      - PENDING / TRUSTED / BLOCKED
 * @param {number} ctx.riskScore         - 0–100
 * @param {string} ctx.riskLevel         - LOW / MEDIUM / HIGH
 * @param {string} ctx.endpointSensitivity - public / normal / supervisor / admin / destructive / superadmin
 * @returns {{ decision: string, rule: string|null, reason: string }}
 */
function evaluatePolicy(ctx) {
  for (const rule of POLICY_RULES) {
    if (rule.match(ctx)) {
      return {
        decision: rule.decision,
        rule: rule.id,
        reason: rule.reason
      };
    }
  }

  // Default: ALLOW
  return { decision: 'ALLOW', rule: 'DEFAULT_ALLOW', reason: 'No blocking rule matched' };
}

/**
 * Get all policy rules for display on the policy summary page.
 */
function getPolicyRules() {
  return POLICY_RULES.map(r => ({
    id: r.id,
    description: r.description,
    decision: r.decision,
    reason: r.reason
  }));
}

module.exports = { evaluatePolicy, getPolicyRules };
