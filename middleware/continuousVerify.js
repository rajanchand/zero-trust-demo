/**
 * Continuous Verification Middleware
 * ---
 * This is the Zero Trust "never trust, always verify" layer.
 *
 * On every API request it:
 *  1. Looks up the user's device by fingerprint
 *  2. Gathers geo/IP context
 *  3. Computes a risk score
 *  4. Runs the policy engine
 *  5. Logs the decision
 *  6. Blocks, allows, or requests step-up auth
 *
 * Endpoint sensitivity is set via req.endpointSensitivity before this middleware runs.
 */
const Device = require('../models/Device');
const { geoLookup } = require('../utils/geoLookup');
const { calculateRisk } = require('../utils/riskScorer');
const { evaluatePolicy } = require('../utils/policyEngine');
const { logAudit } = require('../utils/auditLogger');
const { getClientIP, parseBrowser, parseOS, checkImpossibleTravel, detectProxy } = require('../utils/helpers');

/**
 * Factory: returns middleware configured for a given endpoint sensitivity level.
 * @param {string} sensitivity - public | normal | supervisor | admin | destructive | superadmin
 */
function continuousVerify(sensitivity = 'normal') {
  return async (req, res, next) => {
    try {
      const ip = getClientIP(req);
      const ua = req.headers['user-agent'] || '';
      const browser = parseBrowser(ua);
      const fingerprint = req.headers['x-device-fingerprint'] || 'unknown';

      // 1. Geo lookup
      const geo = await geoLookup(ip);

      // 2. Device lookup
      let device = null;
      let isNewDevice = false;
      let deviceTrusted = false;
      let deviceStatus = 'PENDING';

      if (req.user && fingerprint !== 'unknown') {
        device = await Device.findOne({ userId: req.user.userId, fingerprint });
        if (device) {
          deviceTrusted = device.status === 'TRUSTED';
          deviceStatus = device.status;
          // Update last seen
          device.lastSeen = new Date();
          await device.save();
        } else {
          isNewDevice = true;
        }
      }

      // 3. Check for country change and impossible travel
      const isNewCountry = req.user?.lastLoginCountry
        ? (geo.country !== req.user.lastLoginCountry && geo.country !== 'Local')
        : false;

      const impossibleTravel = checkImpossibleTravel(
        req.user?.lastLoginAt,
        req.user?.lastLoginCountry,
        geo.country
      );

      const proxySuspected = detectProxy(req, geo.proxy);

      // 4. Risk score
      const risk = calculateRisk({
        isNewDevice,
        deviceTrusted,
        isNewCountry,
        failedLogins: req.user?.failedLoginAttempts || 0,
        proxySuspected,
        impossibleTravel
      });

      // 5. Policy engine
      const policyResult = evaluatePolicy({
        role: req.user?.role || 'user',
        deviceTrusted,
        deviceStatus,
        riskScore: risk.score,
        riskLevel: risk.level,
        endpointSensitivity: sensitivity
      });

      // Attach context to request for downstream use
      req.riskContext = {
        ip,
        country: geo.country,
        isp: geo.isp,
        browser,
        os: parseOS(ua),
        fingerprint,
        deviceTrusted,
        deviceStatus,
        isNewDevice,
        isNewCountry,
        impossibleTravel,
        proxySuspected,
        riskScore: risk.score,
        riskLevel: risk.level,
        riskFactors: risk.factors,
        policyDecision: policyResult.decision,
        policyRule: policyResult.rule,
        policyReason: policyResult.reason
      };

      // 6. Log the decision
      await logAudit({
        actor: req.user?.email || 'anonymous',
        actorRole: req.user?.role || null,
        action: `POLICY_${policyResult.decision}`,
        endpoint: req.originalUrl,
        decision: policyResult.decision,
        riskScore: risk.score,
        riskLevel: risk.level,
        matchedRule: policyResult.rule,
        ip,
        country: geo.country,
        deviceFingerprint: fingerprint,
        browser,
        metadata: { factors: risk.factors, reason: policyResult.reason }
      });

      // 7. Enforce decision
      if (policyResult.decision === 'DENY') {
        return res.status(403).json({
          error: 'Access denied by policy engine',
          rule: policyResult.rule,
          reason: policyResult.reason,
          riskScore: risk.score,
          riskLevel: risk.level
        });
      }

      if (policyResult.decision === 'STEP_UP') {
        return res.status(403).json({
          error: 'Step-up authentication required',
          code: 'STEP_UP_REQUIRED',
          rule: policyResult.rule,
          reason: policyResult.reason,
          riskScore: risk.score
        });
      }

      // ALLOW – continue
      next();
    } catch (err) {
      console.error('[ContinuousVerify] Error:', err.message);
      // Fail closed: deny on error (Zero Trust principle)
      return res.status(500).json({ error: 'Security verification failed' });
    }
  };
}

module.exports = { continuousVerify };
