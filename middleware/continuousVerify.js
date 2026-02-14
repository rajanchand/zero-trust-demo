/**
 * Continuous Verification Middleware
 * ---
 * This is the Zero Trust "never trust, always verify" layer.
 *
 * On every API request it:
 *  1. Looks up the user's device by fingerprint
 *  2. Gathers geo/IP context
 *  3. Detects IP/location changes mid-session
 *  4. Computes a risk score
 *  5. Runs the policy engine
 *  6. Tracks suspicious activity & auto-locks if repeated
 *  7. Logs the decision
 *  8. Blocks, allows, or requests step-up auth
 *
 * Endpoint sensitivity is set via req.endpointSensitivity before this middleware runs.
 */
const Device = require('../models/Device');
const User = require('../models/User');
const { geoLookup } = require('../utils/geoLookup');
const { calculateRisk } = require('../utils/riskScorer');
const { evaluatePolicy } = require('../utils/policyEngine');
const { logAudit } = require('../utils/auditLogger');
const { getClientIP, parseBrowser, parseOS, checkImpossibleTravel, detectProxy } = require('../utils/helpers');

// Threshold for suspicious events before temporary lock
const SUSPICIOUS_LOCK_THRESHOLD = parseInt(process.env.SUSPICIOUS_LOCK_THRESHOLD) || 5;
const SUSPICIOUS_LOCK_MINUTES = parseInt(process.env.SUSPICIOUS_LOCK_MINUTES) || 30;

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

      // 3. Check for country change and impossible travel (vs last login)
      const isNewCountry = req.user?.lastLoginCountry
        ? (geo.country !== req.user.lastLoginCountry && geo.country !== 'Local')
        : false;

      const impossibleTravel = checkImpossibleTravel(
        req.user?.lastLoginAt,
        req.user?.lastLoginCountry,
        geo.country
      );

      const proxySuspected = detectProxy(req, geo.proxy);

      // 4. Detect IP/location change MID-SESSION (vs session start IP)
      let ipChangedMidSession = false;
      let countryChangedMidSession = false;

      // Only flag IP change if both IPs are real (not localhost/private)
      const isLocalIP = (addr) => !addr || addr === '127.0.0.1' || addr === 'localhost' || addr.startsWith('10.') || addr.startsWith('192.168.') || addr.startsWith('172.');
      
      if (req.user?.activeSessionIP && ip !== req.user.activeSessionIP && !isLocalIP(ip) && !isLocalIP(req.user.activeSessionIP)) {
        ipChangedMidSession = true;
      }
      if (req.user?.activeSessionCountry && geo.country !== 'Local' &&
          req.user.activeSessionCountry !== 'Local' &&
          geo.country !== req.user.activeSessionCountry) {
        countryChangedMidSession = true;
      }

      // 5. Check suspicious lock status
      const isSuspiciousLocked = req.user?.suspiciousEventCount >= SUSPICIOUS_LOCK_THRESHOLD;

      // 6. Risk score (includes mid-session change factors)
      const risk = calculateRisk({
        isNewDevice,
        deviceTrusted,
        isNewCountry,
        failedLogins: req.user?.failedLoginAttempts || 0,
        proxySuspected,
        impossibleTravel,
        ipChangedMidSession,
        countryChangedMidSession,
        suspiciousEventCount: req.user?.suspiciousEventCount || 0
      });

      // 7. Policy engine (includes mid-session and suspicious lock context)
      const policyResult = evaluatePolicy({
        role: req.user?.role || 'user',
        deviceTrusted,
        deviceStatus,
        riskScore: risk.score,
        riskLevel: risk.level,
        endpointSensitivity: sensitivity,
        ipChangedMidSession,
        countryChangedMidSession,
        isSuspiciousLocked
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
        ipChangedMidSession,
        countryChangedMidSession,
        riskScore: risk.score,
        riskLevel: risk.level,
        riskFactors: risk.factors,
        policyDecision: policyResult.decision,
        policyRule: policyResult.rule,
        policyReason: policyResult.reason
      };

      // 8. Track suspicious activity & auto-lock
      const isSuspicious = policyResult.decision === 'DENY' || policyResult.decision === 'STEP_UP' ||
                           ipChangedMidSession || countryChangedMidSession || impossibleTravel;

      if (isSuspicious && req.user) {
        try {
          const userDoc = await User.findById(req.user.userId);
          if (userDoc) {
            userDoc.suspiciousEventCount = (userDoc.suspiciousEventCount || 0) + 1;
            userDoc.lastSuspiciousEvent = policyResult.rule || 'UNKNOWN';

            // Auto-lock if threshold reached
            if (userDoc.suspiciousEventCount >= SUSPICIOUS_LOCK_THRESHOLD && !userDoc.isSuspiciousLocked) {
              userDoc.suspiciousLockUntil = new Date(Date.now() + SUSPICIOUS_LOCK_MINUTES * 60 * 1000);

              await logAudit({
                actor: req.user.email, actorRole: req.user.role,
                action: 'ACCOUNT_SUSPICIOUS_LOCK',
                endpoint: req.originalUrl,
                decision: 'DENY',
                riskScore: risk.score, riskLevel: risk.level,
                ip, country: geo.country,
                deviceFingerprint: fingerprint, browser,
                metadata: {
                  suspiciousEventCount: userDoc.suspiciousEventCount,
                  lockDurationMinutes: SUSPICIOUS_LOCK_MINUTES,
                  triggerRule: policyResult.rule,
                  reason: 'Automatic temporary lock due to repeated suspicious activity'
                }
              });
            }

            await userDoc.save();
          }
        } catch (trackErr) {
          console.error('[ContinuousVerify] Suspicious tracking error:', trackErr.message);
        }
      }

      // 9. Log IP/location change events specifically
      if (ipChangedMidSession && req.user) {
        await logAudit({
          actor: req.user.email, actorRole: req.user.role,
          action: 'SESSION_IP_CHANGE',
          endpoint: req.originalUrl,
          decision: policyResult.decision,
          riskScore: risk.score, riskLevel: risk.level,
          ip, country: geo.country,
          deviceFingerprint: fingerprint, browser,
          metadata: {
            previousIP: req.user.activeSessionIP,
            newIP: ip,
            previousCountry: req.user.activeSessionCountry,
            newCountry: geo.country
          }
        });
      }

      if (countryChangedMidSession && req.user) {
        await logAudit({
          actor: req.user.email, actorRole: req.user.role,
          action: 'SESSION_COUNTRY_CHANGE',
          endpoint: req.originalUrl,
          decision: policyResult.decision,
          riskScore: risk.score, riskLevel: risk.level,
          ip, country: geo.country,
          deviceFingerprint: fingerprint, browser,
          metadata: {
            previousCountry: req.user.activeSessionCountry,
            newCountry: geo.country,
            reason: 'Country changed during active session'
          }
        });
      }

      // 10. Log the policy decision
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

      // 11. Enforce decision
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

      // ALLOW – reset suspicious count on successful normal request
      if (req.user && risk.level === 'LOW') {
        try {
          await User.findByIdAndUpdate(req.user.userId, {
            $set: { suspiciousEventCount: 0, lastSuspiciousEvent: null }
          });
        } catch (_) { /* non-critical */ }
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
