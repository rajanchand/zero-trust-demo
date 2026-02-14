/**
 * Risk Scorer
 * ---
 * Computes a risk score (0–100) based on simple, transparent rules.
 * This is a rules-based engine – no ML, easy to explain in a dissertation.
 *
 * Factors:
 *  - New device:                    +30
 *  - Device not trusted:            +25
 *  - New country:                   +25
 *  - Too many failed logins:        +25
 *  - Proxy / VPN suspected:         +20
 *  - Impossible travel:             +30
 *  - IP changed mid-session:        +35
 *  - Country changed mid-session:   +40
 *  - Repeated suspicious activity:  +20
 */

/**
 * Calculate risk score.
 * @param {Object} ctx - Context about the current request
 * @param {boolean} ctx.isNewDevice        - First time seeing this device?
 * @param {boolean} ctx.deviceTrusted      - Device approved by admin?
 * @param {boolean} ctx.isNewCountry       - Country differs from last login?
 * @param {number}  ctx.failedLogins       - Recent failed login count
 * @param {boolean} ctx.proxySuspected     - VPN / proxy / Tor detected?
 * @param {boolean} ctx.impossibleTravel   - Different country too quickly?
 * @param {boolean} ctx.ipChangedMidSession    - IP changed during active session?
 * @param {boolean} ctx.countryChangedMidSession - Country changed during active session?
 * @param {number}  ctx.suspiciousEventCount    - Number of recent suspicious events
 * @returns {{ score: number, level: string, factors: string[] }}
 */
function calculateRisk(ctx) {
  let score = 0;
  const factors = [];

  // 1. New device
  if (ctx.isNewDevice) {
    score += 30;
    factors.push('New device detected (+30)');
  }

  // 2. Device not trusted (pending or blocked)
  if (!ctx.deviceTrusted) {
    score += 25;
    factors.push('Device not trusted (+25)');
  }

  // 3. New country
  if (ctx.isNewCountry) {
    score += 25;
    factors.push('Login from new country (+25)');
  }

  // 4. Too many failed logins (threshold: 3+)
  if (ctx.failedLogins >= 3) {
    score += 25;
    factors.push(`High failed login count: ${ctx.failedLogins} (+25)`);
  }

  // 5. Proxy / VPN suspected
  if (ctx.proxySuspected) {
    score += 20;
    factors.push('Proxy/VPN suspected (+20)');
  }

  // 6. Impossible travel
  if (ctx.impossibleTravel) {
    score += 30;
    factors.push('Impossible travel detected (+30)');
  }

  // 7. IP changed mid-session (Zero Trust: continuous verification)
  if (ctx.ipChangedMidSession) {
    score += 35;
    factors.push('IP address changed mid-session (+35)');
  }

  // 8. Country changed mid-session (stronger signal)
  if (ctx.countryChangedMidSession) {
    score += 40;
    factors.push('Country changed mid-session (+40)');
  }

  // 9. Repeated suspicious activity on this account
  if (ctx.suspiciousEventCount >= 3) {
    score += 20;
    factors.push(`Repeated suspicious events: ${ctx.suspiciousEventCount} (+20)`);
  }

  // Cap at 100
  score = Math.min(score, 100);

  // Determine level
  let level = 'LOW';
  if (score >= 60) level = 'HIGH';
  else if (score >= 30) level = 'MEDIUM';

  return { score, level, factors };
}

module.exports = { calculateRisk };
