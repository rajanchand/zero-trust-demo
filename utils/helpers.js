/**
 * Helper Utilities
 * ---
 * Small shared functions used across the backend.
 */

/**
 * Extract client IP from the request, respecting proxy headers.
 * @param {Object} req - Express request
 * @returns {string}
 */
function getClientIP(req) {
  let ip;
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // x-forwarded-for can be a comma-separated list; take the first one
    ip = forwarded.split(',')[0].trim();
  } else {
    ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
  }
  // Strip IPv6-mapped IPv4 prefix (e.g. ::ffff:127.0.0.1 → 127.0.0.1)
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.slice(7);
  }
  return ip;
}

/**
 * Extract a simple browser name from user-agent string.
 * @param {string} ua - User-Agent header
 * @returns {string}
 */
function parseBrowser(ua) {
  if (!ua) return 'Unknown';
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Edg')) return 'Edge';
  if (ua.includes('Chrome')) return 'Chrome';
  if (ua.includes('Safari')) return 'Safari';
  if (ua.includes('Opera') || ua.includes('OPR')) return 'Opera';
  return 'Other';
}

/**
 * Parse OS from user-agent string.
 * @param {string} ua
 * @returns {string}
 */
function parseOS(ua) {
  if (!ua) return 'Unknown';
  if (ua.includes('Windows')) return 'Windows';
  if (ua.includes('Mac OS')) return 'macOS';
  if (ua.includes('Linux')) return 'Linux';
  if (ua.includes('Android')) return 'Android';
  if (ua.includes('iPhone') || ua.includes('iPad')) return 'iOS';
  return 'Other';
}

/**
 * Check for "impossible travel": different country within a short window.
 * If the last login was from a different country less than 1 hour ago,
 * flag as impossible travel (for demo purposes).
 * @param {Date|null} lastLoginAt
 * @param {string|null} lastCountry
 * @param {string} currentCountry
 * @returns {boolean}
 */
function checkImpossibleTravel(lastLoginAt, lastCountry, currentCountry) {
  if (!lastLoginAt || !lastCountry || !currentCountry) return false;
  if (lastCountry === currentCountry) return false;
  if (currentCountry === 'Local' || lastCountry === 'Local') return false;

  const diffMs = Date.now() - new Date(lastLoginAt).getTime();
  const ONE_HOUR = 60 * 60 * 1000;
  return diffMs < ONE_HOUR;
}

/**
 * Detect proxy / VPN / Tor based on simple heuristics (demo).
 * In a real system you'd use a threat-intel feed or commercial API.
 * @param {Object} req - Express request
 * @param {boolean} geoProxyFlag - from geo lookup
 * @returns {boolean}
 */
function detectProxy(req, geoProxyFlag) {
  // Check geo API flag
  if (geoProxyFlag) return true;

  // Check common proxy headers (demo heuristic)
  const proxyHeaders = [
    'x-forwarded-for',
    'via',
    'x-real-ip',
    'forwarded'
  ];
  let proxyHeaderCount = 0;
  for (const h of proxyHeaders) {
    if (req.headers[h]) proxyHeaderCount++;
  }
  // If multiple proxy headers are present, flag as suspicious
  if (proxyHeaderCount >= 2) return true;

  return false;
}

/**
 * Generate a 6-digit numeric OTP (for demo).
 * @returns {string}
 */
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

module.exports = {
  getClientIP,
  parseBrowser,
  parseOS,
  checkImpossibleTravel,
  detectProxy,
  generateOTP
};
