/**
 * Geo Lookup Utility
 * ---
 * Attempts to determine the country from an IP address.
 * Uses a free API (ip-api.com) with a fallback to 'Unknown'.
 *
 * For dissertation demo purposes, localhost IPs are mapped to 'Local'.
 */

/**
 * Look up country for a given IP address.
 * @param {string} ip - Client IP
 * @returns {Promise<{country: string, isp: string, proxy: boolean}>}
 */
async function geoLookup(ip) {
  // Default result
  const result = { country: 'Unknown', isp: 'Unknown', proxy: false };

  // Normalise: strip IPv6-mapped IPv4 prefix
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.slice(7);
  }

  // Localhost / private IPs – skip lookup
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    result.country = 'Local';
    result.isp = 'Localhost';
    return result;
  }

  try {
    // ip-api.com is free for non-commercial use (perfect for a dissertation demo)
    const url = `http://ip-api.com/json/${ip}?fields=status,country,isp,proxy`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000); // 3s timeout

    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);

    const data = await response.json();

    if (data.status === 'success') {
      result.country = data.country || 'Unknown';
      result.isp = data.isp || 'Unknown';
      result.proxy = !!data.proxy;
    }
  } catch (err) {
    // API failed – that's okay, we fall back gracefully
    console.warn('[GeoLookup] Could not resolve IP:', ip, '-', err.message);
  }

  return result;
}

module.exports = { geoLookup };
