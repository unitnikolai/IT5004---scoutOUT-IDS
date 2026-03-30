// ==================== VIRUSTOTAL INTEGRATION (IP ONLY + PRIVATE IP SKIP) ====================

// Configuration
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours cache

// Simple in-memory cache for VirusTotal results
const vtCache = new Map();

// Helper: detects private/local IPs so we NEVER send them to VirusTotal
function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return true;
  if (parts[0] === 10) return true;                          // 10.0.0.0/8
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16-31.0.0/12
  if (parts[0] === 192 && parts[1] === 168) return true;     // 192.168.0.0/16
  if (parts[0] === 127) return true;                         // localhost
  if (parts[0] === 169 && parts[1] === 254) return true;     // link-local
  return false;
}

// Only checks public IPs — private IPs are skipped instantly
async function checkPublicIP(ip) {
  // 1. Skip private IPs completely
  if (isPrivateIP(ip)) {
    return {
      skipped: true,
      message: "Private IP address — not sent to VirusTotal (local network only)",
      ip: ip,
      vtSeverity: "low"
    };
  }

  const cacheKey = `ip:${ip}`;
  const cached = vtCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }

  if (!VT_API_KEY) {
    console.warn('VIRUSTOTAL_API_KEY not set in .env');
    return { error: 'VT API key not configured' };
  }

  const url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`;

  try {
    const response = await fetch(url, {
      headers: { 'x-apikey': VT_API_KEY }
    });

    if (response.status === 429) return { error: 'Rate limit exceeded' };
    if (!response.ok) throw new Error(`VT API ${response.status}`);

    const data = await response.json();
    vtCache.set(cacheKey, { data, timestamp: Date.now() });
    return data;
  } catch (err) {
    console.error('VirusTotal error:', err.message);
    return { error: err.message };
  }
}

module.exports = { isPrivateIP, checkPublicIP, }