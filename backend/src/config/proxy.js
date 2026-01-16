/**
 * Proxy Configuration
 * Defines target API settings and proxy behavior
 */

const proxyConfig = {
  // Default target API (can be overridden per request)
  defaultTarget: process.env.PROXY_TARGET_URL || 'https://jsonplaceholder.typicode.com',
  
  // Proxy settings
  changeOrigin: true, // Changes the origin of the host header to the target URL
  secure: true, // Verify SSL certificates
  followRedirects: true, // Follow HTTP 3xx responses as redirects
  
  // Timeout settings (in milliseconds)
  timeout: parseInt(process.env.PROXY_TIMEOUT) || 30000, // 30 seconds
  proxyTimeout: parseInt(process.env.PROXY_TIMEOUT) || 30000,
  
  // Path rewriting
  pathRewrite: {
    '^/proxy': '', // Remove /proxy prefix when forwarding
  },
  
  // Headers to add to proxied requests
  headers: {
    'X-Proxied-By': 'SentinelAPI',
    'X-Proxy-Version': '1.0.0',
  },
  
  // Allowed target domains (whitelist for security)
  allowedTargets: process.env.ALLOWED_PROXY_TARGETS 
    ? process.env.ALLOWED_PROXY_TARGETS.split(',')
    : [
        'jsonplaceholder.typicode.com',
        'api.github.com',
        'reqres.in',
        'localhost',
        '127.0.0.1',
      ],
  
  // Rate limiting for proxy requests
  rateLimit: {
    windowMs: 60 * 1000, // 1 minute
    max: 100, // Max 100 requests per minute per IP
  },
};

/**
 * Validate if target URL is allowed
 */
const isTargetAllowed = (targetUrl) => {
  try {
    const url = new URL(targetUrl);
    const hostname = url.hostname;
    
    // Check if hostname is in allowed list
    return proxyConfig.allowedTargets.some(allowed => {
      // Support wildcard matching
      if (allowed.startsWith('*.')) {
        const domain = allowed.substring(2);
        return hostname.endsWith(domain);
      }
      return hostname === allowed || hostname.includes(allowed);
    });
  } catch (error) {
    return false;
  }
};

/**
 * Get target URL from request
 * Priority: Query param > Header > Default
 */
const getTargetUrl = (req) => {
  // Check query parameter
  if (req.query.target) {
    return req.query.target;
  }
  
  // Check custom header
  if (req.headers['x-proxy-target']) {
    return req.headers['x-proxy-target'];
  }
  
  // Return default
  return proxyConfig.defaultTarget;
};

module.exports = {
  proxyConfig,
  isTargetAllowed,
  getTargetUrl,
};
