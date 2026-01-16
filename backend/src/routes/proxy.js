/**
 * Proxy Routes
 * Handles proxy-related endpoints
 */

const express = require('express');
const router = express.Router();
const { 
  createProxy, 
  validateProxyTarget, 
  logProxyRequest,
  proxyHealthCheck 
} = require('../middleware/proxy');
const { proxyLimiter } = require('../middleware/rateLimit');
const securityMiddleware = require('../middleware/security');

/**
 * GET /health
 * Check proxy health and configuration
 */
router.get('/health', proxyHealthCheck);

/**
 * GET /config
 * Get current proxy configuration
 */
router.get('/config', (req, res) => {
  const { proxyConfig } = require('../config/proxy');
  
  res.json({
    success: true,
    config: {
      defaultTarget: proxyConfig.defaultTarget,
      timeout: proxyConfig.timeout,
      allowedTargets: proxyConfig.allowedTargets,
      changeOrigin: proxyConfig.changeOrigin,
      secure: proxyConfig.secure,
    },
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
