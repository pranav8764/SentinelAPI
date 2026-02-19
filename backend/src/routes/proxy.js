/**
 * Proxy Routes
 * Handles proxy-related endpoints
 */

import express from 'express';
const router = express.Router();
import { 
  createProxy, 
  validateProxyTarget, 
  logProxyRequest,
  proxyHealthCheck 
} from '../middleware/proxy.js';
import { proxyLimiter } from '../middleware/rateLimit.js';
import securityMiddleware from '../middleware/security.js';

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
  import('../config/proxy.js').then(({ proxyConfig }) => {
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
});

export default router;
