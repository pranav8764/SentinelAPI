import ApiKey from '../models/ApiKey.js';
import logger from '../utils/logger.js';

// Middleware to authenticate using API key
const authenticateApiKey = async (req, res, next) => {
  try {
    // Check for API key in header or query parameter
    const apiKey = req.headers['x-api-key'] || req.query.api_key;

    if (!apiKey) {
      return res.status(401).json({
        error: 'API key required',
        code: 'NO_API_KEY'
      });
    }

    // Find and validate API key
    const keyDoc = await ApiKey.findOne({ key: apiKey }).populate('userId', '-password');

    if (!keyDoc) {
      logger.warn(`Invalid API key attempt: ${apiKey.substring(0, 12)}...`);
      return res.status(401).json({
        error: 'Invalid API key',
        code: 'INVALID_API_KEY'
      });
    }

    // Check if key is active
    if (!keyDoc.isActive) {
      return res.status(401).json({
        error: 'API key is inactive',
        code: 'INACTIVE_API_KEY'
      });
    }

    // Check if key is expired
    if (keyDoc.isExpired) {
      return res.status(401).json({
        error: 'API key has expired',
        code: 'EXPIRED_API_KEY'
      });
    }

    // Record usage (async, don't wait)
    keyDoc.recordUsage().catch(err => 
      logger.error(`Failed to record API key usage: ${err.message}`)
    );

    // Attach key info and user to request
    req.apiKey = keyDoc;
    req.user = keyDoc.userId;

    next();
  } catch (error) {
    logger.error(`API key authentication error: ${error.message}`);
    return res.status(500).json({
      error: 'Authentication error',
      code: 'AUTH_ERROR'
    });
  }
};

// Middleware to check API key permissions
const requireApiKeyPermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.apiKey) {
      return res.status(401).json({
        error: 'Not authenticated with API key',
        code: 'NOT_AUTHENTICATED'
      });
    }

    const hasPermission = permissions.some(p => 
      req.apiKey.permissions && req.apiKey.permissions.includes(p)
    );

    if (!hasPermission) {
      return res.status(403).json({
        error: 'Insufficient API key permissions',
        code: 'INSUFFICIENT_PERMISSION',
        required: permissions,
        current: req.apiKey.permissions
      });
    }

    next();
  };
};

// Middleware that accepts either JWT or API key
const authenticateFlexible = async (req, res, next) => {
  // Check for API key first
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (apiKey) {
    return authenticateApiKey(req, res, next);
  }

  // Fall back to JWT authentication
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Import JWT auth dynamically to avoid circular dependency
    const { authenticate } = await import('./auth.js');
    return authenticate(req, res, next);
  }

  return res.status(401).json({
    error: 'Authentication required. Provide either API key or JWT token.',
    code: 'NO_AUTH'
  });
};

export {
  authenticateApiKey,
  requireApiKeyPermission,
  authenticateFlexible
};
