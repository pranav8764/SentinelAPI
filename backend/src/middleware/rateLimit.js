
import rateLimit from 'express-rate-limit';
import logger from '../utils/logger.js';
import SecurityConfig from '../models/SecurityConfig.js';

let rateLimitConfig = {
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: 'Too many requests from this IP, please try again later',
};

const loadRateLimitConfig = async () => {
  try {
    const config = await SecurityConfig.findOne();
    if (config && config.rateLimit) {
      rateLimitConfig = {
        windowMs: config.rateLimit.windowMs || rateLimitConfig.windowMs,
        max: config.rateLimit.max || config.rateLimit.maxRequests || rateLimitConfig.max,
        message: config.rateLimit.message || rateLimitConfig.message,
      };
      logger.info('Rate limit configuration loaded from database');
    }
  } catch (error) {
    logger.error('Error loading rate limit config:', error);
  }
};

loadRateLimitConfig();

setInterval(loadRateLimitConfig, 5 * 60 * 1000);

const keyGenerator = (req) => {
  return req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
};

const handler = (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  logger.warn(`Rate limit exceeded for IP: ${ip}`);
  
  res.status(429).json({
    success: false,
    error: 'Rate limit exceeded',
    message: rateLimitConfig.message,
    retryAfter: Math.ceil(rateLimitConfig.windowMs / 1000),
    timestamp: new Date().toISOString(),
  });
};

const skip = async (req) => {
  try {
    const config = await SecurityConfig.findOne();
    if (config && config.whitelist) {
      const ip = req.ip || req.connection.remoteAddress;
      return config.whitelist.some((entry) => {
        if (typeof entry === 'string') {
          return entry === ip;
        }
        if (entry && typeof entry === 'object') {
          const enabled = entry.enabled !== false;
          return enabled && entry.ip === ip;
        }
        return false;
      });
    }
  } catch (error) {
    logger.error('Error checking whitelist:', error);
  }
  return false;
};

const apiLimiter = rateLimit({
  windowMs: rateLimitConfig.windowMs,
  max: rateLimitConfig.max,
  message: rateLimitConfig.message,
  handler,
  skip,
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per 15 minutes
  message: 'Too many authentication attempts, please try again later',
  handler: (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    logger.warn(`Auth rate limit exceeded for IP: ${ip}`);
    
    res.status(429).json({
      success: false,
      error: 'Too many authentication attempts',
      message: 'Please try again after 15 minutes',
      retryAfter: 900, // 15 minutes in seconds
      timestamp: new Date().toISOString(),
    });
  },
  skip,
  standardHeaders: true,
  legacyHeaders: false,
});

const proxyLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 200, // 200 requests per minute (more lenient for proxy)
  message: 'Too many proxy requests, please slow down',
  handler,
  skip,
  standardHeaders: true,
  legacyHeaders: false,
});

const scannerLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 scans per minute
  message: 'Too many scan requests, please wait before scanning again',
  handler: (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    logger.warn(`Scanner rate limit exceeded for IP: ${ip}`);
    
    res.status(429).json({
      success: false,
      error: 'Scanner rate limit exceeded',
      message: 'Please wait before initiating another scan',
      retryAfter: 60,
      timestamp: new Date().toISOString(),
    });
  },
  skip,
  standardHeaders: true,
  legacyHeaders: false,
});

const updateRateLimitConfig = async (newConfig) => {
  try {
    let config = await SecurityConfig.findOne();
    
    if (!config) {
      config = new SecurityConfig();
    }
    
    config.rateLimit = {
      windowMs: newConfig.windowMs || rateLimitConfig.windowMs,
      max: newConfig.max || rateLimitConfig.max,
      maxRequests: newConfig.max || rateLimitConfig.max,
      message: newConfig.message || rateLimitConfig.message,
    };
    
    await config.save();
    await loadRateLimitConfig();
    
    logger.info('Rate limit configuration updated');
    return true;
  } catch (error) {
    logger.error('Error updating rate limit config:', error);
    return false;
  }
};

const getRateLimitConfig = () => {
  return rateLimitConfig;
};

export {
  apiLimiter,
  authLimiter,
  proxyLimiter,
  scannerLimiter,
  updateRateLimitConfig,
  getRateLimitConfig,
  loadRateLimitConfig,
};
