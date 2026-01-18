/**
 * Rate Limiting Middleware
 * Protects against DDoS and brute force attacks
 */

import rateLimit from 'express-rate-limit';
import logger from '../utils/logger.js';
import SecurityConfig from '../models/SecurityConfig.js';

/**
 * In-memory store for rate limit configuration
 * Updated from database periodically
 */
let rateLimitConfig = {
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: 'Too many requests from this IP, please try again later',
};

/**
 * Load rate limit configuration from database
 */
export const loadRateLimitConfig = async () => {
  try {
    const config = await SecurityConfig.findOne();
    if (config && config.rateLimit) {
      rateLimitConfig = {
        windowMs: config.rateLimit.windowMs || rateLimitConfig.windowMs,
        max: config.rateLimit.max || rateLimitConfig.max,
        message: config.rateLimit.message || rateLimitConfig.message,
      };
      logger.info('Rate limit configuration loaded from database');
    }
  } catch (error) {
    logger.error('Error loading rate limit config:', error);
  }
};

// Load config on startup
loadRateLimitConfig();

// Reload config every 5 minutes
setInterval(loadRateLimitConfig, 5 * 60 * 1000);

/**
 * Custom key generator - uses IP address with IPv6 support
 */
const keyGenerator = (req) => {
  // Use express-rate-limit's built-in IP handling
  return req.ip || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
};

/**
 * Custom handler for rate limit exceeded
 */
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

/**
 * Skip rate limiting for whitelisted IPs
 */
const skip = async (req) => {
  try {
    const config = await SecurityConfig.findOne();
    if (config && config.whitelist) {
      const ip = req.ip || req.connection.remoteAddress;
      return config.whitelist.includes(ip);
    }
  } catch (error) {
    logger.error('Error checking whitelist:', error);
  }
  return false;
};

/**
 * Standard rate limiter for API endpoints
 */
export const apiLimiter = rateLimit({
  windowMs: rateLimitConfig.windowMs,
  max: rateLimitConfig.max,
  message: rateLimitConfig.message,
  handler,
  skip,
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
});

/**
 * Strict rate limiter for authentication endpoints
 */
export const authLimiter = rateLimit({
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

/**
 * Lenient rate limiter for proxy requests
 */
export const proxyLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 200, // 200 requests per minute (more lenient for proxy)
  message: 'Too many proxy requests, please slow down',
  handler,
  skip,
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Very strict rate limiter for scanner endpoints
 */
export const scannerLimiter = rateLimit({
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

/**
 * Update rate limit configuration
 */
export const updateRateLimitConfig = async (newConfig) => {
  try {
    let config = await SecurityConfig.findOne();
    
    if (!config) {
      config = new SecurityConfig();
    }
    
    config.rateLimit = {
      windowMs: newConfig.windowMs || rateLimitConfig.windowMs,
      max: newConfig.max || rateLimitConfig.max,
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

/**
 * Get current rate limit configuration
 */
export const getRateLimitConfig = () => {
  return rateLimitConfig;
};
