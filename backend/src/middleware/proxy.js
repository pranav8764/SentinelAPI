/**
 * Proxy Middleware
 * Forwards requests to target API with security checks and logging
 */

import { createProxyMiddleware } from 'http-proxy-middleware';
import { proxyConfig, isTargetAllowed, getTargetUrl } from '../config/proxy.js';
import logger from '../utils/logger.js';
import RequestLog from '../models/RequestLog.js';

/**
 * Create proxy middleware with custom configuration
 */
export const createProxy = () => {
  return createProxyMiddleware({
    target: proxyConfig.defaultTarget,
    changeOrigin: proxyConfig.changeOrigin,
    secure: proxyConfig.secure,
    followRedirects: proxyConfig.followRedirects,
    timeout: proxyConfig.timeout,
    proxyTimeout: proxyConfig.proxyTimeout,
    pathRewrite: proxyConfig.pathRewrite,
    
    /**
     * Router function - dynamically set target based on request
     */
    router: (req) => {
      const targetUrl = getTargetUrl(req);
      logger.info(`Routing proxy request to: ${targetUrl}`);
      return targetUrl;
    },
    
    /**
     * Modify request before sending to target
     */
    onProxyReq: (proxyReq, req, res) => {
      // Add custom headers
      Object.entries(proxyConfig.headers).forEach(([key, value]) => {
        proxyReq.setHeader(key, value);
      });
      
      // Add original IP
      const clientIp = req.ip || req.connection.remoteAddress;
      proxyReq.setHeader('X-Forwarded-For', clientIp);
      proxyReq.setHeader('X-Real-IP', clientIp);
      
      // Log proxy request
      logger.info(`Proxying ${req.method} ${req.originalUrl} to ${proxyReq.path}`);
      
      // Store start time for response time calculation
      req.proxyStartTime = Date.now();
    },
    
    /**
     * Modify response before sending to client
     */
    onProxyRes: async (proxyRes, req, res) => {
      const responseTime = Date.now() - req.proxyStartTime;
      const targetUrl = getTargetUrl(req);
      
      // Log response
      logger.info(`Proxy response: ${proxyRes.statusCode} in ${responseTime}ms`);
      
      // Add custom response headers
      proxyRes.headers['X-Proxy-Response-Time'] = `${responseTime}ms`;
      proxyRes.headers['X-Proxied-By'] = 'SentinelAPI';
      
      // Update request log with proxy information
      try {
        if (req.requestLogId) {
          await RequestLog.findByIdAndUpdate(req.requestLogId, {
            $set: {
              'proxyInfo.targetUrl': targetUrl,
              'proxyInfo.responseTime': responseTime,
              'proxyInfo.statusCode': proxyRes.statusCode,
              'proxyInfo.proxied': true,
            }
          });
        }
      } catch (error) {
        logger.error('Error updating request log with proxy info:', error);
      }
    },
    
    /**
     * Error handler
     */
    onError: (err, req, res) => {
      const targetUrl = getTargetUrl(req);
      
      logger.error(`Proxy error for ${req.method} ${req.originalUrl}:`, {
        error: err.message,
        code: err.code,
        target: targetUrl,
      });
      
      // Determine error type and send appropriate response
      let statusCode = 502; // Bad Gateway
      let errorMessage = 'Proxy error occurred';
      
      if (err.code === 'ECONNREFUSED') {
        errorMessage = 'Target server refused connection';
      } else if (err.code === 'ETIMEDOUT' || err.code === 'ESOCKETTIMEDOUT') {
        statusCode = 504; // Gateway Timeout
        errorMessage = 'Target server timeout';
      } else if (err.code === 'ENOTFOUND') {
        errorMessage = 'Target server not found';
      } else if (err.code === 'ECONNRESET') {
        errorMessage = 'Connection reset by target server';
      }
      
      res.status(statusCode).json({
        success: false,
        error: errorMessage,
        details: process.env.NODE_ENV === 'development' ? err.message : undefined,
        target: targetUrl,
        timestamp: new Date().toISOString(),
      });
    },
  });
};

/**
 * Middleware to validate proxy target before proxying
 */
export const validateProxyTarget = (req, res, next) => {
  const targetUrl = getTargetUrl(req);
  
  // Validate target URL format
  try {
    new URL(targetUrl);
  } catch (error) {
    logger.warn(`Invalid proxy target URL: ${targetUrl}`);
    return res.status(400).json({
      success: false,
      error: 'Invalid target URL',
      message: 'The proxy target URL is not valid',
    });
  }
  
  // Check if target is allowed
  if (!isTargetAllowed(targetUrl)) {
    logger.warn(`Proxy target not allowed: ${targetUrl}`);
    return res.status(403).json({
      success: false,
      error: 'Target not allowed',
      message: 'The requested proxy target is not in the allowed list',
      allowedTargets: proxyConfig.allowedTargets,
    });
  }
  
  logger.info(`Proxy target validated: ${targetUrl}`);
  next();
};

/**
 * Middleware to log proxy requests
 */
export const logProxyRequest = async (req, res, next) => {
  const targetUrl = getTargetUrl(req);
  
  try {
    // Create request log entry
    const requestLog = new RequestLog({
      method: req.method,
      path: req.originalUrl,
      ip: req.ip || req.connection.remoteAddress,
      headers: req.headers,
      body: req.body,
      query: req.query,
      timestamp: new Date(),
      threatLevel: 'none',
      blocked: false,
      proxyInfo: {
        targetUrl: targetUrl,
        proxied: true,
      },
    });
    
    const savedLog = await requestLog.save();
    req.requestLogId = savedLog._id;
    
    logger.info(`Proxy request logged: ${req.method} ${req.originalUrl} -> ${targetUrl}`);
  } catch (error) {
    logger.error('Error logging proxy request:', error);
    // Don't block the request if logging fails
  }
  
  next();
};

/**
 * Health check for proxy
 */
export const proxyHealthCheck = async (req, res) => {
  const targetUrl = getTargetUrl(req);
  
  try {
    const startTime = Date.now();
    
    // Simple health check - try to resolve target URL
    const url = new URL(targetUrl);
    const isAllowed = isTargetAllowed(targetUrl);
    const responseTime = Date.now() - startTime;
    
    res.json({
      success: true,
      proxy: {
        status: 'healthy',
        target: targetUrl,
        allowed: isAllowed,
        responseTime: `${responseTime}ms`,
      },
      config: {
        defaultTarget: proxyConfig.defaultTarget,
        timeout: proxyConfig.timeout,
        allowedTargets: proxyConfig.allowedTargets,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error('Proxy health check failed:', error);
    res.status(500).json({
      success: false,
      error: 'Proxy health check failed',
      details: error.message,
    });
  }
};
