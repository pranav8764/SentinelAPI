import { checkForVulnerabilities, getThreatLevel } from '../config/securityPatterns.js';
import RequestLog from '../models/RequestLog.js';
import logger from '../utils/logger.js';
import { sanitizeInput, sanitizeXSS, generateCSPHeader } from '../utils/sanitizer.js';
import { responseScanner, securityHeaders } from './responseScanner.js';


class SecurityMiddleware {
  constructor() {
    this.config = {
      enabled: true,
      logAllRequests: true,
      blockThreats: true,
      minThreatLevel: 'high',
      sanitizeInput: true,
      scanResponses: true,
      autoSanitizeResponses: false,
      blockXSSResponses: false,
      addSecurityHeaders: true,
      contentSecurityPolicy: true
    };
  }

  middleware() {
    return async (req, res, next) => {
      if (!this.config.enabled) {
        return next();
      }

      const startTime = Date.now();
      let blocked = false;
      let vulnerabilities = [];
      let threatLevel = 'low';
      let sanitizedData = {};

      try {
        if (this.config.sanitizeInput) {
          sanitizedData = this.sanitizeRequestData(req);
        }

        const urlVulns = this.checkInput(req.url, 'URL');
        vulnerabilities = vulnerabilities.concat(urlVulns);

        if (req.query && Object.keys(req.query).length > 0) {
          const queryString = JSON.stringify(req.query);
          const queryVulns = this.checkInput(queryString, 'Query');
          vulnerabilities = vulnerabilities.concat(queryVulns);
        }

        if (req.body && Object.keys(req.body).length > 0) {
          const bodyString = JSON.stringify(req.body);
          const bodyVulns = this.checkInput(bodyString, 'Body');
          vulnerabilities = vulnerabilities.concat(bodyVulns);
        }

        const userAgent = req.get('User-Agent') || '';
        const headerVulns = this.checkInput(userAgent, 'Headers');
        vulnerabilities = vulnerabilities.concat(headerVulns);

        const allInputs = [
          req.url,
          JSON.stringify(req.query || {}),
          JSON.stringify(req.body || {}),
          userAgent
        ].join(' ');
        
        const xssVulns = checkForVulnerabilities(allInputs, 'xss');
        vulnerabilities = vulnerabilities.concat(xssVulns.map(v => ({ ...v, source: 'XSS_Scan' })));

        threatLevel = getThreatLevel(vulnerabilities);

        blocked = this.shouldBlock(threatLevel, vulnerabilities);

        if (blocked) {
          logger.warn(`Blocked request from ${req.ip}: ${threatLevel} threat detected`, {
            url: req.originalUrl,
            method: req.method,
            vulnerabilities: vulnerabilities.length,
            threatLevel
          });
          
          await this.logRequest(req, res, {
            blocked: true,
            threatLevel,
            vulnerabilities,
            responseTime: Date.now() - startTime,
            statusCode: 403,
            sanitizedData
          });

          if (req.app && req.app.get('io')) {
            req.app.get('io').emit('threat:blocked', {
              ip: req.ip,
              url: req.originalUrl,
              method: req.method,
              threatLevel,
              vulnerabilities: vulnerabilities.length,
              timestamp: new Date().toISOString()
            });
          }

          return res.status(403).json({
            error: 'Request blocked by security policy',
            code: 'SECURITY_VIOLATION',
            threatLevel,
            timestamp: new Date().toISOString()
          });
        }

        if (this.config.scanResponses) {
          responseScanner({
            autoSanitize: this.config.autoSanitizeResponses,
            blockXSSResponses: this.config.blockXSSResponses
          })(req, res, () => {});
        }

        if (this.config.logAllRequests || vulnerabilities.length > 0) {
          const originalEnd = res.end;
          res.end = function(chunk, encoding) {
            // Log asynchronously without blocking the response
            this.logRequest(req, res, {
              blocked: false,
              threatLevel,
              vulnerabilities,
              responseTime: Date.now() - startTime,
              statusCode: res.statusCode,
              sanitizedData
            }).catch(err => logger.error('Error logging request:', err));
            
            if (req.app && req.app.get('io')) {
              try {
                req.app.get('io').emit('request:logged', {
                  method: req.method,
                  url: req.originalUrl,
                  ip: req.ip,
                  statusCode: res.statusCode,
                  threatLevel,
                  blocked: false,
                  timestamp: new Date().toISOString()
                });
              } catch (err) {
                logger.error('Error emitting socket event:', err);
              }
            }
            
            // Call original end immediately
            return originalEnd.call(res, chunk, encoding);
          }.bind(this);
        }

        if (this.config.addSecurityHeaders) {
          this.addSecurityHeaders(req, res);
        }

        next();

      } catch (error) {
        logger.error(`Security middleware error: ${error.message}`, error);
        next();
      }
    };
  }

  sanitizeRequestData(req) {
    const sanitized = {};
    
    try {
      if (req.query && Object.keys(req.query).length > 0) {
        sanitized.query = sanitizeInput(req.query, { type: 'all' });
        
        if (JSON.stringify(sanitized.query) !== JSON.stringify(req.query)) {
          logger.info('Query parameters sanitized', {
            original: Object.keys(req.query).length,
            sanitized: Object.keys(sanitized.query).length
          });
        }
      }
      
      if (req.body && Object.keys(req.body).length > 0) {
        sanitized.body = sanitizeInput(req.body, { type: 'all' });
        
        if (JSON.stringify(sanitized.body) !== JSON.stringify(req.body)) {
          logger.info('Request body sanitized', {
            url: req.originalUrl,
            method: req.method
          });
          req.body = sanitized.body;
        }
      }
      
      const headersToSanitize = ['user-agent', 'referer', 'x-forwarded-for'];
      sanitized.headers = {};
      
      headersToSanitize.forEach(header => {
        const value = req.get(header);
        if (value) {
          const sanitizedValue = sanitizeXSS(value, { encodeEntities: true });
          if (sanitizedValue !== value) {
            sanitized.headers[header] = sanitizedValue;
            req.headers[header] = sanitizedValue;
            logger.info(`Header ${header} sanitized`);
          }
        }
      });
      
      return sanitized;
      
    } catch (error) {
      logger.error('Error sanitizing request data:', error);
      return {};
    }
  }

  checkInput(input, source) {
    if (!input) return [];

    const vulnerabilities = checkForVulnerabilities(input);
    return vulnerabilities.map(vuln => ({
      ...vuln,
      source
    }));
  }

  shouldBlock(threatLevel, vulnerabilities) {
    if (!this.config.blockThreats) {
      return false;
    }

    const threatLevels = ['low', 'medium', 'high', 'critical'];
    const minLevel = threatLevels.indexOf(this.config.minThreatLevel);
    const currentLevel = threatLevels.indexOf(threatLevel);

    return currentLevel >= minLevel;
  }

  addSecurityHeaders(req, res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Powered-By', 'SentinelAPI');
    
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    if (req.secure || req.get('X-Forwarded-Proto') === 'https') {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    
    if (this.config.contentSecurityPolicy) {
      const csp = generateCSPHeader({
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        childSrc: ["'none'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        upgradeInsecureRequests: true,
        blockAllMixedContent: true
      });
      
      res.setHeader('Content-Security-Policy', csp);
    }
  }

  async logRequest(req, res, securityData) {
    try {
      const logEntry = new RequestLog({
        method: req.method,
        url: req.originalUrl || req.url,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || '',
        headers: this.sanitizeHeaders(req.headers),
        body: this.sanitizeBody(req.body),
        query: req.query,
        statusCode: securityData.statusCode,
        responseTime: securityData.responseTime,
        blocked: securityData.blocked,
        threatLevel: securityData.threatLevel === 'none' ? 'low' : securityData.threatLevel,
        vulnerabilities: securityData.vulnerabilities.map(v => ({
          type: v.type,
          pattern: v.pattern,
          severity: v.severity,
          source: v.source
        })),
        proxyInfo: req.proxyInfo || (req.proxyTarget ? { 
          targetUrl: req.proxyTarget,
          proxied: true 
        } : undefined),
        sanitized: securityData.sanitizedData ? Object.keys(securityData.sanitizedData).length > 0 : false
      });

      await logEntry.save();
      
      req.requestLogId = logEntry._id;
      
    } catch (error) {
      logger.error(`Failed to log request: ${error.message}`, error);
    }
  }

  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    delete sanitized.authorization;
    delete sanitized.cookie;
    delete sanitized['x-api-key'];
    return sanitized;
  }

  sanitizeBody(body) {
    if (!body || typeof body !== 'object') {
      return body;
    }

    const sanitized = { ...body };
    const sensitiveFields = ['password', 'token', 'secret', 'key', 'auth'];
    
    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    logger.info('Security middleware configuration updated');
  }

  getConfig() {
    return { ...this.config };
  }
}

export default new SecurityMiddleware();