import { checkForVulnerabilities, getThreatLevel } from '../config/securityPatterns.js';
import RequestLog from '../models/RequestLog.js';
import logger from '../utils/logger.js';

class SecurityMiddleware {
  constructor() {
    this.config = {
      enabled: true,
      logAllRequests: true,
      blockThreats: true,
      minThreatLevel: 'critical' // Only block critical threats initially
    };
  }

  // Main security middleware function
  middleware() {
    return async (req, res, next) => {
      if (!this.config.enabled) {
        return next();
      }

      const startTime = Date.now();
      let blocked = false;
      let vulnerabilities = [];
      let threatLevel = 'low';

      try {
        // Check URL parameters
        const urlVulns = this.checkInput(req.url, 'URL');
        vulnerabilities = vulnerabilities.concat(urlVulns);

        // Check query parameters
        if (req.query && Object.keys(req.query).length > 0) {
          const queryString = JSON.stringify(req.query);
          const queryVulns = this.checkInput(queryString, 'Query');
          vulnerabilities = vulnerabilities.concat(queryVulns);
        }

        // Check request body
        if (req.body && Object.keys(req.body).length > 0) {
          const bodyString = JSON.stringify(req.body);
          const bodyVulns = this.checkInput(bodyString, 'Body');
          vulnerabilities = vulnerabilities.concat(bodyVulns);
        }

        // Check headers for potential threats
        const userAgent = req.get('User-Agent') || '';
        const headerVulns = this.checkInput(userAgent, 'Headers');
        vulnerabilities = vulnerabilities.concat(headerVulns);

        // Determine overall threat level
        threatLevel = getThreatLevel(vulnerabilities);

        // Decide whether to block the request
        blocked = this.shouldBlock(threatLevel, vulnerabilities);

        if (blocked) {
          logger.warn(`Blocked request from ${req.ip}: ${threatLevel} threat detected`);
          
          // Log the blocked request
          await this.logRequest(req, res, {
            blocked: true,
            threatLevel,
            vulnerabilities,
            responseTime: Date.now() - startTime,
            statusCode: 403
          });

          return res.status(403).json({
            error: 'Request blocked by security policy',
            code: 'SECURITY_VIOLATION',
            timestamp: new Date().toISOString()
          });
        }

        // Log the request if configured to do so
        if (this.config.logAllRequests || vulnerabilities.length > 0) {
          // Override res.end to capture response details
          const originalEnd = res.end;
          res.end = async (chunk, encoding) => {
            await this.logRequest(req, res, {
              blocked: false,
              threatLevel,
              vulnerabilities,
              responseTime: Date.now() - startTime,
              statusCode: res.statusCode
            });
            
            originalEnd.call(res, chunk, encoding);
          };
        }

        // Add security headers
        this.addSecurityHeaders(res);

        next();

      } catch (error) {
        logger.error(`Security middleware error: ${error.message}`);
        next();
      }
    };
  }

  // Check input for vulnerabilities
  checkInput(input, source) {
    if (!input) return [];

    const vulnerabilities = checkForVulnerabilities(input);
    return vulnerabilities.map(vuln => ({
      ...vuln,
      source
    }));
  }

  // Determine if request should be blocked
  shouldBlock(threatLevel, vulnerabilities) {
    if (!this.config.blockThreats) {
      return false;
    }

    const threatLevels = ['low', 'medium', 'high', 'critical'];
    const minLevel = threatLevels.indexOf(this.config.minThreatLevel);
    const currentLevel = threatLevels.indexOf(threatLevel);

    return currentLevel >= minLevel;
  }

  // Add security headers to response
  addSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Powered-By', 'SentinelAPI');
  }

  // Log request to database
  async logRequest(req, res, securityData) {
    try {
      const logEntry = new RequestLog({
        method: req.method,
        url: req.url,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get('User-Agent') || '',
        headers: this.sanitizeHeaders(req.headers),
        body: this.sanitizeBody(req.body),
        query: req.query,
        statusCode: securityData.statusCode,
        responseTime: securityData.responseTime,
        blocked: securityData.blocked,
        threatLevel: securityData.threatLevel,
        vulnerabilities: securityData.vulnerabilities.map(v => ({
          type: v.type,
          pattern: v.pattern,
          severity: v.severity
        })),
        proxyTarget: req.proxyTarget || null
      });

      await logEntry.save();
    } catch (error) {
      logger.error(`Failed to log request: ${error.message}`);
    }
  }

  // Sanitize headers for logging (remove sensitive data)
  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    delete sanitized.authorization;
    delete sanitized.cookie;
    delete sanitized['x-api-key'];
    return sanitized;
  }

  // Sanitize body for logging (remove sensitive data)
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

  // Update configuration
  updateConfig(newConfig) {
    this.config = { ...this.config, ...newConfig };
    logger.info('Security middleware configuration updated');
  }

  // Get current configuration
  getConfig() {
    return { ...this.config };
  }
}

export default new SecurityMiddleware();