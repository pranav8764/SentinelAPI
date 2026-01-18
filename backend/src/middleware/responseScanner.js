const logger = require('../utils/logger');
const { checkForVulnerabilities } = require('../config/securityPatterns');
const { sanitizeXSS } = require('../utils/sanitizer');

const SCAN_CONFIG = {
  maxScanSize: 1024 * 1024,
  scanContentTypes: [
    'text/html',
    'text/plain',
    'application/json',
    'application/xml',
    'text/xml',
    'application/javascript',
    'text/javascript'
  ],
  scanHeaders: [
    'location',
    'refresh',
    'set-cookie',
    'x-frame-options',
    'content-security-policy'
  ],
  autoSanitize: process.env.AUTO_SANITIZE_RESPONSES === 'true',
  blockXSSResponses: process.env.BLOCK_XSS_RESPONSES === 'true'
};

function shouldScanContentType(contentType) {
  if (!contentType) return false;
  
  return SCAN_CONFIG.scanContentTypes.some(type => 
    contentType.toLowerCase().includes(type)
  );
}

function scanResponseBody(body, contentType) {
  if (!body || typeof body !== 'string') {
    return { vulnerabilities: [], sanitized: body };
  }
  
  if (body.length > SCAN_CONFIG.maxScanSize) {
    logger.warn('Response too large to scan', { size: body.length });
    return { vulnerabilities: [], sanitized: body };
  }
  
  const vulnerabilities = [];
  let sanitized = body;
  
  try {
    const xssVulns = checkForVulnerabilities(body, 'xss');
    vulnerabilities.push(...xssVulns);
    
    if (contentType && contentType.includes('application/json')) {
      try {
        const parsed = JSON.parse(body);
        const jsonString = JSON.stringify(parsed);
        const jsonVulns = checkForVulnerabilities(jsonString, 'xss');
        vulnerabilities.push(...jsonVulns.map(v => ({ ...v, location: 'json_content' })));
      } catch (e) {
      }
    }
    
    if (SCAN_CONFIG.autoSanitize && vulnerabilities.length > 0) {
      sanitized = sanitizeXSS(body, { 
        encodeEntities: true,
        removeTags: true,
        removeAttributes: true 
      });
      
      logger.info('Response sanitized due to XSS detection', {
        originalLength: body.length,
        sanitizedLength: sanitized.length,
        vulnerabilityCount: vulnerabilities.length
      });
    }
    
    return { vulnerabilities, sanitized };
    
  } catch (error) {
    logger.error('Error scanning response body:', error);
    return { vulnerabilities: [], sanitized: body };
  }
}

function scanResponseHeaders(headers) {
  const vulnerabilities = [];
  
  if (!headers || typeof headers !== 'object') {
    return vulnerabilities;
  }
  
  try {
    SCAN_CONFIG.scanHeaders.forEach(headerName => {
      const headerValue = headers[headerName];
      if (headerValue && typeof headerValue === 'string') {
        const headerVulns = checkForVulnerabilities(headerValue, 'xss');
        vulnerabilities.push(...headerVulns.map(v => ({ 
          ...v, 
          location: `header_${headerName}` 
        })));
      }
    });
    
    const securityHeaders = {
      'x-frame-options': 'Missing X-Frame-Options header',
      'x-content-type-options': 'Missing X-Content-Type-Options header',
      'x-xss-protection': 'Missing X-XSS-Protection header',
      'content-security-policy': 'Missing Content-Security-Policy header',
      'strict-transport-security': 'Missing Strict-Transport-Security header'
    };
    
    Object.entries(securityHeaders).forEach(([header, description]) => {
      if (!headers[header] && !headers[header.toLowerCase()]) {
        vulnerabilities.push({
          type: 'missing_security_header',
          severity: 'medium',
          description,
          location: `missing_header_${header}`
        });
      }
    });
    
    return vulnerabilities;
    
  } catch (error) {
    logger.error('Error scanning response headers:', error);
    return [];
  }
}

function generateSecurityHeaders(req, existingHeaders = {}) {
  const securityHeaders = {};
  
  if (!existingHeaders['x-frame-options']) {
    securityHeaders['X-Frame-Options'] = 'DENY';
  }
  
  if (!existingHeaders['x-content-type-options']) {
    securityHeaders['X-Content-Type-Options'] = 'nosniff';
  }
  
  if (!existingHeaders['x-xss-protection']) {
    securityHeaders['X-XSS-Protection'] = '1; mode=block';
  }
  
  if (!existingHeaders['referrer-policy']) {
    securityHeaders['Referrer-Policy'] = 'strict-origin-when-cross-origin';
  }
  
  if (!existingHeaders['permissions-policy']) {
    securityHeaders['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()';
  }
  
  if (!existingHeaders['content-security-policy']) {
    securityHeaders['Content-Security-Policy'] = 
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; object-src 'none'; frame-src 'none';";
  }
  
  if (req.secure && !existingHeaders['strict-transport-security']) {
    securityHeaders['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }
  
  return securityHeaders;
}

function responseScanner(options = {}) {
  const config = { ...SCAN_CONFIG, ...options };
  
  return (req, res, next) => {
    const originalSend = res.send;
    const originalJson = res.json;
    const originalEnd = res.end;
    
    let responseBody = null;
    let responseVulnerabilities = [];
    
    res.send = function(body) {
      responseBody = body;
      
      if (config.scanResponses !== false) {
        const contentType = res.get('Content-Type');
        
        if (shouldScanContentType(contentType)) {
          const scanResult = scanResponseBody(body, contentType);
          responseVulnerabilities.push(...scanResult.vulnerabilities);
          
          if (config.autoSanitize && scanResult.sanitized !== body) {
            body = scanResult.sanitized;
          }
          
          if (config.blockXSSResponses && scanResult.vulnerabilities.length > 0) {
            const xssVulns = scanResult.vulnerabilities.filter(v => v.type === 'xss');
            if (xssVulns.length > 0) {
              logger.warn('Blocking response due to XSS detection', {
                url: req.originalUrl,
                vulnerabilities: xssVulns.length
              });
              
              return originalSend.call(this, JSON.stringify({
                error: 'Response blocked due to security policy',
                reason: 'XSS content detected',
                timestamp: new Date().toISOString()
              }));
            }
          }
        }
      }
      
      const securityHeaders = generateSecurityHeaders(req, res.getHeaders());
      Object.entries(securityHeaders).forEach(([name, value]) => {
        res.set(name, value);
      });
      
      if (responseVulnerabilities.length > 0) {
        logger.warn('Response vulnerabilities detected', {
          url: req.originalUrl,
          method: req.method,
          vulnerabilities: responseVulnerabilities.map(v => ({
            type: v.type,
            severity: v.severity,
            description: v.description,
            location: v.location
          }))
        });
        
        req.responseVulnerabilities = responseVulnerabilities;
      }
      
      return originalSend.call(this, body);
    };
    
    res.json = function(obj) {
      const body = JSON.stringify(obj);
      return res.send(body);
    };
    
    res.end = function(chunk, encoding) {
      if (chunk) {
        return res.send(chunk);
      }
      return originalEnd.call(this, chunk, encoding);
    };
    
    const originalSetHeader = res.setHeader;
    res.setHeader = function(name, value) {
      if (typeof value === 'string' && SCAN_CONFIG.scanHeaders.includes(name.toLowerCase())) {
        const headerVulns = checkForVulnerabilities(value, 'xss');
        if (headerVulns.length > 0) {
          logger.warn('XSS detected in response header', {
            header: name,
            value: value.substring(0, 100),
            vulnerabilities: headerVulns.length
          });
          
          responseVulnerabilities.push(...headerVulns.map(v => ({ 
            ...v, 
            location: `header_${name}` 
          })));
          
          if (config.autoSanitize) {
            value = sanitizeXSS(value, { encodeEntities: true });
          }
        }
      }
      
      return originalSetHeader.call(this, name, value);
    };
    
    next();
  };
}

function securityHeaders(options = {}) {
  return (req, res, next) => {
    const headers = generateSecurityHeaders(req, res.getHeaders());
    Object.entries(headers).forEach(([name, value]) => {
      res.set(name, value);
    });
    next();
  };
}

module.exports = {
  responseScanner,
  securityHeaders,
  scanResponseBody,
  scanResponseHeaders,
  generateSecurityHeaders,
  SCAN_CONFIG
};