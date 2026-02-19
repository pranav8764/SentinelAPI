import logger from '../utils/logger.js';

const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  // Log incoming request
  logger.http(`${req.method} ${req.url} - ${req.ip}`);
  
  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const duration = Date.now() - start;
    logger.http(`${req.method} ${req.url} - ${res.statusCode} - ${duration}ms`);
    
    // Emit to live monitor
    const logData = {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('user-agent') || '',
      headers: req.headers,
      body: req.body,
      query: req.query,
      statusCode: res.statusCode,
      responseTime: duration,
      blocked: req.blocked || false,
      threatLevel: req.threatLevel || 'low',
      vulnerabilities: req.vulnerabilities || []
    };

    // Emit to live monitor
    const liveMonitor = req.app.get('liveMonitor');
    if (liveMonitor) {
      liveMonitor.emitRequest(logData);
      
      // Emit security alert for blocked requests
      if (req.blocked && req.threatLevel !== 'low') {
        liveMonitor.emitAlert({
          severity: req.threatLevel,
          type: 'blocked_request',
          message: `Blocked ${req.threatLevel} threat from ${req.ip}`,
          ip: req.ip,
          details: {
            method: req.method,
            url: req.url,
            vulnerabilities: req.vulnerabilities
          }
        });
      }
    }
    
    // Call original end method
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

export default requestLogger;