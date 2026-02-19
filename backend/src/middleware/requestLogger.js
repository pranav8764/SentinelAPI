import logger from '../utils/logger.js';
import RequestLog from '../models/RequestLog.js';

const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  // Log incoming request
  logger.http(`${req.method} ${req.url} - ${req.ip}`);
  
  // Override res.end to log response
  const originalEnd = res.end;
  res.end = function(chunk, encoding) {
    const duration = Date.now() - start;
    logger.http(`${req.method} ${req.url} - ${res.statusCode} - ${duration}ms`);
    
    // Save to database and emit to live monitor
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

    // Save to database (async, don't wait)
    RequestLog.create(logData).catch(err => {
      logger.error('Error saving request log:', err);
    });

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