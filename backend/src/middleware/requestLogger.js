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
    
    // Call original end method
    originalEnd.call(this, chunk, encoding);
  };
  
  next();
};

export default requestLogger;