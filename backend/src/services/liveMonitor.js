import RequestLog from '../models/RequestLog.js';
import logger from '../utils/logger.js';

class LiveMonitor {
  constructor(io) {
    this.io = io;
    this.metrics = {
      requestsPerMinute: 0,
      blockedPerMinute: 0,
      avgResponseTime: 0,
      activeConnections: 0
    };
    this.requestBuffer = [];
    this.startMetricsAggregation();
  }

  // Emit real-time request event
  emitRequest(requestData) {
    this.io.emit('request:new', {
      timestamp: new Date(),
      method: requestData.method,
      url: requestData.url,
      ip: requestData.ip,
      statusCode: requestData.statusCode,
      responseTime: requestData.responseTime,
      blocked: requestData.blocked,
      threatLevel: requestData.threatLevel,
      vulnerabilities: requestData.vulnerabilities || []
    });

    this.requestBuffer.push(requestData);
  }

  // Emit security alert
  emitAlert(alertData) {
    this.io.emit('alert:security', {
      timestamp: new Date(),
      severity: alertData.severity,
      type: alertData.type,
      message: alertData.message,
      ip: alertData.ip,
      details: alertData.details
    });

    logger.warn(`Security Alert: ${alertData.message}`, { ip: alertData.ip });
  }

  // Emit system metrics
  emitMetrics(metrics) {
    this.io.emit('metrics:update', {
      timestamp: new Date(),
      ...metrics
    });
  }

  // Aggregate metrics every minute
  startMetricsAggregation() {
    setInterval(async () => {
      try {
        const oneMinuteAgo = new Date(Date.now() - 60000);
        
        const recentRequests = await RequestLog.find({
          timestamp: { $gte: oneMinuteAgo }
        });

        const metrics = {
          requestsPerMinute: recentRequests.length,
          blockedPerMinute: recentRequests.filter(r => r.blocked).length,
          avgResponseTime: recentRequests.length > 0
            ? recentRequests.reduce((sum, r) => sum + (r.responseTime || 0), 0) / recentRequests.length
            : 0,
          activeConnections: this.io.engine.clientsCount,
          threatDistribution: {
            low: recentRequests.filter(r => r.threatLevel === 'low').length,
            medium: recentRequests.filter(r => r.threatLevel === 'medium').length,
            high: recentRequests.filter(r => r.threatLevel === 'high').length,
            critical: recentRequests.filter(r => r.threatLevel === 'critical').length
          }
        };

        this.metrics = metrics;
        this.emitMetrics(metrics);
        
        // Clear buffer
        this.requestBuffer = [];
      } catch (error) {
        logger.error('Error aggregating metrics:', error);
      }
    }, 60000); // Every minute
  }

  // Get current metrics
  getCurrentMetrics() {
    return this.metrics;
  }
}

export default LiveMonitor;
