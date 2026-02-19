import express from 'express';
import RequestLog from '../models/RequestLog.js';
import SecurityConfig from '../models/SecurityConfig.js';
import AdminUser from '../models/AdminUser.js';
import logger from '../utils/logger.js';
import { authenticate, requireRole, requirePermission } from '../middleware/auth.js';
import { updateRateLimitConfig, getRateLimitConfig } from '../middleware/rateLimit.js';

const router = express.Router();

// Apply authentication to all admin routes
router.use(authenticate);

// Get request logs with pagination and filtering
router.get('/logs', requirePermission('view_logs'), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const skip = (page - 1) * limit;

    // Build filter
    const filter = {};
    if (req.query.blocked !== undefined) {
      filter.blocked = req.query.blocked === 'true';
    }
    if (req.query.threatLevel) {
      filter.threatLevel = req.query.threatLevel;
    }
    if (req.query.ip) {
      filter.ip = req.query.ip;
    }
    if (req.query.method) {
      filter.method = req.query.method;
    }

    const logs = await RequestLog.find(filter)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    const total = await RequestLog.countDocuments(filter);

    res.json({
      logs,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    logger.error(`Error fetching logs: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// Get security statistics
router.get('/stats', requirePermission('view_analytics'), async (req, res) => {
  try {
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const last7d = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    const [
      totalRequests,
      blockedRequests,
      requests24h,
      blocked24h,
      requests7d,
      blocked7d,
      threatLevelStats,
      topIPs
    ] = await Promise.all([
      RequestLog.countDocuments(),
      RequestLog.countDocuments({ blocked: true }),
      RequestLog.countDocuments({ timestamp: { $gte: last24h } }),
      RequestLog.countDocuments({ timestamp: { $gte: last24h }, blocked: true }),
      RequestLog.countDocuments({ timestamp: { $gte: last7d } }),
      RequestLog.countDocuments({ timestamp: { $gte: last7d }, blocked: true }),
      RequestLog.aggregate([
        { $group: { _id: '$threatLevel', count: { $sum: 1 } } }
      ]),
      RequestLog.aggregate([
        { $group: { _id: '$ip', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ])
    ]);

    res.json({
      overview: {
        totalRequests,
        blockedRequests,
        blockRate: totalRequests > 0 ? (blockedRequests / totalRequests * 100).toFixed(2) : 0
      },
      last24h: {
        requests: requests24h,
        blocked: blocked24h,
        blockRate: requests24h > 0 ? (blocked24h / requests24h * 100).toFixed(2) : 0
      },
      last7d: {
        requests: requests7d,
        blocked: blocked7d,
        blockRate: requests7d > 0 ? (blocked7d / requests7d * 100).toFixed(2) : 0
      },
      threatLevels: threatLevelStats.reduce((acc, item) => {
        acc[item._id] = item.count;
        return acc;
      }, {}),
      topIPs: topIPs.map(item => ({
        ip: item._id,
        requests: item.count
      }))
    });
  } catch (error) {
    logger.error(`Error fetching stats: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Get recent blocked requests
router.get('/recent-threats', requirePermission('view_logs'), async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 20;
    
    const threats = await RequestLog.find({ blocked: true })
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('timestamp method url ip threatLevel vulnerabilities')
      .lean();

    res.json({ threats });
  } catch (error) {
    logger.error(`Error fetching recent threats: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch recent threats' });
  }
});

// Get security configuration
router.get('/config', requirePermission('manage_config'), async (req, res) => {
  try {
    const config = await SecurityConfig.findOne({ name: 'default' });
    if (!config) {
      return res.status(404).json({ error: 'Security configuration not found' });
    }
    res.json({ config });
  } catch (error) {
    logger.error(`Error fetching config: ${error.message}`);
    res.status(500).json({ error: 'Failed to fetch configuration' });
  }
});

// Update security configuration
router.put('/config', requirePermission('manage_config'), async (req, res) => {
  try {
    const config = await SecurityConfig.findOneAndUpdate(
      { name: 'default' },
      req.body,
      { new: true, upsert: true }
    );
    
    logger.info('Security configuration updated');
    res.json({ config, message: 'Configuration updated successfully' });
  } catch (error) {
    logger.error(`Error updating config: ${error.message}`);
    res.status(500).json({ error: 'Failed to update configuration' });
  }
});

// Health check for admin API
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'admin-api'
  });
});

// Get rate limit configuration
router.get('/rate-limit', requirePermission('view_analytics'), (req, res) => {
  try {
    const config = getRateLimitConfig();
    res.json({
      success: true,
      config,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error(`Error fetching rate limit config: ${error.message}`);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch rate limit configuration' 
    });
  }
});

// Update rate limit configuration
router.put('/rate-limit', requirePermission('manage_config'), async (req, res) => {
  try {
    const { windowMs, max, message } = req.body;
    
    // Validate input
    if (windowMs && (windowMs < 1000 || windowMs > 3600000)) {
      return res.status(400).json({
        success: false,
        error: 'windowMs must be between 1000 (1 second) and 3600000 (1 hour)',
      });
    }
    
    if (max && (max < 1 || max > 10000)) {
      return res.status(400).json({
        success: false,
        error: 'max must be between 1 and 10000',
      });
    }
    
    const success = await updateRateLimitConfig({ windowMs, max, message });
    
    if (success) {
      logger.info('Rate limit configuration updated via admin API');
      res.json({
        success: true,
        message: 'Rate limit configuration updated successfully',
        config: getRateLimitConfig(),
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'Failed to update rate limit configuration',
      });
    }
  } catch (error) {
    logger.error(`Error updating rate limit config: ${error.message}`);
    res.status(500).json({
      success: false,
      error: 'Failed to update rate limit configuration',
    });
  }
});

// Delete all logs
router.delete('/logs', requirePermission('manage_config'), async (req, res) => {
  try {
    const result = await RequestLog.deleteMany({});
    logger.info(`All logs cleared: ${result.deletedCount} logs deleted`);
    res.json({
      success: true,
      message: 'All logs cleared successfully',
      deletedCount: result.deletedCount
    });
  } catch (error) {
    logger.error(`Error clearing logs: ${error.message}`);
    res.status(500).json({ 
      success: false,
      error: 'Failed to clear logs' 
    });
  }
});

export default router;