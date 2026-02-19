import express from 'express';
import RequestLog from '../models/RequestLog.js';
import { authenticate } from '../middleware/auth.js';

const router = express.Router();

// Get real-time statistics
router.get('/stats/realtime', authenticate, async (req, res) => {
  try {
    const liveMonitor = req.app.get('liveMonitor');
    const metrics = liveMonitor ? liveMonitor.getCurrentMetrics() : null;

    res.json({
      success: true,
      metrics
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching real-time stats',
      error: error.message
    });
  }
});

// Get recent activity (last N requests)
router.get('/activity/recent', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 50;
    
    const recentRequests = await RequestLog.find()
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('timestamp method url ip statusCode responseTime blocked threatLevel');

    res.json({
      success: true,
      requests: recentRequests
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching recent activity',
      error: error.message
    });
  }
});

// Get time-series data for charts
router.get('/stats/timeseries', authenticate, async (req, res) => {
  try {
    const hours = parseInt(req.query.hours) || 24;
    const startTime = new Date(Date.now() - hours * 60 * 60 * 1000);

    const requests = await RequestLog.find({
      timestamp: { $gte: startTime }
    }).select('timestamp blocked threatLevel responseTime');

    // Group by hour
    const hourlyData = {};
    requests.forEach(req => {
      const hour = new Date(req.timestamp).setMinutes(0, 0, 0);
      if (!hourlyData[hour]) {
        hourlyData[hour] = {
          timestamp: hour,
          total: 0,
          blocked: 0,
          avgResponseTime: 0,
          responseTimeSum: 0,
          threats: { low: 0, medium: 0, high: 0, critical: 0 }
        };
      }
      hourlyData[hour].total++;
      if (req.blocked) hourlyData[hour].blocked++;
      hourlyData[hour].responseTimeSum += req.responseTime || 0;
      hourlyData[hour].threats[req.threatLevel]++;
    });

    // Calculate averages
    const timeseries = Object.values(hourlyData).map(data => ({
      timestamp: data.timestamp,
      total: data.total,
      blocked: data.blocked,
      avgResponseTime: data.total > 0 ? data.responseTimeSum / data.total : 0,
      threats: data.threats
    })).sort((a, b) => a.timestamp - b.timestamp);

    res.json({
      success: true,
      timeseries
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching time-series data',
      error: error.message
    });
  }
});

// Get top IPs by request count
router.get('/stats/top-ips', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const hours = parseInt(req.query.hours) || 24;
    const startTime = new Date(Date.now() - hours * 60 * 60 * 1000);

    const topIPs = await RequestLog.aggregate([
      { $match: { timestamp: { $gte: startTime } } },
      {
        $group: {
          _id: '$ip',
          count: { $sum: 1 },
          blocked: { $sum: { $cond: ['$blocked', 1, 0] } }
        }
      },
      { $sort: { count: -1 } },
      { $limit: limit }
    ]);

    res.json({
      success: true,
      topIPs: topIPs.map(item => ({
        ip: item._id,
        requests: item.count,
        blocked: item.blocked
      }))
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching top IPs',
      error: error.message
    });
  }
});

export default router;
