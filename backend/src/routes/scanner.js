import express from 'express';
import scanner from '../services/scanner.js';
import ScanResult from '../models/ScanResult.js';
import { authenticate } from '../middleware/auth.js';
import logger from '../utils/logger.js';

const router = express.Router();

// Apply authentication to all scanner routes
router.use(authenticate);

// Note: NoSQL protection is skipped for scanner routes in server.js
// because URLs contain special characters that would be sanitized

/**
 * POST /api/scanner/scan
 * Scan a single endpoint
 */
router.post('/scan', async (req, res) => {
  try {
    // Decode HTML entities in the URL (middleware is encoding slashes)
    let url = req.body.url;
    
    if (url) {
      // Decode HTML entities like #x2F back to /
      url = url.replace(/#x2F/g, '/').replace(/#x3A/g, ':');
    }

    const {
      method = 'GET',
      headers = {},
      body = null,
      authType = 'none',
      authConfig = {}
    } = req.body;

    // Validate required fields
    if (!url) {
      return res.status(400).json({
        error: 'URL is required',
        code: 'MISSING_URL'
      });
    }

    // Validate URL format
    try {
      const urlObj = new URL(url);
      // Ensure it's http or https
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return res.status(400).json({
          error: 'URL must use HTTP or HTTPS protocol',
          code: 'INVALID_PROTOCOL'
        });
      }
    } catch (error) {
      return res.status(400).json({
        error: 'Invalid URL format. Please include the full URL with protocol (e.g., https://api.example.com)',
        code: 'INVALID_URL',
        details: error.message
      });
    }

    logger.info(`Starting scan for ${url} by user ${req.user.username}`);

    // Perform the scan
    const scanResults = await scanner.scanEndpoint({
      url,
      method,
      headers,
      body,
      authType,
      authConfig
    });

    // Save scan results to database
    const scanRecord = new ScanResult({
      ...scanResults,
      userId: req.user._id
    });

    await scanRecord.save();

    logger.info(`Scan completed for ${url}: ${scanResults.vulnerabilities.length} vulnerabilities found`);

    res.json({
      success: true,
      scanId: scanRecord._id,
      results: scanResults
    });

  } catch (error) {
    logger.error(`Scan error: ${error.message}`);
    res.status(500).json({
      error: 'Scan failed',
      message: error.message,
      code: 'SCAN_ERROR'
    });
  }
});

/**
 * GET /api/scanner/history
 * Get scan history for the current user
 */
router.get('/history', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const scans = await ScanResult.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-tests') // Exclude detailed tests for list view
      .lean();

    const total = await ScanResult.countDocuments({ userId: req.user._id });

    res.json({
      scans,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });

  } catch (error) {
    logger.error(`Error fetching scan history: ${error.message}`);
    res.status(500).json({
      error: 'Failed to fetch scan history',
      code: 'FETCH_ERROR'
    });
  }
});

/**
 * GET /api/scanner/result/:id
 * Get detailed scan result by ID
 */
router.get('/result/:id', async (req, res) => {
  try {
    const scan = await ScanResult.findOne({
      _id: req.params.id,
      userId: req.user._id
    }).lean();

    if (!scan) {
      return res.status(404).json({
        error: 'Scan result not found',
        code: 'NOT_FOUND'
      });
    }

    res.json(scan);

  } catch (error) {
    logger.error(`Error fetching scan result: ${error.message}`);
    res.status(500).json({
      error: 'Failed to fetch scan result',
      code: 'FETCH_ERROR'
    });
  }
});

/**
 * DELETE /api/scanner/result/:id
 * Delete a scan result
 */
router.delete('/result/:id', async (req, res) => {
  try {
    const result = await ScanResult.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!result) {
      return res.status(404).json({
        error: 'Scan result not found',
        code: 'NOT_FOUND'
      });
    }

    logger.info(`Scan result ${req.params.id} deleted by user ${req.user.username}`);

    res.json({
      success: true,
      message: 'Scan result deleted'
    });

  } catch (error) {
    logger.error(`Error deleting scan result: ${error.message}`);
    res.status(500).json({
      error: 'Failed to delete scan result',
      code: 'DELETE_ERROR'
    });
  }
});

/**
 * GET /api/scanner/stats
 * Get scanning statistics for the current user
 */
router.get('/stats', async (req, res) => {
  try {
    const totalScans = await ScanResult.countDocuments({ userId: req.user._id });
    
    const vulnerabilityStats = await ScanResult.aggregate([
      { $match: { userId: req.user._id } },
      {
        $group: {
          _id: null,
          totalVulnerabilities: { $sum: '$summary.total' },
          critical: { $sum: '$summary.critical' },
          high: { $sum: '$summary.high' },
          medium: { $sum: '$summary.medium' },
          low: { $sum: '$summary.low' }
        }
      }
    ]);

    const recentScans = await ScanResult.find({ userId: req.user._id })
      .sort({ createdAt: -1 })
      .limit(5)
      .select('url method summary createdAt')
      .lean();

    res.json({
      totalScans,
      vulnerabilities: vulnerabilityStats[0] || {
        totalVulnerabilities: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      recentScans
    });

  } catch (error) {
    logger.error(`Error fetching scanner stats: ${error.message}`);
    res.status(500).json({
      error: 'Failed to fetch statistics',
      code: 'STATS_ERROR'
    });
  }
});

export default router;
