import express from 'express';
import ApiKey from '../models/ApiKey.js';
import { authenticate, requirePermission } from '../middleware/auth.js';
import logger from '../utils/logger.js';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Get all API keys for current user
router.get('/', async (req, res) => {
  try {
    const apiKeys = await ApiKey.find({ userId: req.user._id })
      .select('-hashedKey')
      .sort({ createdAt: -1 });

    // Don't expose the actual key in list view
    const sanitizedKeys = apiKeys.map(key => ({
      ...key.toObject(),
      key: `${key.key.substring(0, 12)}...${key.key.substring(key.key.length - 4)}`,
      isExpired: key.isExpired
    }));

    res.json({ apiKeys: sanitizedKeys });
  } catch (error) {
    logger.error(`Get API keys error: ${error.message}`);
    res.status(500).json({
      error: 'Failed to retrieve API keys',
      code: 'GET_KEYS_ERROR'
    });
  }
});

// Create new API key
router.post('/', async (req, res) => {
  try {
    const { name, permissions, expiresInDays, rateLimit } = req.body;

    if (!name) {
      return res.status(400).json({
        error: 'API key name is required',
        code: 'MISSING_NAME'
      });
    }

    // Generate new key
    const key = ApiKey.generateKey();

    // Calculate expiration
    let expiresAt = null;
    if (expiresInDays && expiresInDays > 0) {
      expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + expiresInDays);
    }

    const apiKey = new ApiKey({
      name,
      key,
      userId: req.user._id,
      permissions: permissions || ['read', 'scan'],
      expiresAt,
      rateLimit: rateLimit || {
        requestsPerMinute: 60,
        requestsPerHour: 1000
      }
    });

    await apiKey.save();

    logger.info(`API key created: ${name} by user: ${req.user.username}`);

    // Return the full key only once during creation
    res.status(201).json({
      message: 'API key created successfully',
      apiKey: {
        id: apiKey._id,
        name: apiKey.name,
        key: apiKey.key, // Full key shown only once
        permissions: apiKey.permissions,
        expiresAt: apiKey.expiresAt,
        createdAt: apiKey.createdAt
      },
      warning: 'Save this key securely. It will not be shown again.'
    });
  } catch (error) {
    logger.error(`Create API key error: ${error.message}`);
    res.status(500).json({
      error: 'Failed to create API key',
      code: 'CREATE_KEY_ERROR'
    });
  }
});

// Update API key
router.put('/:id', async (req, res) => {
  try {
    const { name, permissions, isActive, rateLimit } = req.body;

    const apiKey = await ApiKey.findOne({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!apiKey) {
      return res.status(404).json({
        error: 'API key not found',
        code: 'KEY_NOT_FOUND'
      });
    }

    if (name) apiKey.name = name;
    if (permissions) apiKey.permissions = permissions;
    if (typeof isActive === 'boolean') apiKey.isActive = isActive;
    if (rateLimit) apiKey.rateLimit = rateLimit;

    await apiKey.save();

    logger.info(`API key updated: ${apiKey.name} by user: ${req.user.username}`);

    res.json({
      message: 'API key updated successfully',
      apiKey: {
        id: apiKey._id,
        name: apiKey.name,
        permissions: apiKey.permissions,
        isActive: apiKey.isActive,
        rateLimit: apiKey.rateLimit
      }
    });
  } catch (error) {
    logger.error(`Update API key error: ${error.message}`);
    res.status(500).json({
      error: 'Failed to update API key',
      code: 'UPDATE_KEY_ERROR'
    });
  }
});

// Delete API key
router.delete('/:id', async (req, res) => {
  try {
    const apiKey = await ApiKey.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id
    });

    if (!apiKey) {
      return res.status(404).json({
        error: 'API key not found',
        code: 'KEY_NOT_FOUND'
      });
    }

    logger.info(`API key deleted: ${apiKey.name} by user: ${req.user.username}`);

    res.json({
      message: 'API key deleted successfully'
    });
  } catch (error) {
    logger.error(`Delete API key error: ${error.message}`);
    res.status(500).json({
      error: 'Failed to delete API key',
      code: 'DELETE_KEY_ERROR'
    });
  }
});

// Get API key usage statistics
router.get('/:id/stats', async (req, res) => {
  try {
    const apiKey = await ApiKey.findOne({
      _id: req.params.id,
      userId: req.user._id
    }).select('-hashedKey -key');

    if (!apiKey) {
      return res.status(404).json({
        error: 'API key not found',
        code: 'KEY_NOT_FOUND'
      });
    }

    res.json({
      stats: {
        name: apiKey.name,
        usageCount: apiKey.usageCount,
        lastUsed: apiKey.lastUsed,
        createdAt: apiKey.createdAt,
        isActive: apiKey.isActive,
        isExpired: apiKey.isExpired,
        expiresAt: apiKey.expiresAt
      }
    });
  } catch (error) {
    logger.error(`Get API key stats error: ${error.message}`);
    res.status(500).json({
      error: 'Failed to retrieve API key statistics',
      code: 'GET_STATS_ERROR'
    });
  }
});

export default router;
