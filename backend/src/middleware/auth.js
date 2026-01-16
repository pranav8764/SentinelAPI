const jwt = require('jsonwebtoken');
const AdminUser = require('../models/AdminUser');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'sentinel-secret-key-change-in-production';
const JWT_EXPIRE = process.env.JWT_EXPIRE || '7d';

// Generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      username: user.username,
      role: user.role,
      permissions: user.permissions
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRE }
  );
};

// Verify JWT token middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }

    const token = authHeader.split(' ')[1];

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      
      // Verify user still exists and is active
      const user = await AdminUser.findById(decoded.id).select('-password');
      
      if (!user) {
        return res.status(401).json({
          error: 'User not found.',
          code: 'USER_NOT_FOUND'
        });
      }

      if (!user.isActive) {
        return res.status(401).json({
          error: 'Account is deactivated.',
          code: 'ACCOUNT_DEACTIVATED'
        });
      }

      if (user.isLocked) {
        return res.status(401).json({
          error: 'Account is locked. Try again later.',
          code: 'ACCOUNT_LOCKED'
        });
      }

      req.user = user;
      next();
    } catch (jwtError) {
      if (jwtError.name === 'TokenExpiredError') {
        return res.status(401).json({
          error: 'Token expired.',
          code: 'TOKEN_EXPIRED'
        });
      }
      return res.status(401).json({
        error: 'Invalid token.',
        code: 'INVALID_TOKEN'
      });
    }
  } catch (error) {
    logger.error(`Auth middleware error: ${error.message}`);
    return res.status(500).json({
      error: 'Authentication error.',
      code: 'AUTH_ERROR'
    });
  }
};

// Check role middleware
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Not authenticated.',
        code: 'NOT_AUTHENTICATED'
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'Insufficient permissions.',
        code: 'INSUFFICIENT_ROLE'
      });
    }

    next();
  };
};

// Check permission middleware
const requirePermission = (...permissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: 'Not authenticated.',
        code: 'NOT_AUTHENTICATED'
      });
    }

    const hasPermission = permissions.some(p => 
      req.user.permissions && req.user.permissions.includes(p)
    );

    // Admin role has all permissions
    if (req.user.role === 'admin' || hasPermission) {
      return next();
    }

    return res.status(403).json({
      error: 'Insufficient permissions.',
      code: 'INSUFFICIENT_PERMISSION'
    });
  };
};

module.exports = {
  generateToken,
  authenticate,
  requireRole,
  requirePermission,
  JWT_SECRET,
  JWT_EXPIRE
};