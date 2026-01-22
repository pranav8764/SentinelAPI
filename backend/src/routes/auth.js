import express from 'express';
import AdminUser from '../models/AdminUser.js';
import { generateToken, authenticate } from '../middleware/auth.js';
import { nosqlProtection, validateUserInput } from '../middleware/nosqlProtection.js';
import logger from '../utils/logger.js';

const router = express.Router();

// Apply strict NoSQL protection to all auth routes
router.use(nosqlProtection({
  sanitizeBody: true,
  sanitizeQuery: true,
  allowOperators: false,  // Never allow operators in auth
  strictMode: true,       // Strict sanitization
  blockOnDanger: true     // Block dangerous patterns immediately
}));

// Login
router.post('/login', async (req, res) => {
  try {
    // Validate and sanitize inputs
    const username = validateUserInput(req.body.username, 'string');
    const password = validateUserInput(req.body.password, 'string');

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required.',
        code: 'MISSING_CREDENTIALS'
      });
    }

    // Find user by username or email (safe because inputs are validated)
    const user = await AdminUser.findOne({
      $or: [{ username }, { email: username }]
    });

    if (!user) {
      return res.status(401).json({
        error: 'Invalid credentials.',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Check if account is locked
    if (user.isLocked) {
      const lockTime = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(401).json({
        error: `Account locked. Try again in ${lockTime} minutes.`,
        code: 'ACCOUNT_LOCKED'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      return res.status(401).json({
        error: 'Account is deactivated.',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Verify password
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      await user.incLoginAttempts();
      logger.warn(`Failed login attempt for user: ${username}`);
      return res.status(401).json({
        error: 'Invalid credentials.',
        code: 'INVALID_CREDENTIALS'
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();

    // Generate token
    const token = generateToken(user);

    logger.info(`User logged in: ${username}`);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      }
    });
  } catch (error) {
    logger.error(`Login error: ${error.message}`);
    res.status(500).json({
      error: 'Login failed.',
      code: 'LOGIN_ERROR'
    });
  }
});

// Register (only for initial setup or admin creation)
router.post('/register', async (req, res) => {
  try {
    // Validate and sanitize inputs
    const username = validateUserInput(req.body.username, 'string');
    const email = validateUserInput(req.body.email, 'email');
    const password = validateUserInput(req.body.password, 'string');
    const role = req.body.role ? validateUserInput(req.body.role, 'string') : 'admin';

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({
        error: 'Username, email, and password are required.',
        code: 'MISSING_FIELDS'
      });
    }

    // Check if user already exists (safe because inputs are validated)
    const existingUser = await AdminUser.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      return res.status(400).json({
        error: 'Username or email already exists.',
        code: 'USER_EXISTS'
      });
    }

    // Create new user (all inputs are validated)
    const user = new AdminUser({
      username,
      email,
      password,
      role,
      permissions: ['view_logs', 'manage_config', 'view_analytics']
    });

    await user.save();

    // Generate token
    const token = generateToken(user);

    logger.info(`New admin user registered: ${username}`);

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        permissions: user.permissions
      }
    });
  } catch (error) {
    logger.error(`Registration error: ${error.message}`);
    res.status(500).json({
      error: 'Registration failed.',
      code: 'REGISTRATION_ERROR'
    });
  }
});

// Get current user profile
router.get('/me', authenticate, async (req, res) => {
  res.json({
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      permissions: req.user.permissions,
      lastLogin: req.user.lastLogin,
      createdAt: req.user.createdAt
    }
  });
});

// Refresh token
router.post('/refresh', authenticate, async (req, res) => {
  const token = generateToken(req.user);
  res.json({ token });
});

// Logout (client-side token removal, but we can log it)
router.post('/logout', authenticate, async (req, res) => {
  logger.info(`User logged out: ${req.user.username}`);
  res.json({ message: 'Logged out successfully' });
});

export default router;