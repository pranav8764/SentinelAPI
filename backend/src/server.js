import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';

// Load environment variables
dotenv.config();

// Import custom modules
import database from './config/database.js';
import logger from './utils/logger.js';
import requestLogger from './middleware/requestLogger.js';
import securityMiddleware from './middleware/security.js';
import { nosqlProtection } from './middleware/nosqlProtection.js';

// Import routes
import adminRoutes from './routes/admin.js';
import authRoutes from './routes/auth.js';
import authTestRoutes from './routes/authTest.js';
import apiKeysRoutes from './routes/apiKeys.js';
import proxyManagementRoutes from './routes/proxy.js';
import scannerRoutes from './routes/scanner.js';
import monitoringRoutes from './routes/monitoring.js';
import vulnerabilityRoutes from './routes/vulnerability.js';
import testRoutes from './routes/test.js';

// Import proxy middleware
import { createProxy, validateProxyTarget, logProxyRequest } from './middleware/proxy.js';
import { proxyLimiter } from './middleware/rateLimit.js';

// Import live monitoring
import LiveMonitor from './services/liveMonitor.js';

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);

// Apply NoSQL protection globally (before security middleware)
// Exclude scanner and vulnerability routes as they need to handle URLs with special characters
app.use((req, res, next) => {
  if (req.path.startsWith('/api/scanner') || req.path.startsWith('/api/vulnerability')) {
    // Skip strict NoSQL protection for scanner and vulnerability routes
    return next();
  }
  
  nosqlProtection({
    sanitizeBody: true,
    sanitizeQuery: true,
    sanitizeParams: true,
    allowOperators: false,
    strictMode: true,
    blockOnDanger: true
  })(req, res, next);
});

// Apply security middleware but skip scanner and vulnerability routes
app.use((req, res, next) => {
  if (req.path.startsWith('/api/scanner') || req.path.startsWith('/api/vulnerability')) {
    // Skip security middleware for scanner and vulnerability routes (URLs need special chars)
    return next();
  }
  securityMiddleware.middleware()(req, res, next);
});

// Store Socket.IO instance on app for middleware access
app.set('io', io);

// Initialize live monitoring
const liveMonitor = new LiveMonitor(io);
app.set('liveMonitor', liveMonitor);

// Initialize database connection
database.connect();

// Basic route
app.get('/', (req, res) => {
  res.json({ 
    message: 'SentinelAPI Backend is running!',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/auth-test', authTestRoutes);
app.use('/api/api-keys', apiKeysRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/proxy', proxyManagementRoutes);
app.use('/api/scanner', scannerRoutes);
app.use('/api/monitoring', monitoringRoutes);
app.use('/api/vulnerability', vulnerabilityRoutes);
app.use('/api/test', testRoutes);

// Proxy route - forwards requests to target API
app.use('/proxy',
  proxyLimiter,
  validateProxyTarget,
  securityMiddleware.middleware(),
  logProxyRequest,
  createProxy()
);

// Socket.io connection
io.on('connection', (socket) => {
  logger.info(`Client connected: ${socket.id}`);

  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    logger.info('Process terminated');
    database.disconnect();
  });
});

export { app, server, io };
