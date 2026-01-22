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
import proxyManagementRoutes from './routes/proxy.js';

// Import proxy middleware
import { createProxy, validateProxyTarget, logProxyRequest } from './middleware/proxy.js';
import { proxyLimiter } from './middleware/rateLimit.js';

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
app.use(nosqlProtection({
  sanitizeBody: true,
  sanitizeQuery: true,
  sanitizeParams: true,
  allowOperators: false,
  strictMode: true,
  blockOnDanger: true
}));

app.use(securityMiddleware.middleware());

// Store Socket.IO instance on app for middleware access
app.set('io', io);

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
app.use('/api/admin', adminRoutes);
app.use('/api/proxy', proxyManagementRoutes);

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
