const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const http = require('http');
const socketIo = require('socket.io');

// Load environment variables
dotenv.config();

// Import custom modules
const database = require('./config/database');
const logger = require('./utils/logger');
const requestLogger = require('./middleware/requestLogger');
const securityMiddleware = require('./middleware/security');

// Import routes
const adminRoutes = require('./routes/admin');
const authRoutes = require('./routes/auth');
const proxyManagementRoutes = require('./routes/proxy');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
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
app.use(securityMiddleware.middleware());

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
const { createProxy, validateProxyTarget, logProxyRequest } = require('./middleware/proxy');
const { proxyLimiter } = require('./middleware/rateLimit');

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

module.exports = { app, server, io };