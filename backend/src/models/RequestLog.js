const mongoose = require('mongoose');

const requestLogSchema = new mongoose.Schema({
  timestamp: {
    type: Date,
    default: Date.now,
    index: true
  },
  method: {
    type: String,
    required: true,
    enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
  },
  url: {
    type: String,
    required: true
  },
  ip: {
    type: String,
    required: true,
    index: true
  },
  userAgent: {
    type: String,
    default: ''
  },
  headers: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  body: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  query: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  statusCode: {
    type: Number,
    default: null
  },
  responseTime: {
    type: Number,
    default: null
  },
  blocked: {
    type: Boolean,
    default: false,
    index: true
  },
  threatLevel: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'low',
    index: true
  },
  vulnerabilities: [{
    type: {
      type: String,
      enum: ['sqlInjection', 'nosqlInjection', 'xss', 'commandInjection', 'pathTraversal']
    },
    pattern: String,
    severity: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical']
    }
  }],
  proxyTarget: {
    type: String,
    default: null
  }
}, {
  timestamps: true
});

// Index for efficient querying
requestLogSchema.index({ timestamp: -1, blocked: 1 });
requestLogSchema.index({ ip: 1, timestamp: -1 });
requestLogSchema.index({ threatLevel: 1, timestamp: -1 });

module.exports = mongoose.model('RequestLog', requestLogSchema);