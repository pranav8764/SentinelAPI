import mongoose from 'mongoose';

const scanResultSchema = new mongoose.Schema({
  url: {
    type: String,
    required: true
  },
  method: {
    type: String,
    required: true,
    enum: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AdminUser',
    required: true
  },
  vulnerabilities: [{
    type: {
      type: String,
      required: true
    },
    severity: {
      type: String,
      enum: ['critical', 'high', 'medium', 'low'],
      required: true
    },
    description: String,
    evidence: String,
    remediation: String,
    cwe: String,
    owasp: String
  }],
  tests: [{
    name: String,
    category: String,
    passed: Boolean,
    message: String,
    payload: String
  }],
  summary: {
    total: { type: Number, default: 0 },
    critical: { type: Number, default: 0 },
    high: { type: Number, default: 0 },
    medium: { type: Number, default: 0 },
    low: { type: Number, default: 0 }
  },
  responseTime: {
    type: Number,
    default: 0
  },
  statusCode: {
    type: Number
  },
  passed: {
    type: Number,
    default: 0
  },
  failed: {
    type: Number,
    default: 0
  },
  error: String
}, {
  timestamps: true
});

// Index for faster queries
scanResultSchema.index({ userId: 1, createdAt: -1 });
scanResultSchema.index({ url: 1 });

export default mongoose.model('ScanResult', scanResultSchema);
