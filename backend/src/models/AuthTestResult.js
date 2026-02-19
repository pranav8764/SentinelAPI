import mongoose from 'mongoose';

const authTestResultSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AdminUser',
    required: true
  },
  testType: {
    type: String,
    enum: ['oauth', 'apikey', 'session', 'jwt'],
    required: true
  },
  success: {
    type: Boolean,
    required: true
  },
  responseTime: {
    type: Number, // in milliseconds
    required: true
  },
  statusCode: {
    type: Number
  },
  targetUrl: {
    type: String
  },
  config: {
    type: mongoose.Schema.Types.Mixed
  },
  result: {
    type: mongoose.Schema.Types.Mixed
  },
  error: {
    type: mongoose.Schema.Types.Mixed
  },
  metadata: {
    userAgent: String,
    ipAddress: String,
    timestamp: Date
  }
}, {
  timestamps: true
});

// Indexes for faster queries
authTestResultSchema.index({ userId: 1, createdAt: -1 });
authTestResultSchema.index({ testType: 1 });
authTestResultSchema.index({ success: 1 });

export default mongoose.model('AuthTestResult', authTestResultSchema);
