import mongoose from 'mongoose';
import crypto from 'crypto';

const apiKeySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  key: {
    type: String,
    required: true,
    unique: true
  },
  hashedKey: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'AdminUser',
    required: true
  },
  permissions: [{
    type: String,
    enum: ['read', 'write', 'admin', 'scan', 'test']
  }],
  isActive: {
    type: Boolean,
    default: true
  },
  expiresAt: {
    type: Date,
    default: null
  },
  lastUsed: {
    type: Date,
    default: null
  },
  usageCount: {
    type: Number,
    default: 0
  },
  rateLimit: {
    requestsPerMinute: {
      type: Number,
      default: 60
    },
    requestsPerHour: {
      type: Number,
      default: 1000
    }
  },
  metadata: {
    type: Map,
    of: String
  }
}, {
  timestamps: true
});

// Index for faster lookups
apiKeySchema.index({ key: 1 });
apiKeySchema.index({ userId: 1 });
apiKeySchema.index({ expiresAt: 1 });

// Virtual for checking if key is expired
apiKeySchema.virtual('isExpired').get(function() {
  return this.expiresAt && this.expiresAt < Date.now();
});

// Pre-save middleware to hash the key
apiKeySchema.pre('save', async function(next) {
  if (this.isModified('key')) {
    this.hashedKey = crypto
      .createHash('sha256')
      .update(this.key)
      .digest('hex');
  }
  next();
});

// Method to verify key
apiKeySchema.methods.verifyKey = function(candidateKey) {
  const hashedCandidate = crypto
    .createHash('sha256')
    .update(candidateKey)
    .digest('hex');
  return this.hashedKey === hashedCandidate;
};

// Method to update usage
apiKeySchema.methods.recordUsage = function() {
  this.lastUsed = Date.now();
  this.usageCount += 1;
  return this.save();
};

// Static method to generate a new API key
apiKeySchema.statics.generateKey = function() {
  return 'sk_' + crypto.randomBytes(32).toString('hex');
};

export default mongoose.model('ApiKey', apiKeySchema);
