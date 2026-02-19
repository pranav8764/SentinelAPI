import mongoose from 'mongoose';

const securityConfigSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  enabled: {
    type: Boolean,
    default: true
  },
  sqlInjection: {
    enabled: {
      type: Boolean,
      default: true
    },
    patterns: [{
      pattern: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'high'
      }
    }],
    action: {
      type: String,
      enum: ['block', 'log', 'warn'],
      default: 'block'
    }
  },
  nosqlInjection: {
    enabled: {
      type: Boolean,
      default: true
    },
    operators: [{
      operator: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'high'
      }
    }],
    action: {
      type: String,
      enum: ['block', 'log', 'warn'],
      default: 'block'
    }
  },
  xss: {
    enabled: {
      type: Boolean,
      default: true
    },
    patterns: [{
      pattern: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'high'
      }
    }],
    action: {
      type: String,
      enum: ['block', 'log', 'warn'],
      default: 'block'
    }
  },
  commandInjection: {
    enabled: {
      type: Boolean,
      default: true
    },
    patterns: [{
      pattern: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical'],
        default: 'critical'
      }
    }],
    action: {
      type: String,
      enum: ['block', 'log', 'warn'],
      default: 'block'
    }
  },
  rateLimit: {
    enabled: {
      type: Boolean,
      default: true
    },
    windowMs: {
      type: Number,
      default: 900000 // 15 minutes
    },
    max: {
      type: Number,
      default: 100
    },
    maxRequests: {
      type: Number,
      default: 100
    },
    skipSuccessfulRequests: {
      type: Boolean,
      default: false
    }
  },
  whitelist: [{
    ip: String,
    description: String,
    enabled: {
      type: Boolean,
      default: true
    }
  }],
  blacklist: [{
    ip: String,
    description: String,
    enabled: {
      type: Boolean,
      default: true
    }
  }]
}, {
  timestamps: true
});

export default mongoose.model('SecurityConfig', securityConfigSchema);
