/**
 * NoSQL Injection Protection Middleware
 * Protects against MongoDB operator injection and query manipulation
 */

import logger from '../utils/logger.js';

// Dangerous MongoDB operators that should be blocked or sanitized
const DANGEROUS_OPERATORS = [
  '$where',      // JavaScript execution
  '$eval',       // Code evaluation
  '$function',   // Server-side JavaScript
  '$accumulator',// Custom accumulator functions
  '$regex',      // Regex injection (can be dangerous)
];

// Query operators that need validation
const QUERY_OPERATORS = [
  '$ne', '$gt', '$gte', '$lt', '$lte',
  '$in', '$nin', '$exists', '$type',
  '$or', '$and', '$not', '$nor',
  '$all', '$elemMatch', '$size',
  '$mod', '$text', '$search'
];

// Update operators
const UPDATE_OPERATORS = [
  '$set', '$unset', '$inc', '$mul',
  '$rename', '$setOnInsert', '$push',
  '$pull', '$addToSet', '$pop'
];

/**
 * Check if a value contains MongoDB operators
 */
function containsOperators(value) {
  if (typeof value === 'string') {
    // Check for operator strings
    return /\$\w+/.test(value);
  }
  
  if (typeof value === 'object' && value !== null) {
    // Check object keys for operators
    return Object.keys(value).some(key => key.startsWith('$'));
  }
  
  return false;
}

/**
 * Check if an operator is dangerous
 */
function isDangerousOperator(operator) {
  return DANGEROUS_OPERATORS.includes(operator);
}

/**
 * Sanitize a single value by removing or escaping operators
 */
function sanitizeValue(value, options = {}) {
  const { allowOperators = false, strictMode = true } = options;
  
  // Handle null/undefined
  if (value === null || value === undefined) {
    return value;
  }
  
  // Handle strings
  if (typeof value === 'string') {
    if (strictMode) {
      // Remove all operator-like strings
      return value.replace(/\$\w+/g, '');
    } else {
      // Just escape the $ character
      return value.replace(/\$/g, '\\$');
    }
  }
  
  // Handle arrays
  if (Array.isArray(value)) {
    return value.map(item => sanitizeValue(item, options));
  }
  
  // Handle objects
  if (typeof value === 'object') {
    const sanitized = {};
    
    for (const [key, val] of Object.entries(value)) {
      // Check if key is an operator
      if (key.startsWith('$')) {
        // Block dangerous operators
        if (isDangerousOperator(key)) {
          logger.warn('Dangerous MongoDB operator blocked', { operator: key });
          continue; // Skip this key
        }
        
        // Allow safe operators if enabled
        if (allowOperators && (QUERY_OPERATORS.includes(key) || UPDATE_OPERATORS.includes(key))) {
          sanitized[key] = sanitizeValue(val, options);
        } else if (!allowOperators) {
          // Remove the $ prefix to neutralize the operator
          sanitized[key.substring(1)] = sanitizeValue(val, options);
          logger.info('MongoDB operator neutralized', { original: key, sanitized: key.substring(1) });
        }
      } else {
        // Regular key - sanitize the value
        sanitized[key] = sanitizeValue(val, options);
      }
    }
    
    return sanitized;
  }
  
  // Return primitive values as-is
  return value;
}

/**
 * Validate MongoDB query for dangerous patterns
 */
function validateQuery(query) {
  const issues = [];
  
  function checkValue(value, path = '') {
    if (typeof value === 'string') {
      // Check for JavaScript code patterns
      if (/function\s*\(/.test(value) || /=>\s*{/.test(value)) {
        issues.push({
          type: 'javascript_code',
          path,
          description: 'JavaScript code detected in query'
        });
      }
      
      // Check for eval patterns
      if (/eval\s*\(/.test(value)) {
        issues.push({
          type: 'eval_detected',
          path,
          description: 'Eval function detected in query'
        });
      }
    }
    
    if (typeof value === 'object' && value !== null) {
      for (const [key, val] of Object.entries(value)) {
        const currentPath = path ? `${path}.${key}` : key;
        
        // Check for dangerous operators
        if (isDangerousOperator(key)) {
          issues.push({
            type: 'dangerous_operator',
            path: currentPath,
            operator: key,
            description: `Dangerous operator ${key} detected`
          });
        }
        
        // Recursively check nested values
        checkValue(val, currentPath);
      }
    }
    
    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        checkValue(item, `${path}[${index}]`);
      });
    }
  }
  
  checkValue(query);
  return issues;
}

/**
 * NoSQL Protection Middleware
 */
export function nosqlProtection(options = {}) {
  const {
    sanitizeBody = true,
    sanitizeQuery = true,
    sanitizeParams = true,
    allowOperators = false,
    strictMode = true,
    blockOnDanger = true
  } = options;
  
  return (req, res, next) => {
    try {
      let blocked = false;
      const threats = [];
      
      // Sanitize request body
      if (sanitizeBody && req.body && typeof req.body === 'object') {
        const issues = validateQuery(req.body);
        
        if (issues.length > 0) {
          threats.push(...issues);
          
          if (blockOnDanger && issues.some(i => i.type === 'dangerous_operator' || i.type === 'javascript_code')) {
            blocked = true;
          }
        }
        
        if (!blocked) {
          req.body = sanitizeValue(req.body, { allowOperators, strictMode });
          req.sanitizedBody = true;
        }
      }
      
      // Sanitize query parameters
      if (sanitizeQuery && req.query && typeof req.query === 'object') {
        const issues = validateQuery(req.query);
        
        if (issues.length > 0) {
          threats.push(...issues);
          
          if (blockOnDanger && issues.some(i => i.type === 'dangerous_operator' || i.type === 'javascript_code')) {
            blocked = true;
          }
        }
        
        if (!blocked) {
          req.query = sanitizeValue(req.query, { allowOperators, strictMode });
          req.sanitizedQuery = true;
        }
      }
      
      // Sanitize route parameters
      if (sanitizeParams && req.params && typeof req.params === 'object') {
        req.params = sanitizeValue(req.params, { allowOperators: false, strictMode });
        req.sanitizedParams = true;
      }
      
      // Block request if dangerous patterns detected
      if (blocked) {
        logger.warn('NoSQL injection attempt blocked', {
          ip: req.ip,
          url: req.originalUrl,
          method: req.method,
          threats: threats.map(t => ({ type: t.type, path: t.path }))
        });
        
        return res.status(403).json({
          error: 'Request blocked by security policy',
          code: 'NOSQL_INJECTION_DETECTED',
          message: 'Dangerous MongoDB operators detected',
          timestamp: new Date().toISOString()
        });
      }
      
      // Log threats but allow request
      if (threats.length > 0) {
        logger.info('NoSQL injection patterns detected and sanitized', {
          ip: req.ip,
          url: req.originalUrl,
          threats: threats.length
        });
      }
      
      next();
      
    } catch (error) {
      logger.error('Error in NoSQL protection middleware:', error);
      next(); // Continue on error to avoid breaking the app
    }
  };
}

/**
 * Sanitize MongoDB query object before database operations
 * Use this in your route handlers for extra protection
 */
export function sanitizeMongoQuery(query, options = {}) {
  const { allowOperators = true, strictMode = false } = options;
  
  // Validate first
  const issues = validateQuery(query);
  
  if (issues.some(i => i.type === 'dangerous_operator' || i.type === 'javascript_code')) {
    throw new Error('Dangerous MongoDB operators detected in query');
  }
  
  // Sanitize
  return sanitizeValue(query, { allowOperators, strictMode });
}

/**
 * Safe query builder - ensures queries are constructed safely
 */
export class SafeQueryBuilder {
  constructor() {
    this.query = {};
  }
  
  // Equality check
  equals(field, value) {
    if (typeof field !== 'string' || field.startsWith('$')) {
      throw new Error('Invalid field name');
    }
    this.query[field] = sanitizeValue(value, { allowOperators: false, strictMode: true });
    return this;
  }
  
  // Greater than
  gt(field, value) {
    if (typeof field !== 'string' || field.startsWith('$')) {
      throw new Error('Invalid field name');
    }
    this.query[field] = { $gt: sanitizeValue(value, { allowOperators: false, strictMode: true }) };
    return this;
  }
  
  // Less than
  lt(field, value) {
    if (typeof field !== 'string' || field.startsWith('$')) {
      throw new Error('Invalid field name');
    }
    this.query[field] = { $lt: sanitizeValue(value, { allowOperators: false, strictMode: true }) };
    return this;
  }
  
  // In array
  in(field, values) {
    if (typeof field !== 'string' || field.startsWith('$')) {
      throw new Error('Invalid field name');
    }
    if (!Array.isArray(values)) {
      throw new Error('Values must be an array');
    }
    this.query[field] = { $in: values.map(v => sanitizeValue(v, { allowOperators: false, strictMode: true })) };
    return this;
  }
  
  // Exists check
  exists(field, exists = true) {
    if (typeof field !== 'string' || field.startsWith('$')) {
      throw new Error('Invalid field name');
    }
    this.query[field] = { $exists: Boolean(exists) };
    return this;
  }
  
  // Regex (safe version)
  regex(field, pattern, options = '') {
    if (typeof field !== 'string' || field.startsWith('$')) {
      throw new Error('Invalid field name');
    }
    // Escape special regex characters to prevent ReDoS
    const escaped = String(pattern).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    this.query[field] = { $regex: escaped, $options: options };
    return this;
  }
  
  // OR condition
  or(...conditions) {
    const sanitized = conditions.map(c => sanitizeValue(c, { allowOperators: true, strictMode: false }));
    this.query.$or = sanitized;
    return this;
  }
  
  // AND condition
  and(...conditions) {
    const sanitized = conditions.map(c => sanitizeValue(c, { allowOperators: true, strictMode: false }));
    this.query.$and = sanitized;
    return this;
  }
  
  // Build the final query
  build() {
    return this.query;
  }
}

/**
 * Validate user input before using in queries
 */
export function validateUserInput(input, type = 'string') {
  switch (type) {
    case 'string':
      if (typeof input !== 'string') {
        throw new Error('Expected string input');
      }
      // Remove operators
      return input.replace(/\$/g, '');
      
    case 'number':
      const num = Number(input);
      if (isNaN(num)) {
        throw new Error('Expected numeric input');
      }
      return num;
      
    case 'boolean':
      if (typeof input === 'boolean') return input;
      if (input === 'true') return true;
      if (input === 'false') return false;
      throw new Error('Expected boolean input');
      
    case 'objectId':
      // Validate MongoDB ObjectId format
      if (!/^[0-9a-fA-F]{24}$/.test(String(input))) {
        throw new Error('Invalid ObjectId format');
      }
      return String(input);
      
    case 'email':
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(String(input))) {
        throw new Error('Invalid email format');
      }
      return String(input).toLowerCase();
      
    default:
      return sanitizeValue(input, { allowOperators: false, strictMode: true });
  }
}

export default {
  nosqlProtection,
  sanitizeMongoQuery,
  SafeQueryBuilder,
  validateUserInput,
  sanitizeValue,
  validateQuery
};
