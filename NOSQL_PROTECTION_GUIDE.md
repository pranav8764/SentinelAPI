# NoSQL Injection Protection Guide

## Overview

NoSQL injection is a security vulnerability where attackers manipulate database queries by injecting MongoDB operators or JavaScript code. This guide shows you how to protect your application.

## What is NoSQL Injection?

### Example Attack

**Normal Login Request:**
```json
{
  "username": "admin",
  "password": "password123"
}
```

**NoSQL Injection Attack:**
```json
{
  "username": { "$ne": null },
  "password": { "$ne": null }
}
```

This bypasses authentication because `{ "$ne": null }` means "not equal to null", which matches all users!

### Dangerous MongoDB Operators

1. **`$where`** - Executes JavaScript code
   ```javascript
   { $where: "this.password == 'admin'" }
   ```

2. **`$eval`** - Evaluates JavaScript expressions
   ```javascript
   { $eval: "db.users.find()" }
   ```

3. **`$regex`** - Can cause ReDoS attacks
   ```javascript
   { username: { $regex: ".*" } }
   ```

4. **`$ne`, `$gt`, `$lt`** - Bypass authentication
   ```javascript
   { password: { $ne: null } }
   ```

## Implementation

### Step 1: Add NoSQL Protection Middleware

I've created `backend/src/middleware/nosqlProtection.js` with comprehensive protection.

### Step 2: Apply Middleware Globally

Update `backend/src/server.js`:

```javascript
import { nosqlProtection } from './middleware/nosqlProtection.js';

// Apply NoSQL protection to all routes
app.use(nosqlProtection({
  sanitizeBody: true,      // Sanitize request body
  sanitizeQuery: true,     // Sanitize query parameters
  sanitizeParams: true,    // Sanitize route parameters
  allowOperators: false,   // Block all MongoDB operators
  strictMode: true,        // Strict sanitization
  blockOnDanger: true      // Block dangerous operators
}));
```

### Step 3: Protect Specific Routes

For routes that need MongoDB operators (like search), use selective protection:

```javascript
import { nosqlProtection } from '../middleware/nosqlProtection.js';

// Allow safe operators for search
router.get('/search', 
  nosqlProtection({ 
    allowOperators: true,  // Allow $gt, $lt, etc.
    strictMode: false      // Less strict for search
  }),
  async (req, res) => {
    // Your search logic
  }
);

// Block all operators for authentication
router.post('/login',
  nosqlProtection({
    allowOperators: false,  // Block all operators
    strictMode: true,       // Strict mode
    blockOnDanger: true     // Block immediately
  }),
  async (req, res) => {
    // Your login logic
  }
);
```

### Step 4: Use Safe Query Builder

Instead of building queries manually, use the SafeQueryBuilder:

```javascript
import { SafeQueryBuilder } from '../middleware/nosqlProtection.js';

// ❌ UNSAFE - Direct user input
const unsafeQuery = {
  username: req.body.username,  // Could be { $ne: null }
  age: req.body.age             // Could be { $gt: 0 }
};

// ✅ SAFE - Using SafeQueryBuilder
const safeQuery = new SafeQueryBuilder()
  .equals('username', req.body.username)
  .gt('age', 18)
  .exists('email', true)
  .build();

const users = await User.find(safeQuery);
```

### Step 5: Validate User Input

Always validate and sanitize user input:

```javascript
import { validateUserInput } from '../middleware/nosqlProtection.js';

router.post('/login', async (req, res) => {
  try {
    // Validate inputs
    const username = validateUserInput(req.body.username, 'string');
    const password = validateUserInput(req.body.password, 'string');
    
    // Safe to use in query
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Success
    res.json({ token: generateToken(user) });
    
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

### Step 6: Sanitize Before Database Operations

For extra protection, sanitize queries before database operations:

```javascript
import { sanitizeMongoQuery } from '../middleware/nosqlProtection.js';

router.get('/users', async (req, res) => {
  try {
    // Build query from user input
    const query = {
      role: req.query.role,
      status: req.query.status
    };
    
    // Sanitize before using
    const safeQuery = sanitizeMongoQuery(query, {
      allowOperators: false,
      strictMode: true
    });
    
    const users = await User.find(safeQuery);
    res.json({ users });
    
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
```

## Real-World Examples

### Example 1: Login Protection

```javascript
import { nosqlProtection, validateUserInput } from '../middleware/nosqlProtection.js';

router.post('/login',
  nosqlProtection({ allowOperators: false, strictMode: true }),
  async (req, res) => {
    try {
      // Validate inputs
      const username = validateUserInput(req.body.username, 'string');
      const password = validateUserInput(req.body.password, 'string');
      
      // Find user - safe because inputs are validated
      const user = await User.findOne({ username });
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Verify password
      const isValid = await bcrypt.compare(password, user.password);
      
      if (!isValid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Generate token
      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
      
      res.json({ token, user: { id: user._id, username: user.username } });
      
    } catch (error) {
      logger.error('Login error:', error);
      res.status(400).json({ error: 'Login failed' });
    }
  }
);
```

### Example 2: Search with Filters

```javascript
import { SafeQueryBuilder } from '../middleware/nosqlProtection.js';

router.get('/search',
  nosqlProtection({ allowOperators: true, strictMode: false }),
  async (req, res) => {
    try {
      const { keyword, minPrice, maxPrice, category } = req.query;
      
      // Build safe query
      const queryBuilder = new SafeQueryBuilder();
      
      if (keyword) {
        queryBuilder.regex('name', keyword, 'i');
      }
      
      if (minPrice) {
        queryBuilder.gt('price', Number(minPrice));
      }
      
      if (maxPrice) {
        queryBuilder.lt('price', Number(maxPrice));
      }
      
      if (category) {
        queryBuilder.equals('category', category);
      }
      
      const query = queryBuilder.build();
      const products = await Product.find(query);
      
      res.json({ products });
      
    } catch (error) {
      logger.error('Search error:', error);
      res.status(400).json({ error: 'Search failed' });
    }
  }
);
```

### Example 3: Update User Profile

```javascript
import { validateUserInput, sanitizeValue } from '../middleware/nosqlProtection.js';

router.put('/profile',
  authenticate,
  nosqlProtection({ allowOperators: false, strictMode: true }),
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Validate each field
      const updates = {};
      
      if (req.body.name) {
        updates.name = validateUserInput(req.body.name, 'string');
      }
      
      if (req.body.email) {
        updates.email = validateUserInput(req.body.email, 'email');
      }
      
      if (req.body.age) {
        updates.age = validateUserInput(req.body.age, 'number');
      }
      
      // Update user - safe because all fields are validated
      const user = await User.findByIdAndUpdate(
        userId,
        { $set: updates },  // Using $set is safe here
        { new: true }
      );
      
      res.json({ user });
      
    } catch (error) {
      logger.error('Update error:', error);
      res.status(400).json({ error: error.message });
    }
  }
);
```

### Example 4: Complex Query with OR/AND

```javascript
import { SafeQueryBuilder } from '../middleware/nosqlProtection.js';

router.get('/users/advanced',
  authenticate,
  requirePermission('view_users'),
  async (req, res) => {
    try {
      const { role, status, search } = req.query;
      
      const queryBuilder = new SafeQueryBuilder();
      
      // Add role filter
      if (role) {
        queryBuilder.equals('role', role);
      }
      
      // Add status filter
      if (status) {
        queryBuilder.equals('status', status);
      }
      
      // Add search with OR condition
      if (search) {
        queryBuilder.or(
          { username: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } }
        );
      }
      
      const query = queryBuilder.build();
      const users = await User.find(query);
      
      res.json({ users });
      
    } catch (error) {
      logger.error('Query error:', error);
      res.status(400).json({ error: 'Query failed' });
    }
  }
);
```

## Configuration Options

### Middleware Options

```javascript
nosqlProtection({
  // Sanitize request body (default: true)
  sanitizeBody: true,
  
  // Sanitize query parameters (default: true)
  sanitizeQuery: true,
  
  // Sanitize route parameters (default: true)
  sanitizeParams: true,
  
  // Allow safe MongoDB operators like $gt, $lt (default: false)
  allowOperators: false,
  
  // Strict mode - removes all $ characters (default: true)
  strictMode: true,
  
  // Block request if dangerous operators detected (default: true)
  blockOnDanger: true
})
```

### When to Use Each Mode

**Strict Mode (allowOperators: false, strictMode: true)**
- Authentication endpoints
- User registration
- Password reset
- Any endpoint where operators should never be used

**Moderate Mode (allowOperators: true, strictMode: false)**
- Search endpoints
- Filter endpoints
- Pagination
- Sorting

**Permissive Mode (allowOperators: true, strictMode: false, blockOnDanger: false)**
- Admin endpoints (with proper authentication)
- Internal APIs
- Trusted sources only

## Testing NoSQL Protection

### Test 1: Basic Operator Injection

```bash
# Attack attempt
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}'

# Expected: 403 Forbidden
# Response: "NOSQL_INJECTION_DETECTED"
```

### Test 2: $where Injection

```bash
# Attack attempt
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$where": "this.password == \"admin\""}, "password": "test"}'

# Expected: 403 Forbidden
# Response: "Dangerous MongoDB operators detected"
```

### Test 3: Regex Injection

```bash
# Attack attempt
curl -X GET "http://localhost:3001/api/users?username[\$regex]=.*"

# Expected: Sanitized or blocked
```

### Test 4: Nested Operator Injection

```bash
# Attack attempt
curl -X POST http://localhost:3001/api/users \
  -H "Content-Type: application/json" \
  -d '{"profile": {"age": {"$gt": 0}}, "role": {"$ne": "user"}}'

# Expected: 403 Forbidden or sanitized
```

## Best Practices

### 1. Always Validate Input Types

```javascript
// ❌ BAD - No validation
const age = req.body.age;
const user = await User.findOne({ age });

// ✅ GOOD - Validate type
const age = validateUserInput(req.body.age, 'number');
const user = await User.findOne({ age });
```

### 2. Use Parameterized Queries

```javascript
// ❌ BAD - String concatenation
const query = `{ username: "${req.body.username}" }`;

// ✅ GOOD - Object-based query
const query = { username: req.body.username };
```

### 3. Whitelist Allowed Fields

```javascript
// ❌ BAD - Accept any field
const updates = req.body;
await User.updateOne({ _id: userId }, updates);

// ✅ GOOD - Whitelist fields
const allowedFields = ['name', 'email', 'age'];
const updates = {};
for (const field of allowedFields) {
  if (req.body[field] !== undefined) {
    updates[field] = validateUserInput(req.body[field]);
  }
}
await User.updateOne({ _id: userId }, { $set: updates });
```

### 4. Use Mongoose Schema Validation

```javascript
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    validate: {
      validator: (v) => /^[a-zA-Z0-9_]+$/.test(v),
      message: 'Username can only contain letters, numbers, and underscores'
    }
  },
  email: {
    type: String,
    required: true,
    validate: {
      validator: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v),
      message: 'Invalid email format'
    }
  },
  age: {
    type: Number,
    min: 0,
    max: 150
  }
});
```

### 5. Limit Query Complexity

```javascript
// Prevent complex queries that could cause DoS
function validateQueryComplexity(query, maxDepth = 3) {
  function getDepth(obj, depth = 0) {
    if (depth > maxDepth) {
      throw new Error('Query too complex');
    }
    
    if (typeof obj !== 'object' || obj === null) {
      return depth;
    }
    
    return Math.max(
      ...Object.values(obj).map(v => getDepth(v, depth + 1))
    );
  }
  
  return getDepth(query);
}
```

### 6. Log Suspicious Activity

```javascript
// Log all blocked attempts
if (blocked) {
  logger.warn('NoSQL injection blocked', {
    ip: req.ip,
    url: req.originalUrl,
    body: req.body,
    query: req.query,
    timestamp: new Date()
  });
  
  // Optionally alert security team
  if (isDangerousOperator(operator)) {
    alertSecurityTeam({
      type: 'nosql_injection',
      severity: 'high',
      details: { ip: req.ip, url: req.originalUrl }
    });
  }
}
```

## Common Mistakes to Avoid

### ❌ Mistake 1: Trusting User Input

```javascript
// NEVER do this
const user = await User.findOne(req.body);
```

### ❌ Mistake 2: Using eval() or Function()

```javascript
// NEVER do this
const result = eval(req.body.code);
const fn = new Function(req.body.code);
```

### ❌ Mistake 3: Allowing $where in Production

```javascript
// NEVER allow this
const users = await User.find({ $where: req.body.condition });
```

### ❌ Mistake 4: Not Validating ObjectIds

```javascript
// BAD - Could cause errors
const user = await User.findById(req.params.id);

// GOOD - Validate first
const id = validateUserInput(req.params.id, 'objectId');
const user = await User.findById(id);
```

## Monitoring and Alerting

### Set Up Alerts

```javascript
import { nosqlProtection } from './middleware/nosqlProtection.js';

app.use(nosqlProtection({
  blockOnDanger: true,
  onBlock: (req, threats) => {
    // Send alert
    alertSecurityTeam({
      type: 'nosql_injection_blocked',
      ip: req.ip,
      url: req.originalUrl,
      threats: threats.length,
      timestamp: new Date()
    });
    
    // Log to security log
    securityLogger.critical('NoSQL injection blocked', {
      ip: req.ip,
      threats
    });
  }
}));
```

### Monitor Patterns

```javascript
// Track blocked attempts
const blockedAttempts = new Map();

function trackBlockedAttempt(ip) {
  const count = blockedAttempts.get(ip) || 0;
  blockedAttempts.set(ip, count + 1);
  
  // Ban IP after 5 attempts
  if (count + 1 >= 5) {
    banIP(ip);
    alertSecurityTeam({ type: 'ip_banned', ip });
  }
}
```

## Summary

### Key Takeaways

1. ✅ **Always sanitize user input** before using in queries
2. ✅ **Use SafeQueryBuilder** for complex queries
3. ✅ **Validate input types** (string, number, email, etc.)
4. ✅ **Block dangerous operators** ($where, $eval, $function)
5. ✅ **Use strict mode** for authentication endpoints
6. ✅ **Whitelist allowed fields** for updates
7. ✅ **Log suspicious activity** for monitoring
8. ✅ **Test your protection** regularly

### Protection Layers

1. **Middleware Layer** - nosqlProtection middleware
2. **Validation Layer** - validateUserInput function
3. **Query Layer** - SafeQueryBuilder class
4. **Schema Layer** - Mongoose validation
5. **Monitoring Layer** - Logging and alerting

With these protections in place, your application will be secure against NoSQL injection attacks! 🛡️
