# Security Testing Guide

This document explains how to run comprehensive security tests for the SentinelAPI application.

## Overview

The security testing suite includes tests for:
- **SQL Injection** - Tests for various SQL injection attack patterns
- **NoSQL Injection** - Tests for MongoDB operator injection
- **XSS (Cross-Site Scripting)** - Tests for script injection, event handlers, and encoded payloads
- **Command Injection** - Tests for OS command execution attempts
- **Path Traversal** - Tests for directory traversal attacks
- **Header Injection** - Tests for malicious header values
- **Body Injection** - Tests for malicious JSON payloads
- **Security Headers** - Validates presence of security headers
- **Rate Limiting** - Tests rate limiting functionality
- **Combined Attacks** - Tests multiple attack vectors simultaneously

## Prerequisites

1. **Backend server must be running**
   ```bash
   cd backend
   npm install
   npm start
   ```

2. **MongoDB must be running**
   - Make sure MongoDB is installed and running
   - Default connection: `mongodb://localhost:27017/sentinelapi`

## Running Backend Security Tests

### Method 1: Using npm script (Recommended)

```bash
cd backend
npm run test:security
```

### Method 2: Direct execution

```bash
cd backend
node security-tests.js
```

### Expected Output

The test suite will:
1. Check if the server is running
2. Run all security test suites
3. Display results for each test
4. Show a summary with:
   - Total tests run
   - Tests passed
   - Tests failed
   - Attacks blocked
   - Pass rate and block rate

### Example Output

```
╔════════════════════════════════════════════════════════╗
║     COMPREHENSIVE SECURITY TESTING SUITE              ║
╚════════════════════════════════════════════════════════╝

Testing API: http://localhost:3001

✓ Server is running

=== SQL Injection Tests ===

✓ PASS SQL Injection - UNION SELECT
  Status: 403
  Threat Level: critical
  Attack blocked successfully

✓ PASS SQL Injection - DROP TABLE
  Status: 403
  Threat Level: critical
  Attack blocked successfully

...

╔════════════════════════════════════════════════════════╗
║                    TEST SUMMARY                        ║
╚════════════════════════════════════════════════════════╝

Total Tests:     120
Passed:          118 (98.33%)
Failed:          2
Attacks Blocked: 115 (95.83%)

✓ ALL TESTS PASSED! Security is working correctly.
```

## Running Frontend Security Tests

### Method 1: Using the HTML interface (Recommended)

1. Open `frontend-security-tests.html` in your browser
2. Ensure the API URL is correct (default: `http://localhost:3001`)
3. Click "Run All Tests"
4. View results in real-time
5. Export results as JSON if needed

### Method 2: Using a local server

```bash
# Using Python
python -m http.server 8000

# Using Node.js http-server
npx http-server

# Then open http://localhost:8000/frontend-security-tests.html
```

### Features

- **Real-time results** - See test results as they execute
- **Visual dashboard** - Color-coded status indicators
- **Live logging** - Console-style log output
- **Export functionality** - Download results as JSON
- **Summary statistics** - Total, passed, failed, and blocked counts

## Understanding Test Results

### Status Codes

- **✓ PASS** (Green) - Test passed, security working correctly
- **✗ FAIL** (Red) - Test failed, security issue detected
- **BLOCKED** (Blue) - Attack was successfully blocked
- **PENDING** (Yellow) - Test not yet run

### Threat Levels

- **Critical** - Severe security threat (e.g., SQL injection, command execution)
- **High** - Serious security threat (e.g., XSS, path traversal)
- **Medium** - Moderate security concern
- **Low** - Minor security issue

### HTTP Status Codes

- **403** - Request blocked by security policy (expected for attacks)
- **200** - Request allowed (unexpected for attacks)
- **429** - Rate limit exceeded (expected for rate limit tests)
- **500** - Server error (investigate)

## Security Features Tested

### 1. Input Sanitization
- Removes dangerous characters and patterns
- Encodes HTML entities
- Strips malicious tags and attributes

### 2. Pattern Detection
- Regex-based vulnerability detection
- Multiple attack pattern databases
- Severity classification

### 3. Request Blocking
- Automatic blocking of high-threat requests
- Configurable threat level thresholds
- Real-time threat notifications

### 4. Security Headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Content-Security-Policy
- Referrer-Policy
- Strict-Transport-Security (HTTPS only)

### 5. Rate Limiting
- Per-IP request limiting
- Configurable time windows
- Automatic rate limit enforcement

### 6. Request Logging
- All requests logged to MongoDB
- Threat level classification
- Vulnerability details captured

## Troubleshooting

### Server Not Running

```
✗ Server is not running!
Please start the backend server first: npm start
```

**Solution:** Start the backend server:
```bash
cd backend
npm start
```

### MongoDB Connection Error

```
Error: Failed to connect to MongoDB
```

**Solution:** Ensure MongoDB is running:
```bash
# Windows
net start MongoDB

# macOS/Linux
sudo systemctl start mongod
```

### Tests Failing

If tests are failing unexpectedly:

1. **Check security configuration**
   ```bash
   # View current config
   curl http://localhost:3001/api/admin/config
   ```

2. **Check logs**
   ```bash
   # View backend logs
   tail -f backend/logs/all.log
   ```

3. **Verify middleware is enabled**
   - Check `backend/src/server.js`
   - Ensure `securityMiddleware.middleware()` is applied

4. **Check threat level threshold**
   - Default: blocks `high` and `critical` threats
   - Adjust in security configuration if needed

### Rate Limiting Tests Failing

If rate limiting tests don't work:

1. **Check rate limit configuration**
   ```bash
   curl http://localhost:3001/api/admin/rate-limit
   ```

2. **Adjust rate limits**
   ```bash
   curl -X PUT http://localhost:3001/api/admin/rate-limit \
     -H "Content-Type: application/json" \
     -d '{"windowMs": 60000, "max": 100}'
   ```

## Customizing Tests

### Adding New Test Cases

Edit `backend/security-tests.js`:

```javascript
const customPayloads = [
  { name: 'My Custom Test', payload: 'malicious-payload' }
];

// Add to existing test suite or create new one
async function testCustomAttacks() {
  console.log(chalk.blue('\n=== Custom Attack Tests ===\n'));
  
  for (const test of customPayloads) {
    // Test implementation
  }
}
```

### Modifying Threat Levels

Edit `backend/src/config/securityPatterns.js`:

```javascript
export const securityPatterns = {
  customAttack: [
    {
      pattern: /your-pattern-here/gi,
      severity: 'critical', // low, medium, high, critical
      description: 'Your attack description'
    }
  ]
};
```

### Adjusting Security Configuration

```javascript
// In backend/src/middleware/security.js
this.config = {
  enabled: true,
  logAllRequests: true,
  blockThreats: true,
  minThreatLevel: 'high', // Change to 'medium' or 'critical'
  sanitizeInput: true,
  scanResponses: true
};
```

## Best Practices

1. **Run tests regularly** - After any security-related changes
2. **Review failed tests** - Investigate why attacks weren't blocked
3. **Check logs** - Review `backend/logs/` for detailed information
4. **Monitor in production** - Use the dashboard to monitor real-time threats
5. **Update patterns** - Keep security patterns up-to-date
6. **Test new features** - Add security tests for new endpoints

## Continuous Integration

### GitHub Actions Example

```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    
    services:
      mongodb:
        image: mongo:latest
        ports:
          - 27017:27017
    
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: |
          cd backend
          npm install
      
      - name: Start server
        run: |
          cd backend
          npm start &
          sleep 10
      
      - name: Run security tests
        run: |
          cd backend
          npm run test:security
```

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Security Headers](https://securityheaders.com/)
- [Content Security Policy](https://content-security-policy.com/)

## Support

If you encounter issues or have questions:

1. Check the logs in `backend/logs/`
2. Review the security configuration
3. Ensure all dependencies are installed
4. Verify MongoDB is running
5. Check that the server is accessible

## License

This security testing suite is part of the SentinelAPI project.
