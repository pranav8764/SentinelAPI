# Quick Start - Security Testing

This guide will help you quickly run all security tests for the SentinelAPI application.

## Prerequisites

1. **Node.js** installed (v18 or higher)
2. **MongoDB** installed and running
3. **Backend dependencies** installed

## Step-by-Step Guide

### Step 1: Start MongoDB

**Windows:**
```bash
net start MongoDB
```

**macOS/Linux:**
```bash
sudo systemctl start mongod
# or
brew services start mongodb-community
```

### Step 2: Install Dependencies (First Time Only)

```bash
# Install backend dependencies
cd backend
npm install

# Install frontend dependencies (optional)
cd ../frontend
npm install
```

### Step 3: Start the Backend Server

Open a terminal and run:

```bash
cd backend
npm start
```

You should see:
```
Server running on port 3001
Environment: development
```

**Keep this terminal open!**

### Step 4: Run Security Tests

#### Option A: Using the Batch Script (Windows)

Double-click `run-security-tests.bat` or run:

```bash
run-security-tests.bat
```

#### Option B: Manual Execution

Open a **new terminal** (keep the server running) and run:

```bash
cd backend
npm run test:security
```

#### Option C: Frontend HTML Tests

1. Open `frontend-security-tests.html` in your browser
2. Verify the API URL is `http://localhost:3001`
3. Click **"Run All Tests"**
4. Watch the results in real-time

### Step 5: Review Results

The tests will output:
- ✓ **PASS** - Security working correctly
- ✗ **FAIL** - Security issue detected
- **Threat Level** - Severity of detected threats
- **Summary** - Total, passed, failed, and blocked counts

## Expected Results

### Successful Test Run

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

... (more tests)

╔════════════════════════════════════════════════════════╗
║                    TEST SUMMARY                        ║
╚════════════════════════════════════════════════════════╝

Total Tests:     120+
Passed:          118+ (98%+)
Failed:          0-2
Attacks Blocked: 115+ (95%+)

✓ ALL TESTS PASSED! Security is working correctly.
```

## What Gets Tested?

### 1. SQL Injection (8 tests)
- UNION SELECT attacks
- DROP TABLE attempts
- Boolean-based blind injection
- Time-based blind injection
- Comment injection
- String concatenation
- Hex encoding

### 2. NoSQL Injection (7 tests)
- MongoDB operator injection ($ne, $gt, $where)
- Logical operators ($or, $and)
- Code execution attempts ($eval)
- JavaScript injection

### 3. XSS - Cross-Site Scripting (24 tests)
- Script tags
- Event handlers (onclick, onerror, onload)
- JavaScript protocols
- Iframe/Object/Embed tags
- CSS expressions
- Base64/Unicode/Hex encoding
- Template injection
- Document.cookie access
- Eval functions

### 4. Command Injection (8 tests)
- Pipe commands
- Command chaining (&&, ;)
- Command substitution $()
- Backtick execution
- Windows commands

### 5. Path Traversal (8 tests)
- Directory traversal (../)
- Windows paths (..\\)
- URL encoding
- Absolute paths
- Null byte injection

### 6. Header Injection (4 tests)
- XSS in User-Agent
- XSS in Referer
- CRLF injection
- SQL in custom headers

### 7. Body Injection (6 tests)
- XSS in JSON
- SQL in JSON
- NoSQL in JSON
- Command injection in JSON
- Path traversal in JSON
- Nested attacks

### 8. Security Headers (5 tests)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Content-Security-Policy
- Referrer-Policy

### 9. Rate Limiting (1 test)
- Rapid request flooding (150 requests)

### 10. Combined Attacks (3 tests)
- SQL + XSS
- NoSQL + Command Injection
- Path Traversal + XSS

## Troubleshooting

### Problem: "Server is not running"

**Solution:**
```bash
cd backend
npm start
```

Wait for "Server running on port 3001" message.

### Problem: "Cannot connect to MongoDB"

**Solution:**
```bash
# Windows
net start MongoDB

# macOS
brew services start mongodb-community

# Linux
sudo systemctl start mongod
```

### Problem: Tests are failing

**Check:**
1. Is the server running? `curl http://localhost:3001/health`
2. Are security features enabled? Check `backend/src/server.js`
3. Review logs: `backend/logs/all.log`

### Problem: "Module not found: chalk"

**Solution:**
```bash
cd backend
npm install
```

## Viewing Logs

### Real-time Logs

```bash
# Windows
type backend\logs\all.log

# macOS/Linux
tail -f backend/logs/all.log
```

### Error Logs Only

```bash
# Windows
type backend\logs\error.log

# macOS/Linux
tail -f backend/logs/error.log
```

## Testing Individual Attack Types

You can test specific attack types by modifying the test file:

```javascript
// In backend/security-tests.js
// Comment out tests you don't want to run

async function runAllTests() {
  // await testSQLInjection();
  // await testNoSQLInjection();
  await testXSS(); // Only run XSS tests
  // await testCommandInjection();
  // ... etc
}
```

## Next Steps

After running tests:

1. **Review the Dashboard**
   - Start frontend: `cd frontend && npm run dev`
   - Open: `http://localhost:5174`
   - Login with admin credentials
   - View logs and statistics

2. **Check Request Logs**
   - Navigate to `/logs` in the dashboard
   - Filter by threat level
   - Review blocked requests

3. **Adjust Security Settings**
   - Navigate to `/settings`
   - Modify rate limits
   - Update security configuration

4. **Monitor Real-time**
   - Dashboard shows live threat notifications
   - WebSocket updates for new threats
   - Real-time statistics

## Automated Testing

### Run on Every Commit

Add to `.git/hooks/pre-commit`:

```bash
#!/bin/sh
echo "Running security tests..."
cd backend
npm run test:security
if [ $? -ne 0 ]; then
    echo "Security tests failed! Commit aborted."
    exit 1
fi
```

### Scheduled Testing

**Windows Task Scheduler:**
- Create task to run `run-security-tests.bat` daily

**Linux Cron:**
```bash
# Run daily at 2 AM
0 2 * * * cd /path/to/project && ./run-security-tests.sh
```

## Performance Notes

- **Test Duration:** ~30-60 seconds for all tests
- **Server Load:** Moderate (150+ requests)
- **Database Impact:** Minimal (read-only operations)
- **Network:** Local only (no external requests)

## Security Best Practices

1. ✅ Run tests before deploying
2. ✅ Review failed tests immediately
3. ✅ Keep security patterns updated
4. ✅ Monitor logs regularly
5. ✅ Test new endpoints
6. ✅ Document security changes
7. ✅ Train team on security

## Support

Need help? Check:
- `SECURITY_TESTING.md` - Detailed testing guide
- `backend/logs/` - Application logs
- `README.md` - Project documentation

## Summary

```bash
# Quick command reference
cd backend
npm start                    # Start server
npm run test:security        # Run tests
npm run dev                  # Development mode

# Or use the batch script
run-security-tests.bat       # Windows
```

That's it! You're now ready to test the security of your SentinelAPI application. 🛡️
