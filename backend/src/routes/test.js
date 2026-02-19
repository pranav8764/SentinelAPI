import express from 'express';

const router = express.Router();

/**
 * Test endpoint - Intentionally vulnerable for testing the scanner
 * DO NOT USE IN PRODUCTION
 */

// Vulnerable endpoint with multiple issues
router.get('/vulnerable', (req, res) => {
  const { id, search } = req.query;
  
  // Intentionally exposing sensitive data for testing
  res.json({
    message: `Searching for: ${search}`, // XSS vulnerable
    userId: id,
    // Sensitive data exposure examples
    apiKey: 'sk_test_1234567890abcdefghijklmnop',
    password: 'admin123',
    email: 'user@example.com',
    creditCard: '4532-1234-5678-9010',
    ssn: '123-45-6789',
    jwtToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    awsKey: 'AKIAIOSFODNN7EXAMPLE',
    dbConnection: 'mongodb://admin:password@localhost:27017/mydb'
  });
});

// Endpoint with missing security headers
router.get('/no-headers', (req, res) => {
  // Remove security headers
  res.removeHeader('X-Content-Type-Options');
  res.removeHeader('X-Frame-Options');
  res.removeHeader('Strict-Transport-Security');
  
  res.json({ message: 'This endpoint has no security headers' });
});

// Endpoint with CORS issues
router.options('/cors-test', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.send();
});

router.get('/cors-test', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.json({ message: 'CORS misconfigured endpoint' });
});

// Endpoint without authentication
router.get('/no-auth', (req, res) => {
  res.json({
    message: 'This endpoint should require authentication but does not',
    sensitiveData: 'Anyone can access this'
  });
});

// Endpoint with verbose errors
router.get('/error', (req, res) => {
  try {
    throw new Error('Database connection failed at /var/www/app/db.js:42');
  } catch (error) {
    res.status(500).json({
      error: error.message,
      stack: error.stack,
      details: {
        file: '/var/www/app/db.js',
        line: 42,
        function: 'connectToDatabase'
      }
    });
  }
});

// Secure endpoint for comparison
router.get('/secure', (req, res) => {
  res.header('X-Content-Type-Options', 'nosniff');
  res.header('X-Frame-Options', 'DENY');
  res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.header('Content-Security-Policy', "default-src 'self'");
  res.header('X-XSS-Protection', '1; mode=block');
  
  res.json({
    message: 'This is a secure endpoint',
    data: 'No sensitive information exposed'
  });
});

export default router;
