import axios from 'axios';

const BASE_URL = 'http://localhost:3001';
const API_URL = `${BASE_URL}/api`;

console.log('🧪 Testing SentinelAPI Backend\n');
console.log('=' .repeat(50));

// Test 1: Root endpoint
async function testRoot() {
  try {
    console.log('\n✅ Test 1: Root Endpoint (GET /)');
    const response = await axios.get(BASE_URL);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return true;
  } catch (error) {
    console.log('❌ Failed:', error.message);
    return false;
  }
}

// Test 2: Health check
async function testHealth() {
  try {
    console.log('\n✅ Test 2: Health Check (GET /health)');
    const response = await axios.get(`${BASE_URL}/health`);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return true;
  } catch (error) {
    console.log('❌ Failed:', error.message);
    return false;
  }
}

// Test 3: Register a new user
async function testRegister() {
  try {
    console.log('\n✅ Test 3: Register User (POST /api/auth/register)');
    const userData = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'Test123456',
      role: 'admin'
    };
    const response = await axios.post(`${API_URL}/auth/register`, userData);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return response.data.token;
  } catch (error) {
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Error:', JSON.stringify(error.response.data, null, 2));
      // If user already exists, try to login instead
      if (error.response.data.code === 'USER_EXISTS') {
        console.log('ℹ️  User already exists, will try login...');
        return null;
      }
    } else {
      console.log('❌ Failed:', error.message);
    }
    return null;
  }
}

// Test 4: Login
async function testLogin() {
  try {
    console.log('\n✅ Test 4: Login (POST /api/auth/login)');
    const credentials = {
      username: 'testuser',
      password: 'Test123456'
    };
    const response = await axios.post(`${API_URL}/auth/login`, credentials);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return response.data.token;
  } catch (error) {
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Error:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.log('❌ Failed:', error.message);
    }
    return null;
  }
}

// Test 5: Get current user (requires auth)
async function testGetMe(token) {
  try {
    console.log('\n✅ Test 5: Get Current User (GET /api/auth/me)');
    const response = await axios.get(`${API_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return true;
  } catch (error) {
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Error:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.log('❌ Failed:', error.message);
    }
    return false;
  }
}

// Test 6: Get admin stats (requires auth)
async function testAdminStats(token) {
  try {
    console.log('\n✅ Test 6: Get Admin Stats (GET /api/admin/stats)');
    const response = await axios.get(`${API_URL}/admin/stats`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return true;
  } catch (error) {
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Error:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.log('❌ Failed:', error.message);
    }
    return false;
  }
}

// Test 7: Get request logs (requires auth)
async function testAdminLogs(token) {
  try {
    console.log('\n✅ Test 7: Get Request Logs (GET /api/admin/logs)');
    const response = await axios.get(`${API_URL}/admin/logs?page=1&limit=5`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    console.log('Status:', response.status);
    console.log('Logs count:', response.data.logs.length);
    console.log('Pagination:', JSON.stringify(response.data.pagination, null, 2));
    return true;
  } catch (error) {
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Error:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.log('❌ Failed:', error.message);
    }
    return false;
  }
}

// Test 8: Proxy health check
async function testProxyHealth() {
  try {
    console.log('\n✅ Test 8: Proxy Health Check (GET /api/proxy/health)');
    const response = await axios.get(`${API_URL}/proxy/health`);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return true;
  } catch (error) {
    if (error.response) {
      console.log('Status:', error.response.status);
      console.log('Error:', JSON.stringify(error.response.data, null, 2));
    } else {
      console.log('❌ Failed:', error.message);
    }
    return false;
  }
}

// Test 9: Test security - SQL injection attempt (should be blocked)
async function testSecuritySQLInjection() {
  try {
    console.log('\n✅ Test 9: Security Test - SQL Injection (should be blocked)');
    const response = await axios.get(`${BASE_URL}/health?id=1' OR '1'='1`);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return false; // Should have been blocked
  } catch (error) {
    if (error.response && error.response.status === 403) {
      console.log('✅ Security working! Request blocked with status:', error.response.status);
      console.log('Response:', JSON.stringify(error.response.data, null, 2));
      return true;
    } else {
      console.log('❌ Failed:', error.message);
      return false;
    }
  }
}

// Test 10: Test security - XSS attempt (should be blocked)
async function testSecurityXSS() {
  try {
    console.log('\n✅ Test 10: Security Test - XSS Attack (should be blocked)');
    const response = await axios.get(`${BASE_URL}/health?name=<script>alert('xss')</script>`);
    console.log('Status:', response.status);
    console.log('Response:', JSON.stringify(response.data, null, 2));
    return false; // Should have been blocked
  } catch (error) {
    if (error.response && error.response.status === 403) {
      console.log('✅ Security working! Request blocked with status:', error.response.status);
      console.log('Response:', JSON.stringify(error.response.data, null, 2));
      return true;
    } else {
      console.log('❌ Failed:', error.message);
      return false;
    }
  }
}

// Run all tests
async function runTests() {
  const results = {
    passed: 0,
    failed: 0,
    total: 10
  };

  // Basic tests
  if (await testRoot()) results.passed++; else results.failed++;
  if (await testHealth()) results.passed++; else results.failed++;
  
  // Auth tests
  let token = await testRegister();
  if (token) results.passed++; else results.failed++;
  
  if (!token) {
    token = await testLogin();
  }
  
  if (token) {
    results.passed++;
    
    // Authenticated tests
    if (await testGetMe(token)) results.passed++; else results.failed++;
    if (await testAdminStats(token)) results.passed++; else results.failed++;
    if (await testAdminLogs(token)) results.passed++; else results.failed++;
  } else {
    console.log('\n⚠️  Skipping authenticated tests - no token available');
    results.failed += 3;
  }
  
  // Proxy test
  if (await testProxyHealth()) results.passed++; else results.failed++;
  
  // Security tests
  if (await testSecuritySQLInjection()) results.passed++; else results.failed++;
  if (await testSecurityXSS()) results.passed++; else results.failed++;
  
  // Summary
  console.log('\n' + '='.repeat(50));
  console.log('📊 Test Summary');
  console.log('='.repeat(50));
  console.log(`Total Tests: ${results.total}`);
  console.log(`✅ Passed: ${results.passed}`);
  console.log(`❌ Failed: ${results.failed}`);
  console.log(`Success Rate: ${((results.passed / results.total) * 100).toFixed(1)}%`);
  console.log('='.repeat(50));
}

// Run the tests
runTests().catch(console.error);
