/**
 * Comprehensive Security Testing Suite
 * Tests all security protections against various attack vectors
 */

import axios from 'axios';
import chalk from 'chalk';

const API_URL = process.env.API_URL || 'http://localhost:3001';
const PROXY_URL = `${API_URL}/proxy`;

// Test configuration
const config = {
  timeout: 10000,
  validateStatus: () => true // Don't throw on any status
};

// Test results tracking
const results = {
  passed: 0,
  failed: 0,
  blocked: 0,
  tests: []
};

// Helper function to log test results
function logTest(name, passed, details = {}) {
  const status = passed ? chalk.green('✓ PASS') : chalk.red('✗ FAIL');
  console.log(`${status} ${name}`);
  
  if (details.response) {
    console.log(chalk.gray(`  Status: ${details.response.status}`));
    if (details.response.data?.threatLevel) {
      console.log(chalk.gray(`  Threat Level: ${details.response.data.threatLevel}`));
    }
  }
  
  if (details.message) {
    console.log(chalk.gray(`  ${details.message}`));
  }
  
  results.tests.push({ name, passed, details });
  if (passed) results.passed++;
  else results.failed++;
}

// Helper function to check if request was blocked
function wasBlocked(response) {
  return response.status === 403 && 
         (response.data?.code === 'SECURITY_VIOLATION' || 
          response.data?.error?.includes('blocked'));
}

// ============================================================================
// SQL INJECTION TESTS
// ============================================================================

async function testSQLInjection() {
  console.log(chalk.blue('\n=== SQL Injection Tests ===\n'));
  
  const sqlPayloads = [
    { name: 'UNION SELECT', payload: "' UNION SELECT * FROM users--" },
    { name: 'DROP TABLE', payload: "'; DROP TABLE users;--" },
    { name: 'Boolean-based blind', payload: "' OR '1'='1'--" },
    { name: 'Time-based blind', payload: "'; WAITFOR DELAY '00:00:05'--" },
    { name: 'Stacked queries', payload: "'; DELETE FROM logs WHERE 1=1--" },
    { name: 'Comment injection', payload: "admin'--" },
    { name: 'String concatenation', payload: "' + (SELECT password FROM users) + '" },
    { name: 'Hex encoding', payload: "0x61646d696e" }
  ];
  
  for (const test of sqlPayloads) {
    try {
      const response = await axios.get(`${API_URL}/health`, {
        params: { search: test.payload },
        ...config
      });
      
      const blocked = wasBlocked(response);
      logTest(`SQL Injection - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`SQL Injection - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// NoSQL INJECTION TESTS
// ============================================================================

async function testNoSQLInjection() {
  console.log(chalk.blue('\n=== NoSQL Injection Tests ===\n'));
  
  const nosqlPayloads = [
    { name: '$ne operator', payload: { username: { $ne: null } } },
    { name: '$gt operator', payload: { price: { $gt: 0 } } },
    { name: '$where injection', payload: { $where: "this.password == 'admin'" } },
    { name: '$regex injection', payload: { username: { $regex: '.*' } } },
    { name: '$or operator', payload: { $or: [{ admin: true }, { user: true }] } },
    { name: '$eval injection', payload: { $eval: "db.users.find()" } },
    { name: 'JavaScript injection', payload: "'; return true; var x='" }
  ];
  
  for (const test of nosqlPayloads) {
    try {
      const response = await axios.post(`${API_URL}/health`, test.payload, config);
      
      const blocked = wasBlocked(response);
      logTest(`NoSQL Injection - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`NoSQL Injection - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// XSS (Cross-Site Scripting) TESTS
// ============================================================================

async function testXSS() {
  console.log(chalk.blue('\n=== XSS (Cross-Site Scripting) Tests ===\n'));
  
  const xssPayloads = [
    { name: 'Basic script tag', payload: '<script>alert("XSS")</script>' },
    { name: 'IMG onerror', payload: '<img src=x onerror=alert("XSS")>' },
    { name: 'SVG onload', payload: '<svg onload=alert("XSS")>' },
    { name: 'JavaScript protocol', payload: '<a href="javascript:alert(\'XSS\')">Click</a>' },
    { name: 'Event handler', payload: '<div onclick="alert(\'XSS\')">Click</div>' },
    { name: 'Iframe injection', payload: '<iframe src="javascript:alert(\'XSS\')"></iframe>' },
    { name: 'Object tag', payload: '<object data="javascript:alert(\'XSS\')"></object>' },
    { name: 'Embed tag', payload: '<embed src="javascript:alert(\'XSS\')">' },
    { name: 'Form action', payload: '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>' },
    { name: 'Meta refresh', payload: '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">' },
    { name: 'Link stylesheet', payload: '<link rel="stylesheet" href="javascript:alert(\'XSS\')">' },
    { name: 'Style expression', payload: '<div style="background:expression(alert(\'XSS\'))">XSS</div>' },
    { name: 'Base64 encoded', payload: '<img src="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">' },
    { name: 'Unicode encoded', payload: '<script>\\u0061\\u006c\\u0065\\u0072\\u0074("XSS")</script>' },
    { name: 'Hex encoded', payload: '<script>\\x61\\x6c\\x65\\x72\\x74("XSS")</script>' },
    { name: 'HTML entities', payload: '&lt;script&gt;alert("XSS")&lt;/script&gt;' },
    { name: 'URL encoded', payload: '%3Cscript%3Ealert("XSS")%3C/script%3E' },
    { name: 'Double encoding', payload: '%253Cscript%253Ealert("XSS")%253C/script%253E' },
    { name: 'Template injection', payload: '{{constructor.constructor("alert(\'XSS\')")()}}' },
    { name: 'Template literal', payload: '${alert("XSS")}' },
    { name: 'Document.cookie', payload: '<script>document.cookie</script>' },
    { name: 'Document.write', payload: '<script>document.write("<img src=x onerror=alert(1)>")</script>' },
    { name: 'Window.location', payload: '<script>window.location="http://evil.com"</script>' },
    { name: 'Eval function', payload: '<script>eval("alert(\'XSS\')")</script>' }
  ];
  
  for (const test of xssPayloads) {
    try {
      const response = await axios.get(`${API_URL}/health`, {
        params: { comment: test.payload },
        ...config
      });
      
      const blocked = wasBlocked(response);
      logTest(`XSS - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`XSS - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// COMMAND INJECTION TESTS
// ============================================================================

async function testCommandInjection() {
  console.log(chalk.blue('\n=== Command Injection Tests ===\n'));
  
  const commandPayloads = [
    { name: 'Pipe to rm', payload: '| rm -rf /' },
    { name: 'Command chaining', payload: '&& cat /etc/passwd' },
    { name: 'Command substitution', payload: '$(whoami)' },
    { name: 'Backtick execution', payload: '`ls -la`' },
    { name: 'Semicolon separator', payload: '; cat /etc/shadow' },
    { name: 'Newline injection', payload: '\\n cat /etc/passwd' },
    { name: 'Windows command', payload: '& dir C:\\' },
    { name: 'PowerShell', payload: '; Get-ChildItem' }
  ];
  
  for (const test of commandPayloads) {
    try {
      const response = await axios.get(`${API_URL}/health`, {
        params: { file: test.payload },
        ...config
      });
      
      const blocked = wasBlocked(response);
      logTest(`Command Injection - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`Command Injection - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// PATH TRAVERSAL TESTS
// ============================================================================

async function testPathTraversal() {
  console.log(chalk.blue('\n=== Path Traversal Tests ===\n'));
  
  const pathPayloads = [
    { name: 'Basic traversal', payload: '../../etc/passwd' },
    { name: 'Windows traversal', payload: '..\\..\\windows\\system32\\config\\sam' },
    { name: 'URL encoded', payload: '%2e%2e%2f%2e%2e%2fetc%2fpasswd' },
    { name: 'Double encoding', payload: '%252e%252e%252f%252e%252e%252fetc%252fpasswd' },
    { name: 'Absolute path', payload: '/etc/passwd' },
    { name: 'Windows absolute', payload: 'C:\\windows\\system32\\config\\sam' },
    { name: 'Null byte', payload: '../../etc/passwd%00.jpg' },
    { name: 'Unicode traversal', payload: '..\\u002f..\\u002fetc\\u002fpasswd' }
  ];
  
  for (const test of pathPayloads) {
    try {
      const response = await axios.get(`${API_URL}/health`, {
        params: { path: test.payload },
        ...config
      });
      
      const blocked = wasBlocked(response);
      logTest(`Path Traversal - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`Path Traversal - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// HEADER INJECTION TESTS
// ============================================================================

async function testHeaderInjection() {
  console.log(chalk.blue('\n=== Header Injection Tests ===\n'));
  
  const headerTests = [
    { name: 'XSS in User-Agent', header: 'User-Agent', value: '<script>alert("XSS")</script>' },
    { name: 'XSS in Referer', header: 'Referer', value: 'javascript:alert("XSS")' },
    { name: 'CRLF injection', header: 'X-Custom', value: 'test\\r\\nX-Injected: malicious' },
    { name: 'SQL in custom header', header: 'X-Search', value: "' OR 1=1--" }
  ];
  
  for (const test of headerTests) {
    try {
      const response = await axios.get(`${API_URL}/health`, {
        headers: { [test.header]: test.value },
        ...config
      });
      
      const blocked = wasBlocked(response);
      logTest(`Header Injection - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`Header Injection - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// BODY INJECTION TESTS
// ============================================================================

async function testBodyInjection() {
  console.log(chalk.blue('\n=== Body Injection Tests ===\n'));
  
  const bodyTests = [
    { name: 'XSS in JSON', payload: { comment: '<script>alert("XSS")</script>' } },
    { name: 'SQL in JSON', payload: { username: "admin' OR '1'='1" } },
    { name: 'NoSQL in JSON', payload: { password: { $ne: null } } },
    { name: 'Command in JSON', payload: { file: '| cat /etc/passwd' } },
    { name: 'Path traversal in JSON', payload: { path: '../../etc/passwd' } },
    { name: 'Nested XSS', payload: { user: { profile: { bio: '<img src=x onerror=alert(1)>' } } } }
  ];
  
  for (const test of bodyTests) {
    try {
      const response = await axios.post(`${API_URL}/health`, test.payload, config);
      
      const blocked = wasBlocked(response);
      logTest(`Body Injection - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`Body Injection - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// SECURITY HEADERS TESTS
// ============================================================================

async function testSecurityHeaders() {
  console.log(chalk.blue('\n=== Security Headers Tests ===\n'));
  
  try {
    const response = await axios.get(`${API_URL}/health`, config);
    
    const requiredHeaders = [
      'x-content-type-options',
      'x-frame-options',
      'x-xss-protection',
      'referrer-policy',
      'content-security-policy'
    ];
    
    for (const header of requiredHeaders) {
      const present = response.headers[header] !== undefined;
      logTest(`Security Header - ${header}`, present, {
        message: present ? `Present: ${response.headers[header]}` : 'Missing!'
      });
    }
  } catch (error) {
    logTest('Security Headers Test', false, {
      message: `Error: ${error.message}`
    });
  }
}

// ============================================================================
// RATE LIMITING TESTS
// ============================================================================

async function testRateLimiting() {
  console.log(chalk.blue('\n=== Rate Limiting Tests ===\n'));
  
  try {
    const requests = [];
    const numRequests = 150; // Exceed typical rate limit
    
    console.log(chalk.gray(`Sending ${numRequests} rapid requests...`));
    
    for (let i = 0; i < numRequests; i++) {
      requests.push(axios.get(`${API_URL}/health`, config));
    }
    
    const responses = await Promise.all(requests);
    const rateLimited = responses.filter(r => r.status === 429).length;
    
    logTest('Rate Limiting', rateLimited > 0, {
      message: `${rateLimited}/${numRequests} requests were rate limited`
    });
  } catch (error) {
    logTest('Rate Limiting Test', false, {
      message: `Error: ${error.message}`
    });
  }
}

// ============================================================================
// COMBINED ATTACK TESTS
// ============================================================================

async function testCombinedAttacks() {
  console.log(chalk.blue('\n=== Combined Attack Tests ===\n'));
  
  const combinedTests = [
    {
      name: 'SQL + XSS',
      params: { search: "' OR 1=1--<script>alert('XSS')</script>" }
    },
    {
      name: 'NoSQL + Command Injection',
      body: { query: { $where: "this.password == 'admin' | cat /etc/passwd" } }
    },
    {
      name: 'Path Traversal + XSS',
      params: { file: '../../etc/passwd<script>alert(1)</script>' }
    }
  ];
  
  for (const test of combinedTests) {
    try {
      const response = test.params 
        ? await axios.get(`${API_URL}/health`, { params: test.params, ...config })
        : await axios.post(`${API_URL}/health`, test.body, config);
      
      const blocked = wasBlocked(response);
      logTest(`Combined Attack - ${test.name}`, blocked, {
        response,
        message: blocked ? 'Attack blocked successfully' : 'WARNING: Attack not blocked!'
      });
      
      if (blocked) results.blocked++;
    } catch (error) {
      logTest(`Combined Attack - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

async function runAllTests() {
  console.log(chalk.bold.cyan('\n╔════════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║     COMPREHENSIVE SECURITY TESTING SUITE              ║'));
  console.log(chalk.bold.cyan('╚════════════════════════════════════════════════════════╝\n'));
  
  console.log(chalk.yellow(`Testing API: ${API_URL}\n`));
  
  // Check if server is running
  try {
    await axios.get(`${API_URL}/health`, { timeout: 5000 });
    console.log(chalk.green('✓ Server is running\n'));
  } catch (error) {
    console.log(chalk.red('✗ Server is not running!'));
    console.log(chalk.yellow('Please start the backend server first: npm start\n'));
    process.exit(1);
  }
  
  // Run all test suites
  await testSQLInjection();
  await testNoSQLInjection();
  await testXSS();
  await testCommandInjection();
  await testPathTraversal();
  await testHeaderInjection();
  await testBodyInjection();
  await testSecurityHeaders();
  await testRateLimiting();
  await testCombinedAttacks();
  
  // Print summary
  console.log(chalk.bold.cyan('\n╔════════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║                    TEST SUMMARY                        ║'));
  console.log(chalk.bold.cyan('╚════════════════════════════════════════════════════════╝\n'));
  
  const total = results.passed + results.failed;
  const passRate = ((results.passed / total) * 100).toFixed(2);
  const blockRate = ((results.blocked / total) * 100).toFixed(2);
  
  console.log(chalk.white(`Total Tests:     ${total}`));
  console.log(chalk.green(`Passed:          ${results.passed} (${passRate}%)`));
  console.log(chalk.red(`Failed:          ${results.failed}`));
  console.log(chalk.yellow(`Attacks Blocked: ${results.blocked} (${blockRate}%)`));
  
  if (results.failed === 0) {
    console.log(chalk.bold.green('\n✓ ALL TESTS PASSED! Security is working correctly.\n'));
  } else {
    console.log(chalk.bold.red('\n✗ SOME TESTS FAILED! Please review the security configuration.\n'));
  }
  
  // Exit with appropriate code
  process.exit(results.failed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch(error => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});
