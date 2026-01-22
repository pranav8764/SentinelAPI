/**
 * NoSQL Injection Protection Tests
 * Tests the NoSQL protection middleware against various attack vectors
 */

import axios from 'axios';
import chalk from 'chalk';

const API_URL = process.env.API_URL || 'http://localhost:3001';

const results = {
  passed: 0,
  failed: 0,
  blocked: 0,
  tests: []
};

function logTest(name, passed, details = {}) {
  const status = passed ? chalk.green('✓ PASS') : chalk.red('✗ FAIL');
  console.log(`${status} ${name}`);
  
  if (details.response) {
    console.log(chalk.gray(`  Status: ${details.response.status}`));
    if (details.response.data?.code) {
      console.log(chalk.gray(`  Code: ${details.response.data.code}`));
    }
  }
  
  if (details.message) {
    console.log(chalk.gray(`  ${details.message}`));
  }
  
  results.tests.push({ name, passed, details });
  if (passed) results.passed++;
  else results.failed++;
}

function wasBlocked(response) {
  return response.status === 403 && 
         (response.data?.code === 'NOSQL_INJECTION_DETECTED' || 
          response.data?.code === 'SECURITY_VIOLATION');
}

// ============================================================================
// NoSQL INJECTION TESTS
// ============================================================================

async function testNoSQLInjection() {
  console.log(chalk.blue('\n=== NoSQL Injection Tests ===\n'));
  
  const tests = [
    {
      name: '$ne operator - Authentication Bypass',
      payload: {
        username: { $ne: null },
        password: { $ne: null }
      },
      description: 'Attempts to bypass authentication by matching all users'
    },
    {
      name: '$gt operator - Always True',
      payload: {
        username: 'admin',
        password: { $gt: '' }
      },
      description: 'Password greater than empty string (always true)'
    },
    {
      name: '$where operator - JavaScript Execution',
      payload: {
        username: { $where: "this.password == 'admin'" },
        password: 'test'
      },
      description: 'Executes JavaScript code in MongoDB'
    },
    {
      name: '$regex operator - Pattern Matching',
      payload: {
        username: { $regex: '.*' },
        password: { $regex: '.*' }
      },
      description: 'Matches any username and password'
    },
    {
      name: '$or operator - Multiple Conditions',
      payload: {
        $or: [
          { username: 'admin' },
          { username: 'root' }
        ],
        password: { $ne: null }
      },
      description: 'Matches multiple usernames with any password'
    },
    {
      name: '$eval operator - Code Evaluation',
      payload: {
        username: { $eval: "db.users.find()" },
        password: 'test'
      },
      description: 'Evaluates JavaScript code'
    },
    {
      name: '$exists operator - Field Check',
      payload: {
        username: { $exists: true },
        password: { $exists: true }
      },
      description: 'Matches any document with username and password fields'
    },
    {
      name: 'Nested $ne operator',
      payload: {
        username: 'admin',
        password: { $ne: { $ne: null } }
      },
      description: 'Nested operator injection'
    },
    {
      name: '$in operator - Array Injection',
      payload: {
        username: { $in: ['admin', 'root', 'user'] },
        password: { $ne: null }
      },
      description: 'Matches multiple usernames'
    },
    {
      name: 'String with operator',
      payload: {
        username: '$ne',
        password: 'test'
      },
      description: 'Operator as string value'
    },
    {
      name: 'Query parameter injection',
      url: '/api/auth/login?username[$ne]=null&password[$ne]=null',
      method: 'get',
      description: 'Operators in query parameters'
    },
    {
      name: 'JSON string with operators',
      payload: {
        username: '{"$ne": null}',
        password: '{"$ne": null}'
      },
      description: 'Operators as JSON strings'
    }
  ];
  
  for (const test of tests) {
    try {
      let response;
      
      if (test.method === 'get') {
        response = await axios.get(`${API_URL}${test.url}`, {
          validateStatus: () => true
        });
      } else {
        response = await axios.post(`${API_URL}/api/auth/login`, test.payload, {
          validateStatus: () => true
        });
      }
      
      const blocked = wasBlocked(response);
      
      // For NoSQL injection, we expect either:
      // 1. Request blocked (403)
      // 2. Invalid credentials (401) - means operators were sanitized
      const isProtected = blocked || response.status === 401 || response.status === 400;
      
      logTest(`NoSQL Injection - ${test.name}`, isProtected, {
        response,
        message: blocked 
          ? 'Attack blocked by NoSQL protection' 
          : isProtected 
            ? 'Operators sanitized, authentication failed normally'
            : 'WARNING: Attack may have succeeded!'
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
// ADVANCED NoSQL TESTS
// ============================================================================

async function testAdvancedNoSQL() {
  console.log(chalk.blue('\n=== Advanced NoSQL Injection Tests ===\n'));
  
  const tests = [
    {
      name: 'Deeply nested operators',
      payload: {
        username: {
          $or: [
            { $ne: null },
            { $exists: true }
          ]
        },
        password: { $ne: null }
      }
    },
    {
      name: 'Array with operators',
      payload: {
        username: ['admin', { $ne: null }],
        password: 'test'
      }
    },
    {
      name: 'Mixed string and operator',
      payload: {
        username: 'admin',
        password: {
          $ne: null,
          $exists: true
        }
      }
    },
    {
      name: 'Function injection',
      payload: {
        username: { $function: { body: 'return true', args: [], lang: 'js' } },
        password: 'test'
      }
    },
    {
      name: 'Aggregation pipeline injection',
      payload: {
        username: { $match: { role: 'admin' } },
        password: 'test'
      }
    },
    {
      name: 'Type coercion attack',
      payload: {
        username: { $type: 'string' },
        password: { $type: 'string' }
      }
    },
    {
      name: 'Null byte injection',
      payload: {
        username: 'admin\x00',
        password: 'test\x00'
      }
    },
    {
      name: 'Unicode operator',
      payload: {
        username: '\u0024ne',  // Unicode $ character
        password: 'test'
      }
    }
  ];
  
  for (const test of tests) {
    try {
      const response = await axios.post(`${API_URL}/api/auth/login`, test.payload, {
        validateStatus: () => true
      });
      
      const blocked = wasBlocked(response);
      const isProtected = blocked || response.status === 401 || response.status === 400;
      
      logTest(`Advanced NoSQL - ${test.name}`, isProtected, {
        response,
        message: blocked 
          ? 'Attack blocked' 
          : isProtected 
            ? 'Operators sanitized'
            : 'WARNING: May be vulnerable!'
      });
      
      if (blocked) results.blocked++;
      
    } catch (error) {
      logTest(`Advanced NoSQL - ${test.name}`, false, {
        message: `Error: ${error.message}`
      });
    }
  }
}

// ============================================================================
// SAFE QUERY BUILDER TESTS
// ============================================================================

async function testSafeQueries() {
  console.log(chalk.blue('\n=== Safe Query Tests ===\n'));
  
  // These should work normally (not blocked)
  const tests = [
    {
      name: 'Normal login',
      payload: {
        username: 'admin',
        password: 'password123'
      },
      shouldWork: true
    },
    {
      name: 'Email login',
      payload: {
        username: 'admin@example.com',
        password: 'password123'
      },
      shouldWork: true
    },
    {
      name: 'Username with special chars',
      payload: {
        username: 'admin_user-123',
        password: 'password123'
      },
      shouldWork: true
    }
  ];
  
  for (const test of tests) {
    try {
      const response = await axios.post(`${API_URL}/api/auth/login`, test.payload, {
        validateStatus: () => true
      });
      
      // Should not be blocked (403), but may fail auth (401)
      const notBlocked = response.status !== 403;
      
      logTest(`Safe Query - ${test.name}`, notBlocked, {
        response,
        message: notBlocked 
          ? 'Request processed normally (not blocked)'
          : 'ERROR: Normal request was blocked!'
      });
      
    } catch (error) {
      logTest(`Safe Query - ${test.name}`, false, {
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
  console.log(chalk.bold.cyan('║     NoSQL INJECTION PROTECTION TESTS                  ║'));
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
  
  // Run test suites
  await testNoSQLInjection();
  await testAdvancedNoSQL();
  await testSafeQueries();
  
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
    console.log(chalk.bold.green('\n✓ ALL TESTS PASSED! NoSQL protection is working correctly.\n'));
  } else {
    console.log(chalk.bold.yellow('\n⚠ SOME TESTS FAILED! Review the NoSQL protection configuration.\n'));
  }
  
  // Recommendations
  if (results.blocked < total * 0.5) {
    console.log(chalk.yellow('Recommendation: Consider enabling stricter NoSQL protection.'));
    console.log(chalk.yellow('Set blockOnDanger: true in nosqlProtection middleware.\n'));
  }
  
  process.exit(results.failed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch(error => {
  console.error(chalk.red('Fatal error:'), error);
  process.exit(1);
});
