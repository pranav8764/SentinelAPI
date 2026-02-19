/**
 * Endpoint Scanner Service
 * Performs comprehensive security scans on API endpoints
 */

import axios from 'axios';
import { checkForVulnerabilities, getThreatLevel } from '../config/securityPatterns.js';
import logger from '../utils/logger.js';

class EndpointScanner {
  constructor() {
    this.timeout = 10000;
  }

  /**
   * Scan a single endpoint for vulnerabilities
   */
  async scanEndpoint(config) {
    const {
      url,
      method = 'GET',
      headers = {},
      body = null,
      authType = 'none',
      authConfig = {}
    } = config;

    const scanResults = {
      url,
      method,
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      tests: [],
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      responseTime: 0,
      statusCode: null,
      passed: 0,
      failed: 0
    };

    try {
      // Add authentication headers
      const requestHeaders = this.buildHeaders(headers, authType, authConfig);

      // 1. Test basic connectivity
      const connectivityTest = await this.testConnectivity(url, method, requestHeaders, body);
      scanResults.tests.push(connectivityTest);
      scanResults.responseTime = connectivityTest.responseTime;
      scanResults.statusCode = connectivityTest.statusCode;

      if (!connectivityTest.success) {
        scanResults.failed++;
        return scanResults;
      }
      scanResults.passed++;

      // 2. Test SQL Injection
      const sqlTests = await this.testSQLInjection(url, method, requestHeaders, body);
      scanResults.tests.push(...sqlTests);
      scanResults.vulnerabilities.push(...sqlTests.filter(t => !t.passed).map(t => t.vulnerability));

      // 3. Test XSS
      const xssTests = await this.testXSS(url, method, requestHeaders, body);
      scanResults.tests.push(...xssTests);
      scanResults.vulnerabilities.push(...xssTests.filter(t => !t.passed).map(t => t.vulnerability));

      // 4. Test NoSQL Injection
      const nosqlTests = await this.testNoSQLInjection(url, method, requestHeaders, body);
      scanResults.tests.push(...nosqlTests);
      scanResults.vulnerabilities.push(...nosqlTests.filter(t => !t.passed).map(t => t.vulnerability));

      // 5. Test Command Injection
      const cmdTests = await this.testCommandInjection(url, method, requestHeaders, body);
      scanResults.tests.push(...cmdTests);
      scanResults.vulnerabilities.push(...cmdTests.filter(t => !t.passed).map(t => t.vulnerability));

      // 6. Test Security Headers
      const headerTests = await this.testSecurityHeaders(url, method, requestHeaders, body);
      scanResults.tests.push(...headerTests);
      scanResults.vulnerabilities.push(...headerTests.filter(t => !t.passed).map(t => t.vulnerability));

      // 7. Test CORS Configuration
      const corsTests = await this.testCORS(url, method, requestHeaders);
      scanResults.tests.push(...corsTests);
      scanResults.vulnerabilities.push(...corsTests.filter(t => !t.passed).map(t => t.vulnerability));

      // 8. Test Authentication
      if (authType !== 'none') {
        const authTests = await this.testAuthentication(url, method, requestHeaders, body, authType);
        scanResults.tests.push(...authTests);
        scanResults.vulnerabilities.push(...authTests.filter(t => !t.passed).map(t => t.vulnerability));
      }

      // 9. Test Rate Limiting
      const rateLimitTests = await this.testRateLimiting(url, method, requestHeaders, body);
      scanResults.tests.push(...rateLimitTests);
      scanResults.vulnerabilities.push(...rateLimitTests.filter(t => !t.passed).map(t => t.vulnerability));

      // Calculate summary
      scanResults.vulnerabilities.forEach(vuln => {
        scanResults.summary.total++;
        scanResults.summary[vuln.severity]++;
      });

      scanResults.passed = scanResults.tests.filter(t => t.passed).length;
      scanResults.failed = scanResults.tests.filter(t => !t.passed).length;

      logger.info(`Scan completed for ${url}: ${scanResults.vulnerabilities.length} vulnerabilities found`);

    } catch (error) {
      logger.error(`Scan error for ${url}: ${error.message}`);
      scanResults.error = error.message;
    }

    return scanResults;
  }

  /**
   * Build request headers with authentication
   */
  buildHeaders(customHeaders, authType, authConfig) {
    const headers = { ...customHeaders };

    switch (authType) {
      case 'bearer':
        if (authConfig.token) {
          headers['Authorization'] = `Bearer ${authConfig.token}`;
        }
        break;
      case 'apikey':
        if (authConfig.key && authConfig.value) {
          headers[authConfig.key] = authConfig.value;
        }
        break;
      case 'basic':
        if (authConfig.username && authConfig.password) {
          const encoded = Buffer.from(`${authConfig.username}:${authConfig.password}`).toString('base64');
          headers['Authorization'] = `Basic ${encoded}`;
        }
        break;
    }

    return headers;
  }

  /**
   * Test basic connectivity
   */
  async testConnectivity(url, method, headers, body) {
    const test = {
      name: 'Connectivity Test',
      category: 'connectivity',
      passed: false,
      responseTime: 0,
      statusCode: null,
      message: ''
    };

    const startTime = Date.now();
    try {
      const response = await axios({
        url,
        method,
        headers,
        data: body,
        timeout: this.timeout,
        validateStatus: () => true
      });

      test.responseTime = Date.now() - startTime;
      test.statusCode = response.status;
      test.passed = response.status < 500;
      test.message = test.passed ? 'Endpoint is accessible' : 'Server error detected';
      test.success = test.passed;
    } catch (error) {
      test.responseTime = Date.now() - startTime;
      test.message = `Connection failed: ${error.message}`;
      test.error = error.message;
    }

    return test;
  }

  /**
   * Test SQL Injection vulnerabilities
   */
  async testSQLInjection(url, method, headers, body) {
    const tests = [];
    const payloads = [
      "' OR '1'='1",
      "1' OR '1'='1' --",
      "' UNION SELECT NULL--",
      "admin'--",
      "1' AND 1=1--"
    ];

    for (const payload of payloads) {
      const test = {
        name: 'SQL Injection Test',
        category: 'sql_injection',
        payload,
        passed: true,
        message: ''
      };

      try {
        const testUrl = this.injectPayload(url, payload);
        const response = await axios({
          url: testUrl,
          method,
          headers,
          data: body,
          timeout: this.timeout,
          validateStatus: () => true
        });

        const responseText = JSON.stringify(response.data);
        const sqlErrors = [
          'sql syntax',
          'mysql_fetch',
          'ora-',
          'postgresql',
          'sqlite',
          'unclosed quotation',
          'quoted string not properly terminated'
        ];

        const hasError = sqlErrors.some(err => responseText.toLowerCase().includes(err));

        if (hasError || response.status === 500) {
          test.passed = false;
          test.vulnerability = {
            type: 'SQL Injection',
            severity: 'critical',
            description: 'Endpoint may be vulnerable to SQL injection attacks',
            evidence: `Payload "${payload}" triggered suspicious response`,
            remediation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
            cwe: 'CWE-89',
            owasp: 'A03:2021 - Injection'
          };
          test.message = 'Potential SQL injection vulnerability detected';
        } else {
          test.message = 'No SQL injection vulnerability detected with this payload';
        }
      } catch (error) {
        test.message = `Test failed: ${error.message}`;
      }

      tests.push(test);
    }

    return tests;
  }

  /**
   * Test XSS vulnerabilities
   */
  async testXSS(url, method, headers, body) {
    const tests = [];
    const payloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg/onload=alert("XSS")>',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')"></iframe>'
    ];

    for (const payload of payloads) {
      const test = {
        name: 'XSS Test',
        category: 'xss',
        payload,
        passed: true,
        message: ''
      };

      try {
        const testUrl = this.injectPayload(url, payload);
        const response = await axios({
          url: testUrl,
          method,
          headers,
          data: body,
          timeout: this.timeout,
          validateStatus: () => true
        });

        const responseText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

        if (responseText.includes(payload) || responseText.includes(payload.replace(/"/g, "'"))) {
          test.passed = false;
          test.vulnerability = {
            type: 'Cross-Site Scripting (XSS)',
            severity: 'high',
            description: 'Endpoint reflects user input without proper sanitization',
            evidence: `Payload "${payload}" was reflected in response`,
            remediation: 'Sanitize and encode all user input before displaying. Use Content Security Policy headers.',
            cwe: 'CWE-79',
            owasp: 'A03:2021 - Injection'
          };
          test.message = 'Potential XSS vulnerability detected';
        } else {
          test.message = 'No XSS vulnerability detected with this payload';
        }
      } catch (error) {
        test.message = `Test failed: ${error.message}`;
      }

      tests.push(test);
    }

    return tests;
  }

  /**
   * Test NoSQL Injection vulnerabilities
   */
  async testNoSQLInjection(url, method, headers, body) {
    const tests = [];
    const payloads = [
      '{"$ne": null}',
      '{"$gt": ""}',
      '{"$where": "1==1"}',
      '{"$regex": ".*"}',
      '[$ne]=1'
    ];

    for (const payload of payloads) {
      const test = {
        name: 'NoSQL Injection Test',
        category: 'nosql_injection',
        payload,
        passed: true,
        message: ''
      };

      try {
        const testUrl = this.injectPayload(url, payload);
        const response = await axios({
          url: testUrl,
          method,
          headers,
          data: body,
          timeout: this.timeout,
          validateStatus: () => true
        });

        if (response.status === 500 || (response.data && response.data.error && 
            response.data.error.toLowerCase().includes('mongo'))) {
          test.passed = false;
          test.vulnerability = {
            type: 'NoSQL Injection',
            severity: 'high',
            description: 'Endpoint may be vulnerable to NoSQL injection attacks',
            evidence: `Payload "${payload}" triggered suspicious response`,
            remediation: 'Validate and sanitize all input. Use schema validation and avoid passing user input directly to database queries.',
            cwe: 'CWE-943',
            owasp: 'A03:2021 - Injection'
          };
          test.message = 'Potential NoSQL injection vulnerability detected';
        } else {
          test.message = 'No NoSQL injection vulnerability detected with this payload';
        }
      } catch (error) {
        test.message = `Test failed: ${error.message}`;
      }

      tests.push(test);
    }

    return tests;
  }

  /**
   * Test Command Injection vulnerabilities
   */
  async testCommandInjection(url, method, headers, body) {
    const tests = [];
    const payloads = [
      '; ls',
      '| whoami',
      '`id`',
      '$(sleep 5)',
      '& ping -c 5 127.0.0.1'
    ];

    for (const payload of payloads) {
      const test = {
        name: 'Command Injection Test',
        category: 'command_injection',
        payload,
        passed: true,
        message: ''
      };

      try {
        const testUrl = this.injectPayload(url, payload);
        const startTime = Date.now();
        const response = await axios({
          url: testUrl,
          method,
          headers,
          data: body,
          timeout: this.timeout,
          validateStatus: () => true
        });
        const responseTime = Date.now() - startTime;

        const responseText = JSON.stringify(response.data);
        const cmdIndicators = ['root:', 'uid=', 'gid=', 'groups=', 'bin/sh'];
        const hasIndicator = cmdIndicators.some(ind => responseText.includes(ind));

        if (hasIndicator || (payload.includes('sleep') && responseTime > 4000)) {
          test.passed = false;
          test.vulnerability = {
            type: 'Command Injection',
            severity: 'critical',
            description: 'Endpoint may be vulnerable to OS command injection',
            evidence: `Payload "${payload}" triggered suspicious response`,
            remediation: 'Never pass user input directly to system commands. Use safe APIs and validate input strictly.',
            cwe: 'CWE-78',
            owasp: 'A03:2021 - Injection'
          };
          test.message = 'Potential command injection vulnerability detected';
        } else {
          test.message = 'No command injection vulnerability detected with this payload';
        }
      } catch (error) {
        test.message = `Test failed: ${error.message}`;
      }

      tests.push(test);
    }

    return tests;
  }

  /**
   * Test Security Headers
   */
  async testSecurityHeaders(url, method, headers, body) {
    const tests = [];

    try {
      const response = await axios({
        url,
        method,
        headers,
        data: body,
        timeout: this.timeout,
        validateStatus: () => true
      });

      const requiredHeaders = {
        'x-content-type-options': { value: 'nosniff', severity: 'medium' },
        'x-frame-options': { value: ['DENY', 'SAMEORIGIN'], severity: 'medium' },
        'strict-transport-security': { value: null, severity: 'high' },
        'content-security-policy': { value: null, severity: 'medium' },
        'x-xss-protection': { value: '1; mode=block', severity: 'low' }
      };

      for (const [headerName, config] of Object.entries(requiredHeaders)) {
        const test = {
          name: `Security Header: ${headerName}`,
          category: 'security_headers',
          passed: true,
          message: ''
        };

        const headerValue = response.headers[headerName];

        if (!headerValue) {
          test.passed = false;
          test.vulnerability = {
            type: 'Missing Security Header',
            severity: config.severity,
            description: `Missing ${headerName} header`,
            evidence: `Response does not include ${headerName} header`,
            remediation: `Add ${headerName} header to all responses`,
            cwe: 'CWE-693',
            owasp: 'A05:2021 - Security Misconfiguration'
          };
          test.message = `Missing ${headerName} header`;
        } else {
          test.message = `${headerName} header is present`;
        }

        tests.push(test);
      }
    } catch (error) {
      logger.error(`Security headers test failed: ${error.message}`);
    }

    return tests;
  }

  /**
   * Test CORS Configuration
   */
  async testCORS(url, method, headers) {
    const tests = [];

    try {
      const response = await axios({
        url,
        method: 'OPTIONS',
        headers: {
          ...headers,
          'Origin': 'https://evil.com',
          'Access-Control-Request-Method': method
        },
        timeout: this.timeout,
        validateStatus: () => true
      });

      const test = {
        name: 'CORS Configuration Test',
        category: 'cors',
        passed: true,
        message: ''
      };

      const allowOrigin = response.headers['access-control-allow-origin'];

      if (allowOrigin === '*') {
        test.passed = false;
        test.vulnerability = {
          type: 'CORS Misconfiguration',
          severity: 'medium',
          description: 'CORS policy allows requests from any origin',
          evidence: 'Access-Control-Allow-Origin: *',
          remediation: 'Restrict CORS to specific trusted origins instead of using wildcard',
          cwe: 'CWE-942',
          owasp: 'A05:2021 - Security Misconfiguration'
        };
        test.message = 'Overly permissive CORS policy detected';
      } else if (allowOrigin === 'https://evil.com') {
        test.passed = false;
        test.vulnerability = {
          type: 'CORS Misconfiguration',
          severity: 'high',
          description: 'CORS policy reflects arbitrary origins',
          evidence: 'Server reflects any origin in Access-Control-Allow-Origin',
          remediation: 'Use a whitelist of allowed origins instead of reflecting the request origin',
          cwe: 'CWE-942',
          owasp: 'A05:2021 - Security Misconfiguration'
        };
        test.message = 'CORS policy reflects arbitrary origins';
      } else {
        test.message = 'CORS configuration appears secure';
      }

      tests.push(test);
    } catch (error) {
      logger.error(`CORS test failed: ${error.message}`);
    }

    return tests;
  }

  /**
   * Test Authentication
   */
  async testAuthentication(url, method, headers, body, authType) {
    const tests = [];

    // Test without authentication
    const test = {
      name: 'Authentication Bypass Test',
      category: 'authentication',
      passed: true,
      message: ''
    };

    try {
      const headersWithoutAuth = { ...headers };
      delete headersWithoutAuth['Authorization'];

      const response = await axios({
        url,
        method,
        headers: headersWithoutAuth,
        data: body,
        timeout: this.timeout,
        validateStatus: () => true
      });

      if (response.status === 200) {
        test.passed = false;
        test.vulnerability = {
          type: 'Authentication Bypass',
          severity: 'critical',
          description: 'Endpoint accessible without authentication',
          evidence: 'Request succeeded without authentication headers',
          remediation: 'Implement proper authentication checks on all protected endpoints',
          cwe: 'CWE-287',
          owasp: 'A07:2021 - Identification and Authentication Failures'
        };
        test.message = 'Endpoint accessible without authentication';
      } else if (response.status === 401 || response.status === 403) {
        test.message = 'Authentication properly enforced';
      } else {
        test.message = `Unexpected response: ${response.status}`;
      }
    } catch (error) {
      test.message = `Test failed: ${error.message}`;
    }

    tests.push(test);
    return tests;
  }

  /**
   * Test Rate Limiting
   */
  async testRateLimiting(url, method, headers, body) {
    const tests = [];
    const test = {
      name: 'Rate Limiting Test',
      category: 'rate_limiting',
      passed: true,
      message: ''
    };

    try {
      const requests = [];
      for (let i = 0; i < 20; i++) {
        requests.push(
          axios({
            url,
            method,
            headers,
            data: body,
            timeout: this.timeout,
            validateStatus: () => true
          })
        );
      }

      const responses = await Promise.all(requests);
      const rateLimited = responses.some(r => r.status === 429);

      if (!rateLimited) {
        test.passed = false;
        test.vulnerability = {
          type: 'Missing Rate Limiting',
          severity: 'medium',
          description: 'Endpoint does not implement rate limiting',
          evidence: '20 rapid requests succeeded without rate limiting',
          remediation: 'Implement rate limiting to prevent abuse and DoS attacks',
          cwe: 'CWE-770',
          owasp: 'A04:2021 - Insecure Design'
        };
        test.message = 'No rate limiting detected';
      } else {
        test.message = 'Rate limiting is implemented';
      }
    } catch (error) {
      test.message = `Test failed: ${error.message}`;
    }

    tests.push(test);
    return tests;
  }

  /**
   * Inject payload into URL
   */
  injectPayload(url, payload) {
    const urlObj = new URL(url);
    urlObj.searchParams.set('test', payload);
    return urlObj.toString();
  }
}

export default new EndpointScanner();
