# 🛡️ SentinelAPI

> **A comprehensive API security testing and vulnerability detection platform built for developers who care about security.**

SentinelAPI helps you identify and fix API vulnerabilities before they become security incidents. Test individual endpoints and monitor traffic in real-time with automated threat detection.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-4.4%2B-green)](https://www.mongodb.com)

---

## 🎯 What is SentinelAPI?

SentinelAPI is a **security-first API testing platform** that provides comprehensive security scanning capabilities similar to OWASP ZAP and Burp Suite - but simpler, more focused, and developer-friendly.

### The Problem We Solve

Modern web applications rely heavily on APIs, but securing them is complex:
- 🔴 **Authentication vulnerabilities** are common but hard to detect manually
- 🔴 **Manual security testing** is tedious, error-prone, and doesn't scale
- 🔴 **Lack of actionable guidance** - tools find issues but don't explain how to fix them
- 🔴 **Inconsistent security practices** lead to vulnerabilities slipping into production

### Our Solution

✅ **Automated Security Testing** - Scan endpoints with comprehensive vulnerability checks  
✅ **Deep Authentication Analysis** - Specialized testing for OAuth 2.0, JWT, API keys, and sessions  
✅ **Actionable Remediation** - Every vulnerability comes with clear fix instructions and code examples  
✅ **Real-Time Monitoring** - Live traffic analysis with automatic threat blocking  
✅ **Detailed Reports** - Export comprehensive security reports in JSON and HTML formats  
✅ **Developer-Friendly** - Beautiful UI, clear reports, and seamless workflow integration

---

## ✨ Key Features

### 🔍 Single Endpoint Scanner
- Quick vulnerability scan for individual API endpoints
- Custom headers and authentication configuration
- Real-time scan progress with detailed feedback
- Support for all HTTP methods (GET, POST, PUT, DELETE, PATCH, etc.)
- Instant vulnerability reports with severity ratings

### 🔐 Authentication Testing

#### OAuth 2.0 Flow Testing
- Authorization Code flow validation
- Client Credentials flow testing
- Implicit flow vulnerability detection
- Token expiration and refresh handling
- PKCE implementation verification

#### JWT Analysis
- Algorithm verification (detect 'none' algorithm attacks)
- Signature validation with secret verification
- Claims inspection and sensitive data detection
- Expiration checking and timing attacks
- Token manipulation testing

#### API Key Testing
- Key exposure in URLs (insecure transmission)
- Key rotation detection
- HTTPS enforcement validation
- Key location security (header vs query parameter)

#### Session Management
- Cookie security flags (HttpOnly, Secure, SameSite)
- Session fixation vulnerability detection
- Session timeout configuration testing

### 🛡️ Core Vulnerability Checks

- **Injection Attacks** - SQL injection, NoSQL injection, command injection
- **CORS Misconfigurations** - Overly permissive CORS policies
- **SSL/TLS Issues** - Certificate validation, weak ciphers, protocol versions
- **Security Headers Analysis** - Missing or misconfigured headers (CSP, HSTS, X-Frame-Options)
- **Rate Limiting Detection** - DoS vulnerability testing
- **Sensitive Data Exposure** - Detect exposed secrets, API keys, PII in responses
- **Broken Access Control** - Authorization bypass attempts
- **XSS Protection** - Cross-site scripting vulnerability detection

### 🔄 Real-Time Proxy Mode

Route your API traffic through SentinelAPI for live monitoring:
- **Automatic threat detection** and blocking
- **Live traffic dashboard** with WebSocket updates
- **Request/response logging** to database
- **Configurable rate limiting** per IP
- **Target URL whitelist** for security

### 📡 Live Monitoring Dashboard

Real-time visibility into API security with WebSocket-powered updates:
- **Live Metrics** - Requests per minute, blocked threats, response times, active connections
- **Request Stream** - Real-time feed of all API requests with full details
- **Security Alerts** - Instant notifications for blocked threats and suspicious activity
- **Threat Distribution** - Visual breakdown of threat levels (Low, Medium, High, Critical)
- **Historical Data** - Time-series analytics and top IP tracking
- **Auto-Reconnect** - Resilient WebSocket connection with automatic recovery
- **Response time tracking** and analytics

### 📊 Detailed Reports

- Comprehensive vulnerability lists with severity indicators
- Detailed descriptions with impact analysis
- Step-by-step remediation instructions
- Code examples and security references (CWE, OWASP)
- Export reports as JSON or HTML
- Professional HTML reports with visual charts and styling
- Risk score calculation based on vulnerability severity
- Automated security recommendations

### 📈 Real-Time Dashboard

- Live statistics and metrics
- Active scan monitoring
- Threat level distribution charts
- Request timeline visualization
- Top requesting IPs
- Recent threats feed
- WebSocket-based real-time updates

### ⚙️ Configuration Management

- Dynamic security rule configuration
- Rate limit customization
- IP whitelist/blacklist management
- Security feature toggles
- Proxy target configuration
- All settings accessible via UI and API

---

## 🏗️ Architecture

### Technology Stack

**Backend**
- **Runtime:** Node.js (v18+)
- **Framework:** Express.js 5
- **Database:** MongoDB (with Mongoose ODM)
- **Real-time:** Socket.io (WebSocket)
- **Authentication:** JWT-based auth
- **Proxy:** http-proxy-middleware
- **Rate Limiting:** express-rate-limit
- **Logging:** Winston

**Frontend**
- **Framework:** React 18
- **Build Tool:** Vite
- **Styling:** Tailwind CSS
- **State Management:** React Hooks
- **Real-time:** Socket.io-client
- **HTTP Client:** Axios

**DevOps**
- **Version Control:** Git
- **Package Manager:** npm
- **Environment:** dotenv
- **Testing:** Jest (backend), Vitest (frontend)

### System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Client Application                    │
│              (Browser / API Client / CLI)                │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   SentinelAPI Server                     │
│  ┌───────────────────────────────────────────────────┐  │
│  │           Express.js Application                  │  │
│  │  ┌─────────────────────────────────────────────┐ │  │
│  │  │  Security Middleware (SQL, XSS, NoSQL, etc) │ │  │
│  │  └─────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────┐ │  │
│  │  │         Rate Limiting Middleware            │ │  │
│  │  └─────────────────────────────────────────────┘ │  │
│  │  ┌─────────────────────────────────────────────┐ │  │
│  │  │           Proxy Middleware                  │ │  │
│  │  └─────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Scanner    │  │   Logger     │  │  WebSocket   │  │
│  │   Service    │  │   Service    │  │   Service    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐                                       │
│  │   Report     │                                       │
│  │  Generator   │                                       │
│  └──────────────┘                                       │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                    MongoDB Database                      │
│  • Request Logs    • Security Config    • Scan Results  │
│  • Admin Users     • API Keys           • Analytics     │
└─────────────────────────────────────────────────────────┘
```

---

## 🎯 Use Cases

### For Developers
- Test APIs during development
- Find security issues before code review
- Learn secure coding practices
- Get actionable fix instructions
- No security expertise needed

### For Security Engineers
- Quick API security audits
- Comprehensive vulnerability reports
- Export reports for compliance
- Monitor production APIs (proxy mode)
- Automated penetration testing

### For DevOps Teams
- Integrate into CI/CD pipelines *(coming soon)*
- Automated security testing
- Track security improvements over time
- Monitor API health and performance

### For QA Testers
- Add security testing to test suites
- Regression testing for security fixes
- Validate authentication flows
- Test rate limiting and DDoS protection

---



## 🔐 Security Features

### Threat Detection
- Real-time SQL injection detection
- XSS attack prevention
- NoSQL injection blocking
- Command injection detection
- Path traversal prevention
- CORS misconfiguration detection

### Rate Limiting
- IP-based rate limiting
- Configurable limits per endpoint type
- Whitelist bypass support
- Standard rate limit headers
- DDoS protection

### Request Logging
- All requests logged to database
- Detailed threat information
- Response time tracking
- IP address tracking
- User agent logging
- Request/response body capture

### Proxy Security
- Target URL whitelist
- HTTPS enforcement
- Request validation
- Response scanning
- Error handling
- Timeout protection

---

## 🧪 Testing

```bash
cd backend
npm test                # full Jest suite
npm run test:security   # detection patterns + sanitizers (true positives and benign inputs)
npm run test:nosql      # NoSQL-injection middleware via supertest, no MongoDB needed
```

CI (GitHub Actions) runs lint and the test suite on every push and pull request. Known gap: the classic `' OR '1'='1` tautology is not yet detected; it is tracked as a `test.failing` case.

---

## 📈 Performance

> Latency and concurrency have not been formally benchmarked yet; no numbers are claimed here until a reproducible load test exists.

- **Database:** Indexes on request-log and scan-result queries
- **Rate Limiting:** In-memory store for minimal overhead
- **WebSocket:** Real-time updates with minimal bandwidth

---


*Last Updated: February 19, 2026*  
*Version: 1.0.0*  
*Status: Working ✅*
