# SentinelAPI - Web API Security & Vulnerability Checker

## 📋 Project Summary

**SentinelAPI** is a comprehensive web application designed to help developers and security professionals identify vulnerabilities in their APIs before they become security incidents. The tool provides automated security testing for individual endpoints and entire API collections, with a strong focus on authentication testing and practical remediation guidance.

---

## 🎯 The Problem

Modern web applications rely heavily on APIs, but securing them is complex and often overlooked:

- **Authentication Vulnerabilities**: Weak JWT implementations, OAuth misconfigurations, and insecure API key handling are common but difficult to detect manually
- **Time-Consuming Manual Testing**: Security testing APIs manually is tedious, error-prone, and doesn't scale when dealing with dozens or hundreds of endpoints
- **Lack of Actionable Guidance**: Many security tools identify vulnerabilities but don't provide clear, practical steps to fix them
- **Collection Testing Gap**: Testing entire API collections (Postman, Swagger) for security issues requires significant manual effort
- **Inconsistent Security Practices**: Without automated checks, security vulnerabilities slip through code reviews and into production

---

## 💡 Our Solution

SentinelAPI provides an intuitive, powerful platform that:

✅ **Automates Security Testing** - Scan individual endpoints or entire API collections with one click  
✅ **Deep Authentication Analysis** - Specialized testing for OAuth 2.0, JWT, API keys, and session management  
✅ **Import & Test Collections** - Native support for Postman, OpenAPI/Swagger, and Insomnia collections  
✅ **Actionable Remediation** - Every vulnerability comes with clear fix instructions and code examples  
✅ **Track Progress Over Time** - Save scan history and compare results to measure security improvements  
✅ **Developer-Friendly** - Beautiful UI, clear reports, and seamless integration into existing workflows  

---

## 🚀 Core Features

### 1. **Single Endpoint Scanner**
- Quick vulnerability scan for individual API endpoints
- Custom headers and authentication configuration
- Real-time scan progress with detailed feedback
- Support for all HTTP methods (GET, POST, PUT, DELETE, etc.)

### 2. **API Collection Testing**
- Import Postman collections (JSON format)
- Import OpenAPI/Swagger specifications (YAML/JSON)
- Import Insomnia collections
- Batch scan all endpoints in a collection
- Preserve authentication configurations from imported collections
- Test endpoint relationships and dependencies
- Select specific endpoints or scan entire collections

### 3. **Authentication Testing**
- **OAuth 2.0 Flow Testing**
  - Authorization Code flow validation
  - Client Credentials flow testing
  - Implicit flow vulnerability detection
  - Token expiration and refresh handling
  - PKCE implementation verification
  
- **JWT Analysis**
  - Algorithm verification (detect 'none' algorithm attacks)
  - Signature validation with secret verification
  - Claims inspection and sensitive data detection
  - Expiration checking and timing attacks
  - Token manipulation testing
  
- **API Key Testing**
  - Key exposure in URLs (insecure transmission)
  - Key rotation detection
  - HTTPS enforcement validation
  - Key location security (header vs query parameter)
  
- **Basic Authentication Testing**
  - Credential strength analysis
  - HTTPS enforcement checks
  - Secure transmission validation
  
- **Session Management**
  - Cookie security flags (HttpOnly, Secure, SameSite)
  - Session fixation vulnerability detection
  - Session timeout configuration testing

### 4. **Core Vulnerability Checks**
- **Injection Attacks**: SQL injection, NoSQL injection, command injection
- **CORS Misconfigurations**: Overly permissive CORS policies
- **SSL/TLS Issues**: Certificate validation, weak ciphers, protocol versions
- **Security Headers Analysis**: Missing or misconfigured headers (CSP, HSTS, X-Frame-Options, etc.)
- **Rate Limiting Detection**: DoS vulnerability testing
- **Sensitive Data Exposure**: Detect exposed secrets, API keys, PII in responses
- **Broken Access Control**: Authorization bypass attempts

### 5. **Detailed Reports**
- Comprehensive list of all vulnerabilities found
- Severity indicators (Critical, High, Medium, Low)
- Detailed vulnerability descriptions with impact analysis
- Step-by-step remediation instructions
- Code examples for fixes
- Export reports as PDF or JSON
- Shareable report links

### 6. **Scan History**
- Save and organize previous scans
- Compare scans over time to track improvements
- Quick re-scan functionality for regression testing
- Filter and search through historical data

### 7. **Real-Time Traffic Monitoring**
- Live dashboard showing ongoing API scans
- WebSocket-based real-time updates
- Active scan progress tracking
- Concurrent scan monitoring
- Live vulnerability detection alerts
- Real-time statistics and metrics
- Active endpoint status indicators
- Scan queue management and visualization

---

## 📋 Input/Output Summary

| **Feature** | **Key Inputs** | **Key Outputs** |
|-------------|----------------|-----------------|
| **Single Endpoint Scanner** | • API URL<br>• HTTP Method<br>• Headers & Auth<br>• Request Body | • Real-time scan progress<br>• Vulnerability report with severity levels<br>• Remediation recommendations |
| **Collection Testing** | • Collection file (Postman/Swagger/Insomnia)<br>• Endpoint selection<br>• Auth override | • Batch scan results<br>• Collection-wide security summary<br>• Per-endpoint reports |
| **OAuth 2.0 Testing** | • Flow type & endpoints<br>• Client credentials<br>• PKCE parameters | • Flow validation results<br>• Token analysis<br>• Security recommendations |
| **JWT Analysis** | • JWT token<br>• Secret key (optional)<br>• Expected algorithm | • Algorithm security check<br>• Signature validation<br>• Claims inspection<br>• Vulnerability detection |
| **API Key Testing** | • Key value & name<br>• Location (header/query)<br>• Target endpoint | • Exposure risk assessment<br>• HTTPS validation<br>• Security recommendations |
| **Basic Auth Testing** | • Username & password<br>• Target endpoint | • Credential strength analysis<br>• HTTPS enforcement check<br>• Security recommendations |
| **Session Testing** | • Session cookie<br>• Cookie name<br>• Endpoints | • Cookie flags analysis<br>• Session fixation check<br>• Timeout assessment |
| **Injection Testing** | • Target endpoint<br>• Parameters to test<br>• Injection type | • Detected vulnerabilities<br>• Attack vectors<br>• Remediation examples |
| **CORS Testing** | • Target endpoint<br>• Origin domains | • Policy analysis<br>• Configuration warnings<br>• Recommendations |
| **SSL/TLS Testing** | • Target URL<br>• Min TLS version | • Certificate validation<br>• Cipher analysis<br>• Protocol recommendations |
| **Security Headers** | • Target endpoint<br>• Expected headers | • Missing/misconfigured headers<br>• Impact assessment<br>• Recommendations |
| **Rate Limiting** | • Target endpoint<br>• Request count & window | • Presence detection<br>• DoS assessment<br>• Configuration recommendations |
| **Data Exposure** | • Target endpoint<br>• Custom patterns | • Exposed secrets/PII<br>• Risk assessment<br>• Protection recommendations |
| **Access Control** | • Target endpoint<br>• Valid credentials<br>• Test scenarios | • Authorization bypass detection<br>• Privilege escalation risks<br>• Improvements |
| **Report Generation** | • Scan ID<br>• Format (PDF/JSON)<br>• Sections to include | • Formatted reports (PDF/JSON)<br>• Shareable links<br>• Code examples |
| **Scan History** | • Filters (date, severity, type)<br>• Sort options<br>• Comparison selection | • Historical scan list<br>• Trend analysis<br>• Comparison reports |
| **Real-Time Monitor** | • View selection<br>• Time range<br>• Refresh interval | • Live dashboard<br>• WebSocket updates<br>• Scan queue visualization |

---

## 🏗️ Technology Stack

### **Backend**
- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB (scan results, history, configurations)
- **Real-time**: Socket.io (WebSocket for live updates)
- **Authentication**: JWT-based auth for user sessions
- **API Testing**: Axios for making requests to target APIs

### **Frontend**
- **Framework**: React
- **Build Tool**: Vite
- **Styling**: Vanilla CSS with CSS variables
- **State Management**: Context API / Zustand
- **Real-time**: Socket.io-client
- **Charts**: Chart.js / Recharts (for analytics)
- **HTTP Client**: Axios

### **DevOps**
- **Version Control**: Git
- **Package Manager**: npm
- **Environment**: dotenv for configuration
- **Testing**: Jest (backend), Vitest (frontend)

---

## 🎨 Design Philosophy

- **Clarity Over Complexity**: Focus on actionable insights, not overwhelming data
- **Developer-First**: Built by developers, for developers
- **Visual Excellence**: Modern, beautiful UI that makes security testing enjoyable
- **Educational**: Not just finding bugs, but teaching how to fix them

---

## 📊 Target Users

- **Backend Developers** - Test APIs during development
- **Security Engineers** - Conduct security audits
- **DevOps Teams** - Integrate into CI/CD pipelines
- **QA Testers** - Add security testing to test suites
- **API Product Teams** - Ensure API security before launch

---

*Built with ❤️ by Pranav Singh Rajoria and Raghavendra Saini*

*Sometimes all it takes is a good roll*