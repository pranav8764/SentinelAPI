import logger from '../utils/logger.js';

/**
 * Generate a detailed security report from scan results
 */
class ReportGenerator {
  /**
   * Generate JSON report
   */
  generateJSON(scanResult) {
    try {
      const report = {
        metadata: {
          reportId: scanResult._id,
          generatedAt: new Date().toISOString(),
          scanDate: scanResult.createdAt,
          reportVersion: '1.0.0'
        },
        target: {
          url: scanResult.url,
          method: scanResult.method,
          statusCode: scanResult.statusCode,
          responseTime: scanResult.responseTime
        },
        summary: {
          totalVulnerabilities: scanResult.summary.total,
          criticalCount: scanResult.summary.critical,
          highCount: scanResult.summary.high,
          mediumCount: scanResult.summary.medium,
          lowCount: scanResult.summary.low,
          testsPassed: scanResult.passed,
          testsFailed: scanResult.failed,
          riskScore: this.calculateRiskScore(scanResult.summary)
        },
        vulnerabilities: scanResult.vulnerabilities.map((vuln, index) => ({
          id: index + 1,
          type: vuln.type,
          severity: vuln.severity,
          description: vuln.description,
          evidence: vuln.evidence,
          remediation: vuln.remediation,
          cwe: vuln.cwe,
          owasp: vuln.owasp
        })),
        tests: scanResult.tests.map((test, index) => ({
          id: index + 1,
          name: test.name,
          category: test.category,
          status: test.passed ? 'PASSED' : 'FAILED',
          message: test.message,
          payload: test.payload
        })),
        recommendations: this.generateRecommendations(scanResult)
      };

      return report;
    } catch (error) {
      logger.error(`Error generating JSON report: ${error.message}`);
      throw error;
    }
  }

  /**
   * Generate HTML report
   */
  generateHTML(scanResult) {
    try {
      const report = this.generateJSON(scanResult);
      
      const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report - ${report.target.url}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
    .header h1 { font-size: 2.5em; margin-bottom: 10px; }
    .header p { opacity: 0.9; font-size: 1.1em; }
    .card { background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .card h2 { color: #667eea; margin-bottom: 20px; font-size: 1.8em; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
    .card h3 { color: #555; margin: 20px 0 10px; font-size: 1.3em; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
    .meta-item { padding: 15px; background: #f8f9fa; border-radius: 5px; border-left: 4px solid #667eea; }
    .meta-label { font-size: 0.85em; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
    .meta-value { font-size: 1.2em; font-weight: 600; color: #333; margin-top: 5px; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
    .summary-card { padding: 20px; border-radius: 8px; text-align: center; color: white; }
    .summary-card.critical { background: linear-gradient(135deg, #e74c3c, #c0392b); }
    .summary-card.high { background: linear-gradient(135deg, #e67e22, #d35400); }
    .summary-card.medium { background: linear-gradient(135deg, #f39c12, #e67e22); }
    .summary-card.low { background: linear-gradient(135deg, #3498db, #2980b9); }
    .summary-card.passed { background: linear-gradient(135deg, #27ae60, #229954); }
    .summary-number { font-size: 2.5em; font-weight: bold; }
    .summary-label { font-size: 0.9em; opacity: 0.9; margin-top: 5px; }
    .vulnerability { border-left: 4px solid; padding: 15px; margin-bottom: 15px; border-radius: 5px; background: #f8f9fa; }
    .vulnerability.critical { border-color: #e74c3c; background: #fef5f5; }
    .vulnerability.high { border-color: #e67e22; background: #fef9f5; }
    .vulnerability.medium { border-color: #f39c12; background: #fffbf5; }
    .vulnerability.low { border-color: #3498db; background: #f5f9fe; }
    .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
    .vuln-title { font-weight: 600; font-size: 1.1em; color: #333; }
    .severity-badge { padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: 600; text-transform: uppercase; }
    .severity-badge.critical { background: #e74c3c; color: white; }
    .severity-badge.high { background: #e67e22; color: white; }
    .severity-badge.medium { background: #f39c12; color: white; }
    .severity-badge.low { background: #3498db; color: white; }
    .vuln-section { margin: 10px 0; }
    .vuln-label { font-weight: 600; color: #555; margin-bottom: 5px; }
    .vuln-content { color: #666; padding-left: 10px; }
    .code-block { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; margin: 10px 0; }
    .test-item { padding: 12px; margin-bottom: 10px; border-radius: 5px; display: flex; justify-content: space-between; align-items: center; }
    .test-item.passed { background: #d4edda; border-left: 4px solid #28a745; }
    .test-item.failed { background: #f8d7da; border-left: 4px solid #dc3545; }
    .test-name { font-weight: 500; color: #333; }
    .test-status { padding: 4px 10px; border-radius: 15px; font-size: 0.85em; font-weight: 600; }
    .test-status.passed { background: #28a745; color: white; }
    .test-status.failed { background: #dc3545; color: white; }
    .recommendation { background: #e8f4f8; border-left: 4px solid #3498db; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
    .recommendation-title { font-weight: 600; color: #2980b9; margin-bottom: 5px; }
    .footer { text-align: center; padding: 30px; color: #666; font-size: 0.9em; }
    .risk-score { display: inline-block; padding: 10px 20px; border-radius: 25px; font-size: 1.5em; font-weight: bold; margin: 10px 0; }
    .risk-score.critical { background: #e74c3c; color: white; }
    .risk-score.high { background: #e67e22; color: white; }
    .risk-score.medium { background: #f39c12; color: white; }
    .risk-score.low { background: #27ae60; color: white; }
    @media print { body { background: white; } .card { box-shadow: none; border: 1px solid #ddd; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ Security Scan Report</h1>
      <p>Generated by SentinelAPI on ${new Date(report.metadata.generatedAt).toLocaleString()}</p>
    </div>

    <div class="card">
      <h2>📋 Report Metadata</h2>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">Report ID</div>
          <div class="meta-value">${report.metadata.reportId}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Scan Date</div>
          <div class="meta-value">${new Date(report.metadata.scanDate).toLocaleString()}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Report Version</div>
          <div class="meta-value">${report.metadata.reportVersion}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>🎯 Target Information</h2>
      <div class="meta-grid">
        <div class="meta-item">
          <div class="meta-label">URL</div>
          <div class="meta-value" style="word-break: break-all;">${report.target.url}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">HTTP Method</div>
          <div class="meta-value">${report.target.method}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Status Code</div>
          <div class="meta-value">${report.target.statusCode || 'N/A'}</div>
        </div>
        <div class="meta-item">
          <div class="meta-label">Response Time</div>
          <div class="meta-value">${report.target.responseTime}ms</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h2>📊 Executive Summary</h2>
      <div style="text-align: center; margin: 20px 0;">
        <div class="meta-label">Overall Risk Score</div>
        <div class="risk-score ${this.getRiskLevel(report.summary.riskScore)}">${report.summary.riskScore}/100</div>
      </div>
      <div class="summary-grid">
        <div class="summary-card critical">
          <div class="summary-number">${report.summary.criticalCount}</div>
          <div class="summary-label">Critical</div>
        </div>
        <div class="summary-card high">
          <div class="summary-number">${report.summary.highCount}</div>
          <div class="summary-label">High</div>
        </div>
        <div class="summary-card medium">
          <div class="summary-number">${report.summary.mediumCount}</div>
          <div class="summary-label">Medium</div>
        </div>
        <div class="summary-card low">
          <div class="summary-number">${report.summary.lowCount}</div>
          <div class="summary-label">Low</div>
        </div>
        <div class="summary-card passed">
          <div class="summary-number">${report.summary.testsPassed}</div>
          <div class="summary-label">Tests Passed</div>
        </div>
      </div>
    </div>

    ${report.vulnerabilities.length > 0 ? `
    <div class="card">
      <h2>🔴 Vulnerabilities Detected</h2>
      ${report.vulnerabilities.map(vuln => `
        <div class="vulnerability ${vuln.severity}">
          <div class="vuln-header">
            <div class="vuln-title">${vuln.id}. ${vuln.type}</div>
            <span class="severity-badge ${vuln.severity}">${vuln.severity}</span>
          </div>
          
          ${vuln.description ? `
          <div class="vuln-section">
            <div class="vuln-label">Description:</div>
            <div class="vuln-content">${vuln.description}</div>
          </div>
          ` : ''}
          
          ${vuln.evidence ? `
          <div class="vuln-section">
            <div class="vuln-label">Evidence:</div>
            <div class="code-block">${this.escapeHtml(vuln.evidence)}</div>
          </div>
          ` : ''}
          
          ${vuln.remediation ? `
          <div class="vuln-section">
            <div class="vuln-label">Remediation:</div>
            <div class="vuln-content">${vuln.remediation}</div>
          </div>
          ` : ''}
          
          <div class="vuln-section">
            <div class="vuln-label">References:</div>
            <div class="vuln-content">
              ${vuln.cwe ? `CWE: ${vuln.cwe} | ` : ''}
              ${vuln.owasp ? `OWASP: ${vuln.owasp}` : ''}
            </div>
          </div>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <div class="card">
      <h2>✅ Test Results</h2>
      ${report.tests.map(test => `
        <div class="test-item ${test.status.toLowerCase()}">
          <div>
            <div class="test-name">${test.name}</div>
            ${test.message ? `<div style="font-size: 0.9em; color: #666; margin-top: 5px;">${test.message}</div>` : ''}
          </div>
          <span class="test-status ${test.status.toLowerCase()}">${test.status}</span>
        </div>
      `).join('')}
    </div>

    ${report.recommendations.length > 0 ? `
    <div class="card">
      <h2>💡 Recommendations</h2>
      ${report.recommendations.map(rec => `
        <div class="recommendation">
          <div class="recommendation-title">${rec.title}</div>
          <div>${rec.description}</div>
        </div>
      `).join('')}
    </div>
    ` : ''}

    <div class="footer">
      <p><strong>SentinelAPI</strong> - API Security Testing Platform</p>
      <p>This report is for informational purposes only. Always verify findings manually.</p>
    </div>
  </div>
</body>
</html>`;

      return html;
    } catch (error) {
      logger.error(`Error generating HTML report: ${error.message}`);
      throw error;
    }
  }

  /**
   * Calculate risk score based on vulnerability summary
   */
  calculateRiskScore(summary) {
    const weights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3
    };

    const score = 
      (summary.critical * weights.critical) +
      (summary.high * weights.high) +
      (summary.medium * weights.medium) +
      (summary.low * weights.low);

    return Math.min(100, score);
  }

  /**
   * Get risk level from score
   */
  getRiskLevel(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  /**
   * Generate recommendations based on vulnerabilities
   */
  generateRecommendations(scanResult) {
    const recommendations = [];
    const vulnTypes = new Set(scanResult.vulnerabilities.map(v => v.type));

    if (vulnTypes.has('SQL Injection')) {
      recommendations.push({
        title: 'Implement Parameterized Queries',
        description: 'Use prepared statements or parameterized queries to prevent SQL injection attacks. Never concatenate user input directly into SQL queries.'
      });
    }

    if (vulnTypes.has('XSS Vulnerability')) {
      recommendations.push({
        title: 'Sanitize User Input',
        description: 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers to mitigate XSS attacks.'
      });
    }

    if (vulnTypes.has('Missing Security Headers')) {
      recommendations.push({
        title: 'Add Security Headers',
        description: 'Implement security headers like X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, and Content-Security-Policy.'
      });
    }

    if (vulnTypes.has('CORS Misconfiguration')) {
      recommendations.push({
        title: 'Configure CORS Properly',
        description: 'Avoid using wildcard (*) in Access-Control-Allow-Origin. Specify exact origins and validate them server-side.'
      });
    }

    if (vulnTypes.has('Sensitive Data Exposure')) {
      recommendations.push({
        title: 'Protect Sensitive Data',
        description: 'Never expose API keys, tokens, or credentials in responses. Use environment variables and secure vaults for secrets.'
      });
    }

    if (scanResult.summary.critical > 0 || scanResult.summary.high > 0) {
      recommendations.push({
        title: 'Immediate Action Required',
        description: 'Critical and high severity vulnerabilities require immediate attention. Prioritize fixing these issues before deployment.'
      });
    }

    return recommendations;
  }

  /**
   * Escape HTML special characters
   */
  escapeHtml(text) {
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
  }
}

export default new ReportGenerator();
