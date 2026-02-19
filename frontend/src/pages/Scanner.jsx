import { useState } from 'react';
import Layout from '../components/Layout';
import api from '../services/api';

function Scanner({ user, onLogout }) {
  const [formData, setFormData] = useState({
    url: '',
    method: 'GET',
    authType: 'none',
    authConfig: {
      token: '',
      key: '',
      value: '',
      username: '',
      password: ''
    },
    headers: {},
    body: ''
  });

  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    setError('');
    setScanning(true);
    setResults(null);

    // Validate URL format
    if (!formData.url.startsWith('http://') && !formData.url.startsWith('https://')) {
      setError('URL must start with http:// or https://');
      setScanning(false);
      return;
    }

    try {
      // Parse body if provided
      let parsedBody = null;
      if (formData.body && formData.body.trim()) {
        try {
          parsedBody = JSON.parse(formData.body);
        } catch (jsonError) {
          setError('Invalid JSON in request body');
          setScanning(false);
          return;
        }
      }

      const response = await api.post('/scanner/scan', {
        url: formData.url,
        method: formData.method,
        authType: formData.authType,
        authConfig: formData.authConfig,
        headers: formData.headers,
        body: parsedBody
      }, {
        timeout: 60000 // 60 seconds for scanner (scans can take time)
      });

      setResults(response.data.results);
    } catch (err) {
      const errorMessage = err.response?.data?.error || err.response?.data?.message || err.message || 'Scan failed. Please try again.';
      const errorDetails = err.response?.data?.details ? ` (${err.response.data.details})` : '';
      setError(errorMessage + errorDetails);
    } finally {
      setScanning(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-400 bg-red-500/10 border-red-500/50',
      high: 'text-orange-400 bg-orange-500/10 border-orange-500/50',
      medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/50',
      low: 'text-blue-400 bg-blue-500/10 border-blue-500/50'
    };
    return colors[severity] || colors.low;
  };

  return (
    <Layout user={user} onLogout={onLogout}>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Endpoint Scanner</h1>
          <p className="text-slate-400 mt-1">Scan individual API endpoints for security vulnerabilities</p>
        </div>

        {/* Scan Form */}
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
          <form onSubmit={handleScan} className="space-y-4">
            {/* URL Input */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Endpoint URL
              </label>
              <input
                type="text"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                placeholder="https://api.example.com/endpoint"
                required
              />
              <p className="text-xs text-slate-400 mt-1">Must include protocol (http:// or https://)</p>
            </div>

            {/* Method Selection */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                HTTP Method
              </label>
              <select
                value={formData.method}
                onChange={(e) => setFormData({ ...formData, method: e.target.value })}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </select>
            </div>

            {/* Authentication Type */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Authentication
              </label>
              <select
                value={formData.authType}
                onChange={(e) => setFormData({ ...formData, authType: e.target.value })}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="none">None</option>
                <option value="bearer">Bearer Token</option>
                <option value="apikey">API Key</option>
                <option value="basic">Basic Auth</option>
              </select>
            </div>

            {/* Auth Config */}
            {formData.authType === 'bearer' && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Bearer Token
                </label>
                <input
                  type="text"
                  value={formData.authConfig.token}
                  onChange={(e) => setFormData({
                    ...formData,
                    authConfig: { ...formData.authConfig, token: e.target.value }
                  })}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  placeholder="Enter bearer token"
                />
              </div>
            )}

            {formData.authType === 'apikey' && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Header Name
                  </label>
                  <input
                    type="text"
                    value={formData.authConfig.key}
                    onChange={(e) => setFormData({
                      ...formData,
                      authConfig: { ...formData.authConfig, key: e.target.value }
                    })}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    placeholder="X-API-Key"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    API Key Value
                  </label>
                  <input
                    type="text"
                    value={formData.authConfig.value}
                    onChange={(e) => setFormData({
                      ...formData,
                      authConfig: { ...formData.authConfig, value: e.target.value }
                    })}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    placeholder="Enter API key"
                  />
                </div>
              </div>
            )}

            {formData.authType === 'basic' && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Username
                  </label>
                  <input
                    type="text"
                    value={formData.authConfig.username}
                    onChange={(e) => setFormData({
                      ...formData,
                      authConfig: { ...formData.authConfig, username: e.target.value }
                    })}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    placeholder="Username"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Password
                  </label>
                  <input
                    type="password"
                    value={formData.authConfig.password}
                    onChange={(e) => setFormData({
                      ...formData,
                      authConfig: { ...formData.authConfig, password: e.target.value }
                    })}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    placeholder="Password"
                  />
                </div>
              </div>
            )}

            {/* Request Body */}
            {['POST', 'PUT', 'PATCH'].includes(formData.method) && (
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-2">
                  Request Body (JSON)
                </label>
                <textarea
                  value={formData.body}
                  onChange={(e) => setFormData({ ...formData, body: e.target.value })}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
                  rows="4"
                  placeholder='{"key": "value"}'
                />
              </div>
            )}

            {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/50 rounded-lg text-red-400 text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={scanning}
              className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {scanning ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Scanning...
                </span>
              ) : (
                'Start Scan'
              )}
            </button>
          </form>
        </div>

        {/* Results */}
        {results && (
          <div className="space-y-6">
            {/* Summary */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h2 className="text-xl font-bold text-white mb-4">Scan Summary</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm">Response Time</div>
                  <div className="text-2xl font-bold text-white mt-1">{results.responseTime}ms</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm">Status Code</div>
                  <div className="text-2xl font-bold text-white mt-1">{results.statusCode || 'N/A'}</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm">Tests Passed</div>
                  <div className="text-2xl font-bold text-green-400 mt-1">{results.passed}</div>
                </div>
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm">Tests Failed</div>
                  <div className="text-2xl font-bold text-red-400 mt-1">{results.failed}</div>
                </div>
              </div>

              <div className="mt-6 grid grid-cols-2 md:grid-cols-5 gap-4">
                <div className="bg-slate-700/50 rounded-lg p-4">
                  <div className="text-slate-400 text-sm">Total Issues</div>
                  <div className="text-2xl font-bold text-white mt-1">{results.summary.total}</div>
                </div>
                <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4">
                  <div className="text-red-400 text-sm">Critical</div>
                  <div className="text-2xl font-bold text-red-400 mt-1">{results.summary.critical}</div>
                </div>
                <div className="bg-orange-500/10 border border-orange-500/50 rounded-lg p-4">
                  <div className="text-orange-400 text-sm">High</div>
                  <div className="text-2xl font-bold text-orange-400 mt-1">{results.summary.high}</div>
                </div>
                <div className="bg-yellow-500/10 border border-yellow-500/50 rounded-lg p-4">
                  <div className="text-yellow-400 text-sm">Medium</div>
                  <div className="text-2xl font-bold text-yellow-400 mt-1">{results.summary.medium}</div>
                </div>
                <div className="bg-blue-500/10 border border-blue-500/50 rounded-lg p-4">
                  <div className="text-blue-400 text-sm">Low</div>
                  <div className="text-2xl font-bold text-blue-400 mt-1">{results.summary.low}</div>
                </div>
              </div>
            </div>

            {/* Vulnerabilities */}
            {results.vulnerabilities.length > 0 && (
              <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
                <h2 className="text-xl font-bold text-white mb-4">Vulnerabilities Found</h2>
                <div className="space-y-4">
                  {results.vulnerabilities.map((vuln, index) => (
                    <div key={index} className={`border rounded-lg p-4 ${getSeverityColor(vuln.severity)}`}>
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="font-bold text-lg">{vuln.type}</h3>
                        <span className="px-3 py-1 rounded-full text-xs font-medium uppercase">
                          {vuln.severity}
                        </span>
                      </div>
                      <p className="text-sm mb-3 opacity-90">{vuln.description}</p>
                      
                      {vuln.evidence && (
                        <div className="mb-3">
                          <div className="text-xs font-medium mb-1">Evidence:</div>
                          <div className="bg-slate-900/50 rounded p-2 text-xs font-mono">
                            {vuln.evidence}
                          </div>
                        </div>
                      )}
                      
                      {vuln.remediation && (
                        <div className="mb-3">
                          <div className="text-xs font-medium mb-1">Remediation:</div>
                          <div className="text-sm opacity-90">{vuln.remediation}</div>
                        </div>
                      )}
                      
                      <div className="flex gap-4 text-xs opacity-75">
                        {vuln.cwe && <span>CWE: {vuln.cwe}</span>}
                        {vuln.owasp && <span>OWASP: {vuln.owasp}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* All Tests */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
              <h2 className="text-xl font-bold text-white mb-4">All Tests</h2>
              <div className="space-y-2">
                {results.tests.map((test, index) => (
                  <div key={index} className="flex items-center justify-between p-3 bg-slate-700/50 rounded-lg">
                    <div className="flex items-center gap-3">
                      {test.passed ? (
                        <svg className="w-5 h-5 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                      ) : (
                        <svg className="w-5 h-5 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      )}
                      <div>
                        <div className="text-white font-medium">{test.name}</div>
                        <div className="text-slate-400 text-sm">{test.message}</div>
                      </div>
                    </div>
                    <span className="text-xs text-slate-500 uppercase">{test.category}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

export default Scanner;
