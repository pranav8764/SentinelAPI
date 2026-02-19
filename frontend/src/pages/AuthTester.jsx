import { useState } from 'react';
import Layout from '../components/Layout';
import { authTestAPI } from '../services/api';

function AuthTester({ user, onLogout }) {
  const [activeTab, setActiveTab] = useState('oauth');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  // OAuth 2.0 State
  const [oauthConfig, setOauthConfig] = useState({
    grantType: 'authorization_code',
    clientId: '',
    clientSecret: '',
    redirectUri: '',
    authorizationUrl: '',
    tokenUrl: '',
    scope: '',
    code: '',
    refreshToken: '',
  });

  // API Key State
  const [apiKeyConfig, setApiKeyConfig] = useState({
    url: '',
    method: 'GET',
    apiKey: '',
    keyLocation: 'header',
    keyName: 'X-API-Key',
    additionalHeaders: '',
  });

  // Session State
  const [sessionConfig, setSessionConfig] = useState({
    url: '',
    method: 'GET',
    sessionId: '',
    cookieName: 'session',
    additionalCookies: '',
  });

  // JWT State
  const [jwtConfig, setJwtConfig] = useState({
    url: '',
    method: 'GET',
    token: '',
    tokenLocation: 'header',
    headerName: 'Authorization',
    headerPrefix: 'Bearer',
  });

  const testOAuth = async () => {
    setLoading(true);
    setResult(null);
    try {
      const response = await authTestAPI.testOAuth(oauthConfig);
      setResult({
        success: true,
        data: response.data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      setResult({
        success: false,
        error: error.response?.data || error.message,
        timestamp: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  };

  const testApiKey = async () => {
    setLoading(true);
    setResult(null);
    try {
      const response = await authTestAPI.testApiKey(apiKeyConfig);
      setResult({
        success: true,
        data: response.data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      setResult({
        success: false,
        error: error.response?.data || error.message,
        timestamp: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  };

  const testSession = async () => {
    setLoading(true);
    setResult(null);
    try {
      const response = await authTestAPI.testSession(sessionConfig);
      setResult({
        success: true,
        data: response.data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      setResult({
        success: false,
        error: error.response?.data || error.message,
        timestamp: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  };

  const testJWT = async () => {
    setLoading(true);
    setResult(null);
    try {
      const response = await authTestAPI.testJWT(jwtConfig);
      setResult({
        success: true,
        data: response.data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      setResult({
        success: false,
        error: error.response?.data || error.message,
        timestamp: new Date().toISOString(),
      });
    } finally {
      setLoading(false);
    }
  };

  const renderOAuthTab = () => (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Grant Type</label>
        <select
          value={oauthConfig.grantType}
          onChange={(e) => setOauthConfig({ ...oauthConfig, grantType: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="authorization_code">Authorization Code</option>
          <option value="client_credentials">Client Credentials</option>
          <option value="refresh_token">Refresh Token</option>
          <option value="password">Password (Resource Owner)</option>
        </select>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Client ID</label>
          <input
            type="text"
            value={oauthConfig.clientId}
            onChange={(e) => setOauthConfig({ ...oauthConfig, clientId: e.target.value })}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="your-client-id"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Client Secret</label>
          <input
            type="password"
            value={oauthConfig.clientSecret}
            onChange={(e) => setOauthConfig({ ...oauthConfig, clientSecret: e.target.value })}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="your-client-secret"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Authorization URL</label>
        <input
          type="url"
          value={oauthConfig.authorizationUrl}
          onChange={(e) => setOauthConfig({ ...oauthConfig, authorizationUrl: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="https://provider.com/oauth/authorize"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Token URL</label>
        <input
          type="url"
          value={oauthConfig.tokenUrl}
          onChange={(e) => setOauthConfig({ ...oauthConfig, tokenUrl: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="https://provider.com/oauth/token"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Redirect URI</label>
        <input
          type="url"
          value={oauthConfig.redirectUri}
          onChange={(e) => setOauthConfig({ ...oauthConfig, redirectUri: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="http://localhost:3000/callback"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Scope</label>
        <input
          type="text"
          value={oauthConfig.scope}
          onChange={(e) => setOauthConfig({ ...oauthConfig, scope: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="read write"
        />
      </div>

      {oauthConfig.grantType === 'authorization_code' && (
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Authorization Code</label>
          <input
            type="text"
            value={oauthConfig.code}
            onChange={(e) => setOauthConfig({ ...oauthConfig, code: e.target.value })}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="authorization-code"
          />
        </div>
      )}

      {oauthConfig.grantType === 'refresh_token' && (
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Refresh Token</label>
          <input
            type="text"
            value={oauthConfig.refreshToken}
            onChange={(e) => setOauthConfig({ ...oauthConfig, refreshToken: e.target.value })}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            placeholder="refresh-token"
          />
        </div>
      )}

      <button
        onClick={testOAuth}
        disabled={loading}
        className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
      >
        {loading ? 'Testing...' : 'Test OAuth 2.0'}
      </button>
    </div>
  );

  const renderApiKeyTab = () => (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Target URL</label>
        <input
          type="url"
          value={apiKeyConfig.url}
          onChange={(e) => setApiKeyConfig({ ...apiKeyConfig, url: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="https://api.example.com/endpoint"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">HTTP Method</label>
          <select
            value={apiKeyConfig.method}
            onChange={(e) => setApiKeyConfig({ ...apiKeyConfig, method: e.target.value })}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-300 mb-2">Key Location</label>
          <select
            value={apiKeyConfig.keyLocation}
            onChange={(e) => setApiKeyConfig({ ...apiKeyConfig, keyLocation: e.target.value })}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="header">Header</option>
            <option value="query">Query Parameter</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">
          {apiKeyConfig.keyLocation === 'header' ? 'Header Name' : 'Query Parameter Name'}
        </label>
        <input
          type="text"
          value={apiKeyConfig.keyName}
          onChange={(e) => setApiKeyConfig({ ...apiKeyConfig, keyName: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder={apiKeyConfig.keyLocation === 'header' ? 'X-API-Key' : 'api_key'}
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">API Key</label>
        <input
          type="password"
          value={apiKeyConfig.apiKey}
          onChange={(e) => setApiKeyConfig({ ...apiKeyConfig, apiKey: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="your-api-key"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">
          Additional Headers (JSON)
        </label>
        <textarea
          value={apiKeyConfig.additionalHeaders}
          onChange={(e) => setApiKeyConfig({ ...apiKeyConfig, additionalHeaders: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
          placeholder='{"Content-Type": "application/json"}'
          rows={3}
        />
      </div>

      <button
        onClick={testApiKey}
        disabled={loading}
        className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
      >
        {loading ? 'Testing...' : 'Test API Key'}
      </button>
    </div>
  );

  const renderSessionTab = () => (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Target URL</label>
        <input
          type="url"
          value={sessionConfig.url}
          onChange={(e) => setSessionConfig({ ...sessionConfig, url: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="https://api.example.com/endpoint"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">HTTP Method</label>
        <select
          value={sessionConfig.method}
          onChange={(e) => setSessionConfig({ ...sessionConfig, method: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Cookie Name</label>
        <input
          type="text"
          value={sessionConfig.cookieName}
          onChange={(e) => setSessionConfig({ ...sessionConfig, cookieName: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="session"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Session ID</label>
        <input
          type="text"
          value={sessionConfig.sessionId}
          onChange={(e) => setSessionConfig({ ...sessionConfig, sessionId: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="session-id-value"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">
          Additional Cookies (key=value; separated)
        </label>
        <textarea
          value={sessionConfig.additionalCookies}
          onChange={(e) => setSessionConfig({ ...sessionConfig, additionalCookies: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
          placeholder="csrf_token=abc123; user_pref=dark"
          rows={3}
        />
      </div>

      <button
        onClick={testSession}
        disabled={loading}
        className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
      >
        {loading ? 'Testing...' : 'Test Session'}
      </button>
    </div>
  );

  const renderJWTTab = () => (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Target URL</label>
        <input
          type="url"
          value={jwtConfig.url}
          onChange={(e) => setJwtConfig({ ...jwtConfig, url: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          placeholder="https://api.example.com/endpoint"
        />
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">HTTP Method</label>
        <select
          value={jwtConfig.method}
          onChange={(e) => setJwtConfig({ ...jwtConfig, method: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>
      </div>

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Token Location</label>
        <select
          value={jwtConfig.tokenLocation}
          onChange={(e) => setJwtConfig({ ...jwtConfig, tokenLocation: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          <option value="header">Header</option>
          <option value="cookie">Cookie</option>
        </select>
      </div>

      {jwtConfig.tokenLocation === 'header' && (
        <>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Header Name</label>
            <input
              type="text"
              value={jwtConfig.headerName}
              onChange={(e) => setJwtConfig({ ...jwtConfig, headerName: e.target.value })}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              placeholder="Authorization"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Header Prefix</label>
            <input
              type="text"
              value={jwtConfig.headerPrefix}
              onChange={(e) => setJwtConfig({ ...jwtConfig, headerPrefix: e.target.value })}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              placeholder="Bearer"
            />
          </div>
        </>
      )}

      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">JWT Token</label>
        <textarea
          value={jwtConfig.token}
          onChange={(e) => setJwtConfig({ ...jwtConfig, token: e.target.value })}
          className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono text-sm"
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          rows={4}
        />
      </div>

      <button
        onClick={testJWT}
        disabled={loading}
        className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
      >
        {loading ? 'Testing...' : 'Test JWT'}
      </button>
    </div>
  );

  return (
    <Layout user={user} onLogout={onLogout}>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Authentication Tester</h1>
          <p className="text-slate-400">Test OAuth 2.0, API Keys, Sessions, and JWT authentication</p>
        </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <div className="flex space-x-2 mb-6 border-b border-slate-700">
            {['oauth', 'apikey', 'session', 'jwt'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 font-medium transition-colors ${
                  activeTab === tab
                    ? 'text-cyan-400 border-b-2 border-cyan-400'
                    : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                {tab === 'oauth' && 'OAuth 2.0'}
                {tab === 'apikey' && 'API Key'}
                {tab === 'session' && 'Session'}
                {tab === 'jwt' && 'JWT'}
              </button>
            ))}
          </div>

          {activeTab === 'oauth' && renderOAuthTab()}
          {activeTab === 'apikey' && renderApiKeyTab()}
          {activeTab === 'session' && renderSessionTab()}
          {activeTab === 'jwt' && renderJWTTab()}
        </div>

        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold text-white mb-4">Test Results</h2>
          {!result ? (
            <div className="text-center py-12 text-slate-400">
              <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <p>No test results yet</p>
              <p className="text-sm mt-2">Configure and run a test to see results</p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className={`p-4 rounded-lg border ${result.success ? 'bg-green-500/10 border-green-500/50' : 'bg-red-500/10 border-red-500/50'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className={`font-medium ${result.success ? 'text-green-400' : 'text-red-400'}`}>
                    {result.success ? '✓ Test Passed' : '✗ Test Failed'}
                  </span>
                  <span className="text-xs text-slate-400">{new Date(result.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>

              <div className="bg-slate-900 rounded-lg p-4 overflow-auto max-h-96">
                <pre className="text-sm text-slate-300 whitespace-pre-wrap">
                  {JSON.stringify(result.success ? result.data : result.error, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
      </div>
    </Layout>
  );
}

export default AuthTester;
