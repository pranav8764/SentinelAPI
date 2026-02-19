import { useState, useEffect } from 'react';
import Layout from '../components/Layout';
import { apiKeysAPI } from '../services/api';

function ApiKeys({ user, onLogout }) {
  const [apiKeys, setApiKeys] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newKey, setNewKey] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    permissions: ['read', 'scan'],
    expiresInDays: 90,
  });

  useEffect(() => {
    fetchApiKeys();
  }, []);

  const fetchApiKeys = async () => {
    try {
      const response = await apiKeysAPI.getAll();
      setApiKeys(response.data.apiKeys);
    } catch (error) {
      console.error('Failed to fetch API keys:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const response = await apiKeysAPI.create(formData);
      setNewKey(response.data.apiKey);
      setFormData({ name: '', permissions: ['read', 'scan'], expiresInDays: 90 });
      fetchApiKeys();
    } catch (error) {
      console.error('Failed to create API key:', error);
    }
  };

  const handleDelete = async (id) => {
    if (!confirm('Are you sure you want to delete this API key?')) return;
    
    try {
      await apiKeysAPI.delete(id);
      fetchApiKeys();
    } catch (error) {
      console.error('Failed to delete API key:', error);
    }
  };

  const handleToggleActive = async (id, isActive) => {
    try {
      await apiKeysAPI.update(id, { isActive: !isActive });
      fetchApiKeys();
    } catch (error) {
      console.error('Failed to update API key:', error);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  const permissionOptions = [
    { value: 'read', label: 'Read', description: 'View data and logs' },
    { value: 'write', label: 'Write', description: 'Modify configurations' },
    { value: 'scan', label: 'Scan', description: 'Run security scans' },
    { value: 'test', label: 'Test', description: 'Run auth tests' },
    { value: 'admin', label: 'Admin', description: 'Full access' },
  ];

  return (
    <Layout user={user} onLogout={onLogout}>
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">API Keys</h1>
            <p className="text-slate-400">Manage API keys for programmatic access</p>
          </div>
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 transition-all"
          >
            + Create API Key
          </button>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500 mx-auto"></div>
          </div>
        ) : apiKeys.length === 0 ? (
          <div className="bg-slate-800 rounded-xl p-12 text-center border border-slate-700">
            <svg className="w-16 h-16 mx-auto mb-4 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
            <h3 className="text-xl font-bold text-white mb-2">No API Keys</h3>
            <p className="text-slate-400 mb-4">Create your first API key to get started</p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="px-6 py-2 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 transition-all"
            >
              Create API Key
            </button>
          </div>
        ) : (
          <div className="grid gap-4">
            {apiKeys.map((key) => (
              <div key={key._id} className="bg-slate-800 rounded-xl p-6 border border-slate-700">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h3 className="text-lg font-bold text-white">{key.name}</h3>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        key.isActive ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                      }`}>
                        {key.isActive ? 'Active' : 'Inactive'}
                      </span>
                      {key.isExpired && (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-orange-500/20 text-orange-400">
                          Expired
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-2 mb-3">
                      <code className="px-3 py-1 bg-slate-900 rounded text-sm text-slate-300 font-mono">
                        {key.key}
                      </code>
                      <button
                        onClick={() => copyToClipboard(key.key)}
                        className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                        title="Copy to clipboard"
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                    <div className="flex flex-wrap gap-2 mb-3">
                      {key.permissions.map((perm) => (
                        <span key={perm} className="px-2 py-1 bg-cyan-500/20 text-cyan-400 rounded text-xs font-medium">
                          {perm}
                        </span>
                      ))}
                    </div>
                    <div className="grid grid-cols-2 gap-4 text-sm text-slate-400">
                      <div>
                        <span className="font-medium">Created:</span> {new Date(key.createdAt).toLocaleDateString()}
                      </div>
                      {key.expiresAt && (
                        <div>
                          <span className="font-medium">Expires:</span> {new Date(key.expiresAt).toLocaleDateString()}
                        </div>
                      )}
                      <div>
                        <span className="font-medium">Usage:</span> {key.usageCount} requests
                      </div>
                      {key.lastUsed && (
                        <div>
                          <span className="font-medium">Last used:</span> {new Date(key.lastUsed).toLocaleDateString()}
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => handleToggleActive(key._id, key.isActive)}
                      className="p-2 text-slate-400 hover:text-yellow-400 transition-colors"
                      title={key.isActive ? 'Deactivate' : 'Activate'}
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                      </svg>
                    </button>
                    <button
                      onClick={() => handleDelete(key._id)}
                      className="p-2 text-slate-400 hover:text-red-400 transition-colors"
                      title="Delete"
                    >
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Create Modal */}
        {showCreateModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
            <div className="bg-slate-800 rounded-xl p-6 max-w-md w-full border border-slate-700">
              <h2 className="text-2xl font-bold text-white mb-4">Create API Key</h2>
              
              {newKey ? (
                <div className="space-y-4">
                  <div className="p-4 bg-green-500/10 border border-green-500/50 rounded-lg">
                    <p className="text-green-400 font-medium mb-2">✓ API Key Created!</p>
                    <p className="text-sm text-slate-300 mb-3">
                      Save this key securely. You won't be able to see it again.
                    </p>
                    <div className="flex items-center space-x-2">
                      <code className="flex-1 px-3 py-2 bg-slate-900 rounded text-sm text-slate-300 font-mono break-all">
                        {newKey.key}
                      </code>
                      <button
                        onClick={() => copyToClipboard(newKey.key)}
                        className="p-2 text-slate-400 hover:text-cyan-400 transition-colors"
                      >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setNewKey(null);
                      setShowCreateModal(false);
                    }}
                    className="w-full py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600 transition-colors"
                  >
                    Close
                  </button>
                </div>
              ) : (
                <form onSubmit={handleCreate} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Name</label>
                    <input
                      type="text"
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      placeholder="My API Key"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Permissions</label>
                    <div className="space-y-2">
                      {permissionOptions.map((option) => (
                        <label key={option.value} className="flex items-start space-x-3 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={formData.permissions.includes(option.value)}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setFormData({
                                  ...formData,
                                  permissions: [...formData.permissions, option.value]
                                });
                              } else {
                                setFormData({
                                  ...formData,
                                  permissions: formData.permissions.filter(p => p !== option.value)
                                });
                              }
                            }}
                            className="mt-1"
                          />
                          <div>
                            <div className="text-white font-medium">{option.label}</div>
                            <div className="text-xs text-slate-400">{option.description}</div>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-300 mb-2">Expires In (Days)</label>
                    <input
                      type="number"
                      value={formData.expiresInDays}
                      onChange={(e) => setFormData({ ...formData, expiresInDays: parseInt(e.target.value) })}
                      className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                      min="1"
                      max="365"
                    />
                    <p className="text-xs text-slate-400 mt-1">Set to 0 for no expiration</p>
                  </div>

                  <div className="flex space-x-3">
                    <button
                      type="submit"
                      className="flex-1 py-2 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 transition-all"
                    >
                      Create
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowCreateModal(false)}
                      className="flex-1 py-2 bg-slate-700 text-white rounded-lg hover:bg-slate-600 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}

export default ApiKeys;
