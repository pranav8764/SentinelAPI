import { useState, useEffect } from 'react';
import { adminAPI } from '../services/api';
import Layout from '../components/Layout';

function Settings({ user, onLogout }) {
  const [rateLimit, setRateLimit] = useState({ windowMs: 60000, max: 100, message: '' });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });

  useEffect(() => {
    fetchSettings();
  }, []);

  const fetchSettings = async () => {
    try {
      const response = await adminAPI.getRateLimit();
      setRateLimit(response.data.config);
    } catch (error) {
      console.error('Error fetching settings:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setMessage({ type: '', text: '' });

    try {
      await adminAPI.updateRateLimit(rateLimit);
      setMessage({ type: 'success', text: 'Settings saved successfully!' });
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.error || 'Failed to save settings' });
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <Layout user={user} onLogout={onLogout}>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout user={user} onLogout={onLogout}>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-white">Settings</h1>
          <p className="text-slate-400 mt-1">Configure security and rate limiting</p>
        </div>

        {message.text && (
          <div className={`p-4 rounded-lg border ${
            message.type === 'success'
              ? 'bg-green-500/10 border-green-500/50 text-green-400'
              : 'bg-red-500/10 border-red-500/50 text-red-400'
          }`}>
            {message.text}
          </div>
        )}

        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold text-white mb-6">Rate Limiting</h2>

          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Time Window (milliseconds)
              </label>
              <input
                type="number"
                value={rateLimit.windowMs}
                onChange={(e) => setRateLimit({ ...rateLimit, windowMs: parseInt(e.target.value) })}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                min="1000"
                max="3600000"
              />
              <p className="mt-1 text-sm text-slate-400">
                Current: {(rateLimit.windowMs / 1000).toFixed(0)} seconds ({(rateLimit.windowMs / 60000).toFixed(1)} minutes)
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Maximum Requests
              </label>
              <input
                type="number"
                value={rateLimit.max}
                onChange={(e) => setRateLimit({ ...rateLimit, max: parseInt(e.target.value) })}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                min="1"
                max="10000"
              />
              <p className="mt-1 text-sm text-slate-400">
                Maximum number of requests allowed per time window
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Error Message (Optional)
              </label>
              <input
                type="text"
                value={rateLimit.message || ''}
                onChange={(e) => setRateLimit({ ...rateLimit, message: e.target.value })}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                placeholder="Too many requests, please try again later"
              />
              <p className="mt-1 text-sm text-slate-400">
                Custom message shown when rate limit is exceeded
              </p>
            </div>

            <div className="pt-4 border-t border-slate-700">
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-indigo-500 text-white font-medium rounded-lg hover:from-cyan-600 hover:to-indigo-600 focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {saving ? 'Saving...' : 'Save Settings'}
              </button>
            </div>
          </div>
        </div>

        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold text-white mb-4">User Information</h2>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-slate-400">Username</span>
              <span className="text-white font-medium">{user.username}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Email</span>
              <span className="text-white font-medium">{user.email}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Role</span>
              <span className="px-2 py-1 text-xs font-medium bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 rounded capitalize">
                {user.role}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Permissions</span>
              <div className="flex flex-wrap gap-2">
                {user.permissions?.map((perm) => (
                  <span key={perm} className="px-2 py-1 text-xs font-medium bg-slate-700 text-slate-300 rounded">
                    {perm.replace('_', ' ')}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

export default Settings;
