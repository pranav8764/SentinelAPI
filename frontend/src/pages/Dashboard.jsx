import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { adminAPI, proxyAPI } from '../services/api';
import Layout from '../components/Layout';

function Dashboard({ user, onLogout }) {
  const [stats, setStats] = useState(null);
  const [proxyHealth, setProxyHealth] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, proxyRes] = await Promise.all([
        adminAPI.getStats(),
        proxyAPI.getHealth(),
      ]);
      setStats(statsRes.data);
      setProxyHealth(proxyRes.data);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
    } finally {
      setLoading(false);
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
          <h1 className="text-3xl font-bold text-white">Dashboard</h1>
          <p className="text-slate-400 mt-1">Overview of your API security</p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            title="Total Requests"
            value={stats?.overview?.totalRequests?.toLocaleString() || '0'}
            icon="📊"
            color="blue"
          />
          <StatCard
            title="Blocked Requests"
            value={stats?.overview?.blockedRequests?.toLocaleString() || '0'}
            icon="🛡️"
            color="red"
          />
          <StatCard
            title="Block Rate"
            value={`${stats?.overview?.blockRate || '0'}%`}
            icon="📈"
            color="yellow"
          />
          <StatCard
            title="Proxy Status"
            value={proxyHealth?.proxy?.status === 'healthy' ? 'Healthy' : 'Down'}
            icon="🔌"
            color={proxyHealth?.proxy?.status === 'healthy' ? 'green' : 'red'}
          />
        </div>

        {/* Recent Activity */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Last 24 Hours</h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Requests</span>
                <span className="text-white font-semibold">{stats?.last24h?.requests?.toLocaleString() || '0'}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Blocked</span>
                <span className="text-red-400 font-semibold">{stats?.last24h?.blocked?.toLocaleString() || '0'}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-slate-400">Block Rate</span>
                <span className="text-yellow-400 font-semibold">{stats?.last24h?.blockRate || '0'}%</span>
              </div>
            </div>
          </div>

          <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Threat Levels</h2>
            <div className="space-y-3">
              {stats?.threatLevels && Object.entries(stats.threatLevels).map(([level, count]) => (
                <div key={level} className="flex justify-between items-center">
                  <span className="text-slate-400 capitalize">{level}</span>
                  <span className={`font-semibold ${
                    level === 'critical' ? 'text-red-400' :
                    level === 'high' ? 'text-orange-400' :
                    level === 'medium' ? 'text-yellow-400' :
                    'text-green-400'
                  }`}>
                    {count.toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold text-white mb-4">Quick Actions</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Link
              to="/logs"
              className="p-4 bg-slate-700 rounded-lg hover:bg-slate-600 transition-colors border border-slate-600"
            >
              <div className="text-2xl mb-2">📋</div>
              <h3 className="font-semibold text-white">View Logs</h3>
              <p className="text-sm text-slate-400 mt-1">Browse request logs</p>
            </Link>
            <Link
              to="/settings"
              className="p-4 bg-slate-700 rounded-lg hover:bg-slate-600 transition-colors border border-slate-600"
            >
              <div className="text-2xl mb-2">⚙️</div>
              <h3 className="font-semibold text-white">Settings</h3>
              <p className="text-sm text-slate-400 mt-1">Configure security</p>
            </Link>
            <button
              onClick={fetchData}
              className="p-4 bg-slate-700 rounded-lg hover:bg-slate-600 transition-colors border border-slate-600 text-left"
            >
              <div className="text-2xl mb-2">🔄</div>
              <h3 className="font-semibold text-white">Refresh Data</h3>
              <p className="text-sm text-slate-400 mt-1">Update statistics</p>
            </button>
          </div>
        </div>
      </div>
    </Layout>
  );
}

function StatCard({ title, value, icon, color }) {
  const colorClasses = {
    blue: 'from-blue-500 to-cyan-500',
    red: 'from-red-500 to-pink-500',
    yellow: 'from-yellow-500 to-orange-500',
    green: 'from-green-500 to-emerald-500',
  };

  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <div className={`w-12 h-12 rounded-lg bg-gradient-to-br ${colorClasses[color]} flex items-center justify-center text-2xl`}>
          {icon}
        </div>
      </div>
      <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
      <p className="text-3xl font-bold text-white mt-2">{value}</p>
    </div>
  );
}

export default Dashboard;
