import { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import Layout from '../components/Layout';
import { monitoringAPI } from '../services/api';

function LiveMonitoring({ user, onLogout }) {
  const [connected, setConnected] = useState(false);
  const [metrics, setMetrics] = useState(null);
  const [recentRequests, setRecentRequests] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [timeSeriesData, setTimeSeriesData] = useState([]);
  const socketRef = useRef(null);

  useEffect(() => {
    const socketUrl = import.meta.env.VITE_API_URL?.replace('/api', '') || 'http://localhost:5000';
    
    // Connect to Socket.IO
    const socket = io(socketUrl, {
      auth: {
        token: localStorage.getItem('token')
      },
      transports: ['websocket', 'polling']
    });

    socketRef.current = socket;

    socket.on('connect', () => {
      setConnected(true);
    });

    socket.on('disconnect', () => {
      setConnected(false);
    });

    // Listen for real-time events
    socket.on('request:new', (data) => {
      setRecentRequests(prev => [data, ...prev].slice(0, 50));
    });

    socket.on('metrics:update', (data) => {
      setMetrics(data);
    });

    socket.on('alert:security', (data) => {
      setAlerts(prev => [data, ...prev].slice(0, 20));
    });

    // Fetch initial data
    fetchTimeSeriesData();
    fetchRecentActivity();

    return () => {
      socket.disconnect();
    };
  }, []);

  const fetchTimeSeriesData = async () => {
    try {
      const response = await monitoringAPI.getTimeSeries(24);
      setTimeSeriesData(response.data.timeseries);
    } catch (error) {
      console.error('Error fetching time series:', error);
    }
  };

  const fetchRecentActivity = async () => {
    try {
      const response = await monitoringAPI.getRecentActivity(50);
      setRecentRequests(response.data.requests);
    } catch (error) {
      console.error('Error fetching recent activity:', error);
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      default: return 'text-green-500';
    }
  };

  const getStatusColor = (code) => {
    if (code >= 500) return 'text-red-500';
    if (code >= 400) return 'text-orange-500';
    if (code >= 300) return 'text-blue-500';
    return 'text-green-500';
  };

  return (
    <Layout user={user} onLogout={onLogout}>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-white">Live Monitoring</h1>
            <p className="text-slate-400 mt-1">Real-time API security monitoring</p>
          </div>
          <div className="flex items-center gap-2">
            <div className={`w-3 h-3 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'} animate-pulse`}></div>
            <span className="text-slate-400">{connected ? 'Connected' : 'Disconnected'}</span>
          </div>
        </div>

        {/* Real-time Metrics */}
        {metrics && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <MetricCard
              title="Requests/Min"
              value={metrics.requestsPerMinute}
              icon="📊"
              color="blue"
            />
            <MetricCard
              title="Blocked/Min"
              value={metrics.blockedPerMinute}
              icon="🛡️"
              color="red"
            />
            <MetricCard
              title="Avg Response"
              value={`${Math.round(metrics.avgResponseTime)}ms`}
              icon="⚡"
              color="yellow"
            />
            <MetricCard
              title="Active Connections"
              value={metrics.activeConnections}
              icon="🔌"
              color="green"
            />
          </div>
        )}

        {/* Threat Distribution */}
        {metrics?.threatDistribution && (
          <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Threat Distribution (Last Minute)</h2>
            <div className="grid grid-cols-4 gap-4">
              <ThreatBadge level="low" count={metrics.threatDistribution.low} />
              <ThreatBadge level="medium" count={metrics.threatDistribution.medium} />
              <ThreatBadge level="high" count={metrics.threatDistribution.high} />
              <ThreatBadge level="critical" count={metrics.threatDistribution.critical} />
            </div>
          </div>
        )}

        {/* Security Alerts */}
        {alerts.length > 0 && (
          <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
            <h2 className="text-xl font-bold text-white mb-4">Security Alerts</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {alerts.map((alert, index) => (
                <div
                  key={index}
                  className={`p-3 rounded-lg border ${
                    alert.severity === 'critical' ? 'bg-red-900/20 border-red-700' :
                    alert.severity === 'high' ? 'bg-orange-900/20 border-orange-700' :
                    'bg-yellow-900/20 border-yellow-700'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`font-semibold ${getThreatColor(alert.severity)}`}>
                          {alert.severity.toUpperCase()}
                        </span>
                        <span className="text-slate-400 text-sm">
                          {new Date(alert.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="text-white mt-1">{alert.message}</p>
                      <p className="text-slate-400 text-sm mt-1">IP: {alert.ip}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recent Requests */}
        <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
          <h2 className="text-xl font-bold text-white mb-4">Recent Requests</h2>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-700">
                  <th className="pb-3 font-medium">Time</th>
                  <th className="pb-3 font-medium">Method</th>
                  <th className="pb-3 font-medium">URL</th>
                  <th className="pb-3 font-medium">IP</th>
                  <th className="pb-3 font-medium">Status</th>
                  <th className="pb-3 font-medium">Response</th>
                  <th className="pb-3 font-medium">Threat</th>
                  <th className="pb-3 font-medium">Blocked</th>
                </tr>
              </thead>
              <tbody className="text-slate-300">
                {recentRequests.map((req, index) => (
                  <tr key={index} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                    <td className="py-3 text-sm">
                      {new Date(req.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        req.method === 'GET' ? 'bg-blue-900/30 text-blue-400' :
                        req.method === 'POST' ? 'bg-green-900/30 text-green-400' :
                        req.method === 'PUT' ? 'bg-yellow-900/30 text-yellow-400' :
                        req.method === 'DELETE' ? 'bg-red-900/30 text-red-400' :
                        'bg-slate-700 text-slate-400'
                      }`}>
                        {req.method}
                      </span>
                    </td>
                    <td className="py-3 text-sm truncate max-w-xs">{req.url}</td>
                    <td className="py-3 text-sm">{req.ip}</td>
                    <td className={`py-3 font-medium ${getStatusColor(req.statusCode)}`}>
                      {req.statusCode}
                    </td>
                    <td className="py-3 text-sm">{req.responseTime}ms</td>
                    <td className={`py-3 font-medium ${getThreatColor(req.threatLevel)}`}>
                      {req.threatLevel}
                    </td>
                    <td className="py-3">
                      {req.blocked ? (
                        <span className="text-red-500">🛑</span>
                      ) : (
                        <span className="text-green-500">✓</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </Layout>
  );
}

function MetricCard({ title, value, icon, color }) {
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

function ThreatBadge({ level, count }) {
  const colors = {
    low: 'bg-green-900/30 text-green-400 border-green-700',
    medium: 'bg-yellow-900/30 text-yellow-400 border-yellow-700',
    high: 'bg-orange-900/30 text-orange-400 border-orange-700',
    critical: 'bg-red-900/30 text-red-400 border-red-700'
  };

  return (
    <div className={`p-4 rounded-lg border ${colors[level]}`}>
      <div className="text-2xl font-bold">{count}</div>
      <div className="text-sm capitalize mt-1">{level}</div>
    </div>
  );
}

export default LiveMonitoring;
