import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Login from './pages/Login';
import Signup from './pages/Signup';
import Dashboard from './pages/Dashboard';
import Scanner from './pages/Scanner';
import AuthTester from './pages/AuthTester';
import ApiKeys from './pages/ApiKeys';
import Logs from './pages/Logs';
import Settings from './pages/Settings';
import LiveMonitoring from './pages/LiveMonitoring';
import VulnerabilityTester from './pages/VulnerabilityTester';
import { authAPI } from './services/api';

function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAuth();
  }, []);

  const checkAuth = async () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const response = await authAPI.getMe();
        setUser(response.data.user);
      } catch (error) {
        console.error('Auth check failed:', error);
        localStorage.removeItem('token');
      }
    }
    setLoading(false);
  };

  const handleLogin = (userData, token) => {
    localStorage.setItem('token', token);
    setUser(userData);
  };

  const handleSignup = (userData, token) => {
    localStorage.setItem('token', token);
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500 mx-auto"></div>
          <p className="mt-4 text-slate-400">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        <Route
          path="/login"
          element={user ? <Navigate to="/" /> : <Login onLogin={handleLogin} />}
        />
        <Route
          path="/signup"
          element={user ? <Navigate to="/" /> : <Signup onSignup={handleSignup} />}
        />
        <Route
          path="/"
          element={user ? <Dashboard user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/scanner"
          element={user ? <Scanner user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/auth-tester"
          element={user ? <AuthTester user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/api-keys"
          element={user ? <ApiKeys user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/logs"
          element={user ? <Logs user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/settings"
          element={user ? <Settings user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/monitoring"
          element={user ? <LiveMonitoring user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        <Route
          path="/vulnerability"
          element={user ? <VulnerabilityTester user={user} onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
      </Routes>
    </Router>
  );
}

export default App;
