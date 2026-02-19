import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3001/api';

const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const authAPI = {
  login: (credentials) => api.post('/auth/login', credentials),
  register: (userData) => api.post('/auth/register', userData),
  getMe: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
};

export const adminAPI = {
  getLogs: (params) => api.get('/admin/logs', { params }),
  getStats: () => api.get('/admin/stats'),
  getRecentThreats: (limit = 20) => api.get('/admin/recent-threats', { params: { limit } }),
  getConfig: () => api.get('/admin/config'),
  updateConfig: (config) => api.put('/admin/config', config),
  getRateLimit: () => api.get('/admin/rate-limit'),
  updateRateLimit: (config) => api.put('/admin/rate-limit', config),
  clearLogs: () => api.delete('/admin/logs'),
};

export const proxyAPI = {
  getHealth: () => api.get('/proxy/health'),
  getConfig: () => api.get('/proxy/config'),
};

export default api;
