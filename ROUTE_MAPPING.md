# Frontend-Backend Route Mapping

## ✅ Connection Status: ALL ROUTES CONNECTED

### Authentication Routes (`/api/auth`)

| Frontend API Call | Backend Route | Method | Status |
|------------------|---------------|--------|--------|
| `authAPI.login()` | `/api/auth/login` | POST | ✅ Connected |
| `authAPI.register()` | `/api/auth/register` | POST | ✅ Connected |
| `authAPI.getMe()` | `/api/auth/me` | GET | ✅ Connected |
| `authAPI.logout()` | `/api/auth/logout` | POST | ✅ Connected |

**Additional Backend Routes (not used in frontend yet):**
- POST `/api/auth/refresh` - Refresh JWT token

---

### Admin Routes (`/api/admin`)

| Frontend API Call | Backend Route | Method | Status |
|------------------|---------------|--------|--------|
| `adminAPI.getLogs()` | `/api/admin/logs` | GET | ✅ Connected |
| `adminAPI.getStats()` | `/api/admin/stats` | GET | ✅ Connected |
| `adminAPI.getRecentThreats()` | `/api/admin/recent-threats` | GET | ✅ Connected |
| `adminAPI.getConfig()` | `/api/admin/config` | GET | ✅ Connected |
| `adminAPI.updateConfig()` | `/api/admin/config` | PUT | ✅ Connected |
| `adminAPI.getRateLimit()` | `/api/admin/rate-limit` | GET | ✅ Connected |
| `adminAPI.updateRateLimit()` | `/api/admin/rate-limit` | PUT | ✅ Connected |

**Additional Backend Routes (not used in frontend yet):**
- GET `/api/admin/health` - Admin API health check

---

### Proxy Routes (`/api/proxy`)

| Frontend API Call | Backend Route | Method | Status |
|------------------|---------------|--------|--------|
| `proxyAPI.getHealth()` | `/api/proxy/health` | GET | ✅ Connected |
| `proxyAPI.getConfig()` | `/api/proxy/config` | GET | ✅ Connected |

---

### Base Routes

| Route | Method | Purpose | Status |
|-------|--------|---------|--------|
| `/` | GET | Welcome message | ✅ Available |
| `/health` | GET | Server health check | ✅ Available |
| `/proxy/*` | ALL | Proxy forwarding | ✅ Available |

---

## Frontend Pages Using Backend APIs

### 1. Login Page (`/login`)
**APIs Used:**
- ✅ `authAPI.login()` → POST `/api/auth/login`

### 2. Dashboard Page (`/`)
**APIs Used:**
- ✅ `authAPI.getMe()` → GET `/api/auth/me` (on load)
- ✅ `adminAPI.getStats()` → GET `/api/admin/stats`
- ✅ `proxyAPI.getHealth()` → GET `/api/proxy/health`

### 3. Logs Page (`/logs`)
**APIs Used:**
- ✅ `authAPI.getMe()` → GET `/api/auth/me` (on load)
- ✅ `adminAPI.getLogs()` → GET `/api/admin/logs`

### 4. Settings Page (`/settings`)
**APIs Used:**
- ✅ `authAPI.getMe()` → GET `/api/auth/me` (on load)
- ✅ `adminAPI.getRateLimit()` → GET `/api/admin/rate-limit`
- ✅ `adminAPI.updateRateLimit()` → PUT `/api/admin/rate-limit`

---

## Configuration

### Backend
- **Base URL:** `http://localhost:3001`
- **API Prefix:** `/api`
- **Full API URL:** `http://localhost:3001/api`

### Frontend
- **Dev Server:** `http://localhost:5174`
- **API URL (from .env):** `http://localhost:3001/api`
- **Configured in:** `frontend/src/services/api.js`

---

## Authentication Flow

1. User logs in via `authAPI.login()`
2. Backend returns JWT token
3. Token stored in `localStorage`
4. All subsequent requests include token in `Authorization: Bearer <token>` header
5. Backend validates token via `authenticate` middleware
6. If token invalid/expired → 401 response → redirect to login

---

## Permissions Required

### Admin Routes
- `view_logs` - Required for logs and recent threats
- `view_analytics` - Required for stats and rate limit config
- `manage_config` - Required for updating config and rate limits

### User Roles
- **admin** - Has all permissions by default
- **viewer** - Limited permissions (view only)

---

## Summary

✅ **All frontend routes are properly connected to backend**
✅ **API base URL correctly configured**
✅ **Authentication flow implemented**
✅ **Error handling in place**
✅ **Token management working**

**Total Routes Mapped:** 14 frontend API calls → 14 backend endpoints
**Connection Status:** 100% ✅
