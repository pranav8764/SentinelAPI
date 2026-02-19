# SentinelAPI Setup Guide

## Prerequisites

- Node.js v18 or higher
- MongoDB v4.4 or higher

## Installation

### 1. Install MongoDB
Download and install MongoDB from [mongodb.com](https://www.mongodb.com/try/download/community)

Start MongoDB:
```bash
mongod
```

### 2. Clone and Install Dependencies

```bash
# Clone the repository
git clone <your-repo-url>
cd SentinelAPI

# Install root dependencies
npm install

# Install backend dependencies
cd backend
npm install

# Install frontend dependencies
cd ../frontend
npm install
```

### 3. Configure Environment Variables

The backend `.env` file is already configured with defaults. Update if needed:

```bash
cd backend
# Edit .env file
# Change JWT_SECRET to a secure random string
```

### 4. Create Admin User

Use the register endpoint to create your first admin user:

**Using curl:**
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"your-secure-password"}'
```

**Using PowerShell:**
```powershell
Invoke-RestMethod -Uri "http://localhost:5000/api/auth/register" -Method POST -ContentType "application/json" -Body '{"username":"admin","email":"admin@example.com","password":"your-secure-password"}'
```

### 5. Start the Application

**Terminal 1 - Backend:**
```bash
cd backend
npm run dev
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

### 6. Access the Application

- Frontend: http://localhost:5173
- Backend API: http://localhost:5000

## Usage

1. Log in with your admin credentials
2. Navigate to "Scanner" to scan API endpoints
3. View logs and statistics in the Dashboard
4. Configure settings as needed

## Features

- **Endpoint Scanner**: Scan individual API endpoints for vulnerabilities
- **Security Testing**: SQL injection, XSS, NoSQL injection, and more
- **Real-time Monitoring**: Track requests and threats
- **Dashboard**: View statistics and recent activity
- **Logs**: Detailed request logging with filtering

## Troubleshooting

### MongoDB Connection Issues
- Ensure MongoDB is running: `mongod`
- Check connection string in `backend/.env`

### Port Already in Use
- Backend: Change `PORT` in `backend/.env`
- Frontend: Vite will prompt for an alternative port

### Login Issues
- Ensure you've created an admin user using the register endpoint
- Check backend logs for errors

## Production Deployment

1. Set `NODE_ENV=production` in backend `.env`
2. Update `JWT_SECRET` to a secure random string
3. Configure MongoDB connection string for production
4. Build frontend: `cd frontend && npm run build`
5. Use a process manager like PM2 for the backend
6. Set up reverse proxy (nginx/Apache) for production

## Security Notes

- Change default JWT_SECRET before deployment
- Use HTTPS in production
- Regularly update dependencies
- Review and adjust rate limiting settings
- Monitor logs for suspicious activity
