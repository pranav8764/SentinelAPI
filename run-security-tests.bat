@echo off
echo ========================================
echo   SentinelAPI Security Testing Suite
echo ========================================
echo.

REM Check if backend server is running
echo Checking if backend server is running...
curl -s http://localhost:3001/health >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Backend server is not running!
    echo.
    echo Please start the backend server first:
    echo   cd backend
    echo   npm start
    echo.
    echo Then run this script again.
    pause
    exit /b 1
)

echo [OK] Backend server is running
echo.

REM Run backend security tests
echo ========================================
echo   Running Backend Security Tests
echo ========================================
echo.
cd backend
call npm run test:security
cd ..

echo.
echo ========================================
echo   Tests Complete!
echo ========================================
echo.
echo To run frontend tests:
echo   1. Open frontend-security-tests.html in your browser
echo   2. Click "Run All Tests"
echo.
pause
