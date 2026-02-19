import express from 'express';
import axios from 'axios';
import { authenticate } from '../middleware/auth.js';
import logger from '../utils/logger.js';

const router = express.Router();

// All auth test routes require authentication
router.use(authenticate);

// Test OAuth 2.0 authentication
router.post('/oauth', async (req, res) => {
  try {
    const {
      grantType,
      clientId,
      clientSecret,
      redirectUri,
      tokenUrl,
      scope,
      code,
      refreshToken,
    } = req.body;

    if (!tokenUrl) {
      return res.status(400).json({
        error: 'Token URL is required',
        code: 'MISSING_TOKEN_URL'
      });
    }

    // Build OAuth request based on grant type
    const tokenData = {
      grant_type: grantType,
      client_id: clientId,
      client_secret: clientSecret,
    };

    if (grantType === 'authorization_code') {
      if (!code) {
        return res.status(400).json({
          error: 'Authorization code is required',
          code: 'MISSING_AUTH_CODE'
        });
      }
      tokenData.code = code;
      tokenData.redirect_uri = redirectUri;
    } else if (grantType === 'refresh_token') {
      if (!refreshToken) {
        return res.status(400).json({
          error: 'Refresh token is required',
          code: 'MISSING_REFRESH_TOKEN'
        });
      }
      tokenData.refresh_token = refreshToken;
    } else if (grantType === 'client_credentials') {
      if (scope) tokenData.scope = scope;
    }

    const startTime = Date.now();
    
    try {
      const formBody = new URLSearchParams(tokenData);
      const response = await axios.post(tokenUrl, formBody.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 10000,
      });

      const responseTime = Date.now() - startTime;

      logger.info(`OAuth test successful for user: ${req.user.username}`);

      res.json({
        success: true,
        grantType,
        responseTime: `${responseTime}ms`,
        tokenReceived: !!response.data.access_token,
        expiresIn: response.data.expires_in,
        tokenType: response.data.token_type,
        scope: response.data.scope,
        refreshToken: !!response.data.refresh_token,
        rawResponse: response.data,
      });
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      logger.warn(`OAuth test failed: ${error.message}`);

      res.json({
        success: false,
        grantType,
        responseTime: `${responseTime}ms`,
        error: error.response?.data || error.message,
        statusCode: error.response?.status,
      });
    }
  } catch (error) {
    logger.error(`OAuth test error: ${error.message}`);
    res.status(500).json({
      error: 'OAuth test failed',
      code: 'OAUTH_TEST_ERROR',
      details: error.message
    });
  }
});

// Test API Key authentication
router.post('/apikey', async (req, res) => {
  try {
    const {
      url,
      method = 'GET',
      apiKey,
      keyLocation = 'header',
      keyName = 'X-API-Key',
      additionalHeaders = '{}',
    } = req.body;

    if (!url || !apiKey) {
      return res.status(400).json({
        error: 'URL and API key are required',
        code: 'MISSING_PARAMETERS'
      });
    }

    const startTime = Date.now();
    
    try {
      const config = {
        method: method.toLowerCase(),
        url,
        timeout: 10000,
        headers: {},
      };

      // Parse additional headers
      try {
        const parsedHeaders = JSON.parse(additionalHeaders);
        config.headers = { ...config.headers, ...parsedHeaders };
      } catch (e) {
        // Ignore invalid JSON
      }

      // Add API key based on location
      if (keyLocation === 'header') {
        config.headers[keyName] = apiKey;
      } else if (keyLocation === 'query') {
        config.params = { [keyName]: apiKey };
      }

      const response = await axios(config);
      const responseTime = Date.now() - startTime;

      logger.info(`API Key test successful for user: ${req.user.username}`);

      res.json({
        success: true,
        method,
        url,
        keyLocation,
        responseTime: `${responseTime}ms`,
        statusCode: response.status,
        headers: response.headers,
        data: response.data,
      });
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      logger.warn(`API Key test failed: ${error.message}`);

      res.json({
        success: false,
        method,
        url,
        keyLocation,
        responseTime: `${responseTime}ms`,
        error: error.response?.data || error.message,
        statusCode: error.response?.status,
        headers: error.response?.headers,
      });
    }
  } catch (error) {
    logger.error(`API Key test error: ${error.message}`);
    res.status(500).json({
      error: 'API Key test failed',
      code: 'APIKEY_TEST_ERROR',
      details: error.message
    });
  }
});

// Test Session-based authentication
router.post('/session', async (req, res) => {
  try {
    const {
      url,
      method = 'GET',
      sessionId,
      cookieName = 'session',
      additionalCookies = '',
    } = req.body;

    if (!url || !sessionId) {
      return res.status(400).json({
        error: 'URL and session ID are required',
        code: 'MISSING_PARAMETERS'
      });
    }

    const startTime = Date.now();
    
    try {
      // Build cookie string
      let cookieString = `${cookieName}=${sessionId}`;
      if (additionalCookies) {
        cookieString += `; ${additionalCookies}`;
      }

      const config = {
        method: method.toLowerCase(),
        url,
        timeout: 10000,
        headers: {
          'Cookie': cookieString,
        },
      };

      const response = await axios(config);
      const responseTime = Date.now() - startTime;

      logger.info(`Session test successful for user: ${req.user.username}`);

      res.json({
        success: true,
        method,
        url,
        responseTime: `${responseTime}ms`,
        statusCode: response.status,
        sessionValid: response.status === 200,
        setCookies: response.headers['set-cookie'],
        headers: response.headers,
        data: response.data,
      });
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      logger.warn(`Session test failed: ${error.message}`);

      res.json({
        success: false,
        method,
        url,
        responseTime: `${responseTime}ms`,
        error: error.response?.data || error.message,
        statusCode: error.response?.status,
        sessionValid: false,
        headers: error.response?.headers,
      });
    }
  } catch (error) {
    logger.error(`Session test error: ${error.message}`);
    res.status(500).json({
      error: 'Session test failed',
      code: 'SESSION_TEST_ERROR',
      details: error.message
    });
  }
});

// Test JWT authentication
router.post('/jwt', async (req, res) => {
  try {
    const {
      url,
      method = 'GET',
      token,
      tokenLocation = 'header',
      headerName = 'Authorization',
      headerPrefix = 'Bearer',
    } = req.body;

    if (!url || !token) {
      return res.status(400).json({
        error: 'URL and JWT token are required',
        code: 'MISSING_PARAMETERS'
      });
    }

    const startTime = Date.now();
    
    try {
      const config = {
        method: method.toLowerCase(),
        url,
        timeout: 10000,
        headers: {},
      };

      // Add JWT based on location
      if (tokenLocation === 'header') {
        const tokenValue = headerPrefix ? `${headerPrefix} ${token}` : token;
        config.headers[headerName] = tokenValue;
      } else if (tokenLocation === 'cookie') {
        config.headers['Cookie'] = `${headerName}=${token}`;
      }

      const response = await axios(config);
      const responseTime = Date.now() - startTime;

      // Try to decode JWT (basic decode, no verification)
      let decodedToken = null;
      try {
        const parts = token.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
          decodedToken = {
            header: JSON.parse(Buffer.from(parts[0], 'base64').toString()),
            payload,
            expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
            issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
          };
        }
      } catch (e) {
        // Invalid JWT format
      }

      logger.info(`JWT test successful for user: ${req.user.username}`);

      res.json({
        success: true,
        method,
        url,
        tokenLocation,
        responseTime: `${responseTime}ms`,
        statusCode: response.status,
        tokenValid: response.status === 200,
        decodedToken,
        headers: response.headers,
        data: response.data,
      });
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      logger.warn(`JWT test failed: ${error.message}`);

      res.json({
        success: false,
        method,
        url,
        tokenLocation,
        responseTime: `${responseTime}ms`,
        error: error.response?.data || error.message,
        statusCode: error.response?.status,
        tokenValid: false,
        headers: error.response?.headers,
      });
    }
  } catch (error) {
    logger.error(`JWT test error: ${error.message}`);
    res.status(500).json({
      error: 'JWT test failed',
      code: 'JWT_TEST_ERROR',
      details: error.message
    });
  }
});

export default router;
