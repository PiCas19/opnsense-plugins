const express = require('express');
const { asyncHandler } = require('../middleware/errorHandler');
const { validators } = require('../middleware/validation');
const { authenticateApiKey, generateToken, hashPassword, comparePassword, auditSecurityEvent } = require('../middleware/auth');
const User = require('../models/User');
const logger = require('../utils/logger');
const crypto = require('crypto');

const router = express.Router();

/**
 * Generate JWT-based API key with extended expiration
 * @param {Object} payload - User data to encode
 * @returns {string} Long-lived JWT token as API key
 */
const generateApiKey = (payload) => {
  // Generate API key as JWT with very long expiration (1 year)
  return generateToken(
    {
      ...payload,
      type: 'api_key', // Mark this as an API key token
      generated_at: new Date().toISOString(),
      key_id: crypto.randomUUID(), // Unique key identifier
    },
    '365d' // 1 year expiration for API keys
  );
};

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: User login with password update or API key generation
 *     description: Authenticate a user and optionally update password or generate a JWT-based API key
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [username, password]
 *             properties:
 *               username: { type: string, example: "testuser" }
 *               password: { type: string, example: "Test123!" }
 *               remember_me: { type: boolean, default: false }
 *               update_password: { type: boolean, default: false, description: "Update the user's password" }
 *               generate_api_key: { type: boolean, default: false, description: "Generate a new JWT-based API key" }
 *     responses:
 *       200:
 *         description: Successful authentication
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *                 data:
 *                   type: object
 *                   properties:
 *                     token: { type: string, description: "Short-lived access token" }
 *                     api_key: { type: string, description: "Long-lived API key (JWT)" }
 *                     user: { type: object }
 *       401:
 *         description: Invalid credentials or unauthorized
 *       400:
 *         description: Validation error
 */
router.post(
  '/login',
  validators.login,
  asyncHandler(async (req, res) => {
    const { username, password, remember_me = false, update_password = false, generate_api_key = false } = req.body;

    // Find user
    const user = await User.findOne({ where: { username } });
    if (!user) {
      await auditSecurityEvent(req, 'login_failed', 'medium', { username });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS',
      });
    }

    // Verify existing password
    const isValidPassword = await comparePassword(password, user.password);
    if (!isValidPassword) {
      await auditSecurityEvent(req, 'login_failed', 'medium', { username });
      return res.status(401).json({
        success: false,
        error: 'Invalid credentials',
        code: 'INVALID_CREDENTIALS',
      });
    }

    if (!user.is_active) {
      await auditSecurityEvent(req, 'login_failed_inactive', 'medium', { username });
      return res.status(401).json({
        success: false,
        error: 'Account is disabled',
        code: 'USER_DISABLED',
      });
    }

    // Update password if requested (re-hash the provided password)
    if (update_password) {
      const newPasswordHash = await hashPassword(password);
      await user.update({ password: newPasswordHash });
      logger.info('Password updated for user', { user_id: user.id, username });
      await auditSecurityEvent(req, 'password_updated', 'low', { user_id: user.id });
    }

    // Generate standard JWT token for web sessions
    const expiresIn = remember_me ? '7d' : '12h';
    const token = generateToken(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        type: 'access_token'
      },
      expiresIn
    );

    // Generate long-lived API key (JWT-based) if requested
    let apiKey = null;
    if (generate_api_key) {
      apiKey = generateApiKey({
        id: user.id,
        username: user.username,
        role: user.role
      });
      
      logger.info('JWT API key generated for user', { 
        user_id: user.id, 
        username: user.username,
        expires_in: '365 days'
      });
      await auditSecurityEvent(req, 'api_key_generated', 'low', { 
        user_id: user.id,
        key_type: 'jwt_api_key'
      });
    }

    // Update last login (fix field name to match your model)
    await user.update({ last_login: new Date() });

    // Log successful login
    logger.info('User logged in successfully', {
      user_id: user.id,
      username: user.username,
      role: user.role,
      remember_me,
      password_updated: update_password,
      api_key_generated: generate_api_key,
      ip: req.ip,
      user_agent: req.get('User-Agent')
    });
    await auditSecurityEvent(req, 'login_success', 'low', { user_id: user.id });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token, // Short-lived access token
        api_key: apiKey, // Long-lived API key (only if requested)
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          last_login: user.last_login,
          is_active: user.is_active
        },
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/auth/validate:
 *   get:
 *     summary: Validate JWT token or API key
 *     description: Validate a JWT token (access token or API key) and return user info
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: Token validated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 data:
 *                   type: object
 *                   properties:
 *                     user: { type: object }
 *                     token_type: { type: string, enum: [access_token, api_key] }
 *                     expires_at: { type: string }
 *       401:
 *         description: Invalid or missing token
 */
router.get(
  '/validate',
  authenticateApiKey, // This middleware should handle both JWT access tokens and API keys
  (req, res) => {
    // Extract token info if available
    const tokenType = req.tokenData?.type || 'unknown';
    const expiresAt = req.tokenData?.exp ? new Date(req.tokenData.exp * 1000).toISOString() : null;
    
    res.json({
      success: true,
      message: 'Token is valid',
      data: {
        user: {
          id: req.user.id,
          username: req.user.username,
          email: req.user.email,
          role: req.user.role,
          is_active: req.user.is_active
        },
        token_info: {
          type: tokenType,
          expires_at: expiresAt,
          key_id: req.tokenData?.key_id || null
        }
      },
    });
  }
);

/**
 * @swagger
 * /api/v1/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     description: Get a new access token using a valid JWT token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 data:
 *                   type: object
 *                   properties:
 *                     token: { type: string }
 *                     expires_in: { type: string }
 *       401:
 *         description: Invalid or expired token
 */
router.post(
  '/refresh',
  authenticateApiKey,
  asyncHandler(async (req, res) => {
    // Generate new access token
    const newToken = generateToken(
      { 
        id: req.user.id, 
        username: req.user.username, 
        role: req.user.role,
        type: 'access_token'
      },
      '12h'
    );

    logger.info('Token refreshed', {
      user_id: req.user.id,
      username: req.user.username,
      old_token_type: req.tokenData?.type
    });

    res.json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        token: newToken,
        expires_in: '12 hours',
        user: {
          id: req.user.id,
          username: req.user.username,
          role: req.user.role
        }
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: User logout
 *     description: Logout user and optionally blacklist the current token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logout successful
 *       401:
 *         description: Not authenticated
 */
router.post(
  '/logout',
  authenticateApiKey,
  asyncHandler(async (req, res) => {
    // Update user last activity
    if (req.user) {
      await req.user.updateLastActivity();
      
      logger.info('User logged out', {
        user_id: req.user.id,
        username: req.user.username,
        token_type: req.tokenData?.type
      });
      
      await auditSecurityEvent(req, 'logout', 'low', { user_id: req.user.id });
    }

    res.json({
      success: true,
      message: 'Logout successful'
    });
  })
);

module.exports = router;