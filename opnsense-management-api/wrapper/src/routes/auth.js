const express = require('express');
const { asyncHandler } = require('../middleware/errorHandler');
const { validators } = require('../middleware/validation');
const { authenticateApiKey, generateToken, hashPassword, comparePassword, auditSecurityEvent } = require('../middleware/auth');
const User = require('../models/User');
const ApiKey = require('../models/ApiKey');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: User login with password update or API key generation
 *     description: Authenticate a user and optionally update password or generate an API key
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
 *               generate_api_key: { type: boolean, default: false, description: "Generate a new API key" }
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
 *                     token: { type: string }
 *                     api_key: { type: string }
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
    let newPasswordHash = user.password;
    if (update_password) {
      newPasswordHash = await hashPassword(password); // Ricalcola l'hash
      await user.update({ password: newPasswordHash });
      logger.info('Password updated for user', { user_id: user.id, username });
      await auditSecurityEvent(req, 'password_updated', 'low', { user_id: user.id });
    }

    // Generate JWT token
    const expiresIn = remember_me ? '7d' : '12h';
    const token = generateToken(
      { id: user.id, username: user.username, role: user.role },
      expiresIn
    );

    // Generate API key if requested
    let apiKey = null;
    if (generate_api_key) {
      const newApiKey = await ApiKey.create({
        user_id: user.id,
        key: require('crypto').randomBytes(32).toString('hex'),
        name: `API Key for ${user.username}`,
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 giorni
        is_active: true,
        usage_count: 0,
      });
      apiKey = newApiKey.key;
      await auditSecurityEvent(req, 'api_key_generated', 'low', { user_id: user.id });
    }

    // Update last login
    await user.update({ last_login_at: new Date() });

    // Log successful login
    logger.info('User logged in', {
      user_id: user.id,
      username: user.username,
      role: user.role,
      remember_me,
      password_updated: update_password,
      api_key_generated: generate_api_key,
    });
    await auditSecurityEvent(req, 'login_success', 'low', { user_id: user.id });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token,
        api_key: apiKey,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      },
    });
  })
);

/**
 * @swagger
 * /auth/validate:
 *   get:
 *     summary: Validate API key
 *     description: Validate an API key and return user info
 *     tags: [Authentication]
 *     security:
 *       - apiKeyAuth: []
 *     responses:
 *       200:
 *         description: API key validated
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
 *       401:
 *         description: Invalid or missing API key
 */
router.get(
  '/validate',
  authenticateApiKey,
  (req, res) => {
    res.json({
      success: true,
      data: {
        user: {
          id: req.user.id,
          username: req.user.username,
          email: req.user.email,
          role: req.user.role,
        },
      },
    });
  }
);

module.exports = router;