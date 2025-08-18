// src/routes/auth.js
const express = require('express');
const jwt = require('jsonwebtoken');
const { asyncHandler } = require('../middleware/errorHandler');
const { validators } = require('../middleware/validation');
const {
  authenticate,
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  allowRefreshJti,
  revokeRefreshJti,
  isRefreshAllowed,
  hashPassword,
  comparePassword,
} = require('../middleware/auth');
const { auditSecurityEvent } = require('../middleware/audit');
const User = require('../models/User');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * @swagger
 * tags:
 *   - name: Authentication
 *     description: JWT access + refresh
 */

/**
 * @swagger
 * /api/v1/auth/login:
 *   post:
 *     summary: User login (JWT access + refresh)
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
 *               update_password: { type: boolean, default: false }
 *     responses:
 *       200:
 *         description: Login successful
 */
router.post(
  '/login',
  validators.login,
  asyncHandler(async (req, res) => {
    const { username, password, remember_me = false, update_password = false } = req.body;

    logger.info('Auth: login attempt', { username, remember_me });

    const user = await User.findOne({ where: { username } });
    if (!user) {
      logger.warn('Auth: login failed (user not found)', { username });
      return res.status(401).json({ success:false, error:'Invalid credentials', code:'INVALID_CREDENTIALS' });
    }

    const ok = await comparePassword(password, user.password);
    if (!ok) {
      logger.warn('Auth: login failed (bad password)', { user_id: user.id, username });
      return res.status(401).json({ success:false, error:'Invalid credentials', code:'INVALID_CREDENTIALS' });
    }

    if (!user.is_active) {
      logger.warn('Auth: login blocked (user disabled)', { user_id: user.id, username });
      return res.status(401).json({ success:false, error:'Account is disabled', code:'USER_DISABLED' });
    }

    if (update_password) {
      const hash = await hashPassword(password);
      await user.update({ password: hash });
      logger.info('Auth: password updated on login', { user_id: user.id, username });
      await auditSecurityEvent(req, 'password_updated', 'low', { user_id: user.id });
    }

    const accessTtl   = remember_me ? '7d' : (process.env.JWT_EXPIRES_IN || '12h');
    const accessToken = signAccessToken({ id: user.id, username: user.username, role: user.role }, accessTtl);
    const refreshToken = signRefreshToken({ id: user.id, username: user.username, role: user.role });

    const { jti: rtJti, exp: rtExp, iat: rtIat } = jwt.decode(refreshToken);
    await allowRefreshJti(rtJti, user.id, rtExp, rtIat);
    setRefreshCookie(res, refreshToken, (rtExp - rtIat) * 1000);

    await user.update({ last_login: new Date() });
    logger.info('Auth: login success', { user_id: user.id, username: user.username, role: user.role, access_ttl: accessTtl });

    await auditSecurityEvent(req, 'login_success', 'low', { user_id: user.id });

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        token: accessToken,
        user: {
          id: user.id, username: user.username, email: user.email,
          role: user.role, last_login: user.last_login, is_active: user.is_active
        }
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/auth/refresh:
 *   post:
 *     summary: Refresh access token
 *     description: Usa il refresh dal cookie httpOnly `refresh_token` o dall'header `X-Refresh-Token: Bearer <token>`.
 *     tags: [Authentication]
 *     responses:
 *       200:
 *         description: Token refreshed
 */
router.post(
  '/refresh',
  asyncHandler(async (req, res) => {
    const cookieRt = req.cookies?.refresh_token || null;
    const hdr = req.headers['x-refresh-token'];
    const headerRt = hdr && hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
    const refreshToken = cookieRt || headerRt;

    if (!refreshToken) {
      logger.warn('Auth: refresh denied (missing token)');
      return res.status(401).json({ success:false, error:'Refresh token required', code:'REFRESH_TOKEN_MISSING' });
    }

    let payload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (e) {
      logger.warn('Auth: refresh denied (invalid/expired)', { name: e.name, message: e.message });
      return res.status(401).json({
        success:false,
        error: e.name === 'TokenExpiredError' ? 'Refresh token expired' : 'Invalid refresh token',
        code:  e.name === 'TokenExpiredError' ? 'REFRESH_EXPIRED' : 'REFRESH_INVALID'
      });
    }

    if (payload.type !== 'refresh_token') {
      logger.warn('Auth: refresh denied (wrong token type)', { type: payload.type });
      return res.status(401).json({ success:false, error:'Refresh token required', code:'TOKEN_WRONG_TYPE' });
    }

    const allowed = await isRefreshAllowed(payload.jti);
    if (!allowed) {
      logger.warn('Auth: refresh denied (revoked/reused jti)', { jti: payload.jti });
      return res.status(401).json({ success:false, error:'Refresh token revoked', code:'REFRESH_REVOKED' });
    }

    await revokeRefreshJti(payload.jti);

    const user = await User.findByPk(payload.id);
    if (!user || !user.is_active) {
      logger.warn('Auth: refresh denied (user invalid/disabled)', { user_id: payload.id });
      return res.status(401).json({ success:false, error:'User invalid', code:'USER_INVALID' });
    }

    const newAccess  = signAccessToken({ id: user.id, username: user.username, role: user.role });
    const newRefresh = signRefreshToken({ id: user.id, username: user.username, role: user.role });

    const { jti:newJti, exp:newExp, iat:newIat } = jwt.decode(newRefresh);
    await allowRefreshJti(newJti, user.id, newExp, newIat);
    setRefreshCookie(res, newRefresh, (newExp - newIat) * 1000);

    logger.info('Auth: token refreshed', { user_id: user.id, username: user.username });

    res.json({ success:true, message:'Token refreshed', data:{ token: newAccess, expires_in: process.env.JWT_EXPIRES_IN || '12h' }});
  })
);

/**
 * @swagger
 * /api/v1/auth/validate:
 *   get:
 *     summary: Validate access token
 *     tags: [Authentication]
 *     security: [{ bearerAuth: [] }]
 *     responses:
 *       200:
 *         description: Token is valid
 */
router.get(
  '/validate',
  authenticate,
  (req, res) => {
    const t = req.tokenData || {};
    logger.debug('Auth: validate ok', { user_id: req.user.id, jti: t.jti, exp: t.exp });
    res.json({
      success: true,
      message: 'Token is valid',
      data: {
        user: {
          id: req.user.id, username: req.user.username, email: req.user.email,
          role: req.user.role, is_active: req.user.is_active
        },
        token_info: {
          type: t.type,
          expires_at: t.exp ? new Date(t.exp * 1000).toISOString() : null,
          jti: t.jti
        }
      }
    });
  }
);

/**
 * @swagger
 * /api/v1/auth/logout:
 *   post:
 *     summary: Logout user (revoke tokens)
 *     tags: [Authentication]
 *     security: [{ bearerAuth: [] }]
 */
router.post(
  '/logout',
  authenticate,
  asyncHandler(async (req, res) => {
    try {
      const { jti, exp, iat } = req.tokenData || {};
      if (jti) {
        await require('../middleware/auth').blacklistAccessJti(jti, exp, iat);
        logger.info('Auth: access token blacklisted', { user_id: req.user.id, jti });
      }
    } catch (e) {
      logger.error('Auth: blacklist access token failed', { error: e.message });
    }

    const rt = req.cookies?.refresh_token;
    if (rt) {
      const decoded = jwt.decode(rt);
      if (decoded?.jti) {
        await revokeRefreshJti(decoded.jti);
        logger.info('Auth: refresh token revoked', { user_id: req.user.id, jti: decoded.jti });
      }
    }

    clearRefreshCookie(res);
    await auditSecurityEvent(req, 'logout', 'low', { user_id: req.user.id });

    logger.info('Auth: logout success', { user_id: req.user.id, username: req.user.username });

    res.json({ success:true, message:'Logout successful' });
  })
);

module.exports = router;
