const express = require('express');
const rateLimit = require('express-rate-limit');
const { 
  generateAccessToken, 
  generateRefreshToken, 
  verifyRefreshToken,
  authenticate 
} = require('../middleware/auth');
const { validateLogin } = require('../middleware/validation');
const User = require('../models/User');
const logger = require('../utils/logger');

const router = express.Router();

// Rate limiting più aggressivo per auth
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 5, // massimo 5 tentativi per IP
  message: {
    success: false,
    message: 'Troppi tentativi di login, riprova più tardi'
  }
});

// In memoria refresh tokens (in produzione usare Redis o DB)
const refreshTokens = new Set();

/**
 * @swagger
 * components:
 *   schemas:
 *     LoginRequest:
 *       type: object
 *       required:
 *         - username
 *         - password
 *       properties:
 *         username:
 *           type: string
 *           description: Nome utente
 *           example: admin
 *         password:
 *           type: string
 *           description: Password
 *           example: Admin123!
 * 
 *     LoginResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: Login effettuato con successo
 *         data:
 *           type: object
 *           properties:
 *             accessToken:
 *               type: string
 *               description: JWT access token
 *             refreshToken:
 *               type: string
 *               description: JWT refresh token
 *             user:
 *               $ref: '#/components/schemas/User'
 * 
 *     RefreshRequest:
 *       type: object
 *       required:
 *         - refreshToken
 *       properties:
 *         refreshToken:
 *           type: string
 *           description: JWT refresh token
 * 
 *     ChangePasswordRequest:
 *       type: object
 *       required:
 *         - current_password
 *         - new_password
 *       properties:
 *         current_password:
 *           type: string
 *           description: Password corrente
 *         new_password:
 *           type: string
 *           description: Nuova password
 *           pattern: '^[a-zA-Z0-9_-]+$'
 */

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login utente
 *     description: Effettua il login con username e password
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login effettuato con successo
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       401:
 *         description: Credenziali non valide
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       423:
 *         description: Account temporaneamente bloccato
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Troppi tentativi di login
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
router.post('/login', authLimiter, validateLogin, async (req, res) => {
  try {
    const { username, password } = req.body;

    // Trova utente
    const user = await User.findByUsername(username);
    if (!user) {
      logger.warn('Tentativo di login con username non valido', { 
        username, 
        ip: req.ip 
      });
      return res.status(401).json({
        success: false,
        message: 'Credenziali non valide'
      });
    }

    // Controlla se account è bloccato
    if (user.isAccountLocked()) {
      logger.warn('Tentativo di accesso su account bloccato', { 
        username: user.username, 
        ip: req.ip 
      });
      return res.status(423).json({
        success: false,
        message: 'Account temporaneamente bloccato. Riprova più tardi.'
      });
    }

    // Verifica password
    const isValidPassword = await user.verifyPassword(password);
    if (!isValidPassword) {
      logger.warn('Tentativo di login con password non valida', { 
        username: user.username, 
        ip: req.ip 
      });
      return res.status(401).json({
        success: false,
        message: 'Credenziali non valide'
      });
    }

    // Aggiorna informazioni login
    await user.update({
      login_ip: req.ip,
      user_agent: req.get('User-Agent'),
      last_activity: new Date()
    });

    // Genera tokens
    const payload = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);
    
    // Salva refresh token
    refreshTokens.add(refreshToken);

    logger.info('Login effettuato con successo', { 
      user_id: user.id,
      username: user.username, 
      ip: req.ip 
    });

    res.json({
      success: true,
      message: 'Login effettuato con successo',
      data: {
        accessToken,
        refreshToken,
        user: user.toSafeJSON()
      }
    });
  } catch (error) {
    logger.error('Errore durante il login', error);
    res.status(500).json({
      success: false,
      message: 'Errore interno del server'
    });
  }
});

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Rinnova access token
 *     description: Rinnova l'access token utilizzando il refresh token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RefreshRequest'
 *     responses:
 *       200:
 *         description: Token rinnovato con successo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Token rinnovato con successo
 *                 data:
 *                   type: object
 *                   properties:
 *                     accessToken:
 *                       type: string
 *                       description: Nuovo JWT access token
 *       401:
 *         description: Refresh token richiesto
 *       403:
 *         description: Refresh token non valido o scaduto
 */
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token richiesto'
      });
    }

    // Verifica se il refresh token è valido e presente
    if (!refreshTokens.has(refreshToken)) {
      return res.status(403).json({
        success: false,
        message: 'Refresh token non valido'
      });
    }

    const decoded = verifyRefreshToken(refreshToken);
    
    // Verifica che l'utente esista ancora ed è attivo
    const user = await User.findByPk(decoded.id);
    if (!user || !user.is_active) {
      refreshTokens.delete(refreshToken);
      return res.status(403).json({
        success: false,
        message: 'Utente non valido'
      });
    }

    // Genera nuovo access token
    const newAccessToken = generateAccessToken({
      id: user.id,
      username: user.username,
      role: user.role
    });

    // Aggiorna ultima attività
    await user.updateLastActivity();

    res.json({
      success: true,
      message: 'Token rinnovato con successo',
      data: {
        accessToken: newAccessToken
      }
    });
  } catch (error) {
    logger.warn('Tentativo di refresh con token non valido', { 
      ip: req.ip,
      error: error.message 
    });
    
    res.status(403).json({
      success: false,
      message: 'Refresh token non valido o scaduto'
    });
  }
});

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Logout utente
 *     description: Effettua il logout invalidando il refresh token
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken:
 *                 type: string
 *                 description: Refresh token da invalidare
 *     responses:
 *       200:
 *         description: Logout effettuato con successo
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Success'
 *       401:
 *         description: Token di accesso richiesto
 */
router.post('/logout', authenticate, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (refreshToken) {
      refreshTokens.delete(refreshToken);
    }

    // Aggiorna ultima attività
    const user = await User.findByPk(req.user.id);
    if (user) {
      await user.updateLastActivity();
    }

    logger.info('Logout effettuato', { 
      user_id: req.user.id,
      username: req.user.username, 
      ip: req.ip 
    });

    res.json({
      success: true,
      message: 'Logout effettuato con successo'
    });
  } catch (error) {
    logger.error('Errore durante il logout', error);
    res.status(500).json({
      success: false,
      message: 'Errore interno del server'
    });
  }
});

/**
 * @swagger
 * /api/auth/verify:
 *   get:
 *     summary: Verifica validità token
 *     description: Verifica se l'access token è valido e restituisce i dati utente
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token valido
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: Token valido
 *                 data:
 *                   type: object
 *                   properties:
 *                     user:
 *                       $ref: '#/components/schemas/User'
 *       401:
 *         description: Token non valido o scaduto
 */
router.get('/verify', authenticate, async (req, res) => {
  try {
    // Verifica che l'utente esista ancora nel database
    const user = await User.findByPk(req.user.id);
    if (!user || !user.is_active) {
      return res.status(401).json({
        success: false,
        message: 'Utente non valido'
      });
    }

    // Aggiorna ultima attività
    await user.updateLastActivity();

    res.json({
      success: true,
      message: 'Token valido',
      data: {
        user: user.toSafeJSON()
      }
    });
  } catch (error) {
    logger.error('Errore nella verifica token', error);
    res.status(500).json({
      success: false,
      message: 'Errore interno del server'
    });
  }
});

/**
 * @swagger
 * /api/auth/change-password:
 *   post:
 *     summary: Cambia password
 *     description: Cambia la password dell'utente corrente
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ChangePasswordRequest'
 *     responses:
 *       200:
 *         description: Password cambiata con successo
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Success'
 *       400:
 *         description: Dati non validi o password corrente errata
 *       401:
 *         description: Token di accesso richiesto
 */
router.post('/change-password', authenticate, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password) {
      return res.status(400).json({
        success: false,
        message: 'Password corrente e nuova password sono richieste'
      });
    }

    const user = await User.findByPk(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'Utente non trovato'
      });
    }

    // Verifica password corrente
    const isCurrentValid = await user.verifyPassword(current_password);
    if (!isCurrentValid) {
      return res.status(400).json({
        success: false,
        message: 'Password corrente non valida'
      });
    }

    // Aggiorna password
    await user.update({ password: new_password });

    logger.info('Password cambiata', {
      user_id: user.id,
      username: user.username,
      ip: req.ip
    });

    res.json({
      success: true,
      message: 'Password cambiata con successo'
    });

  } catch (error) {
    logger.error('Errore nel cambio password', error);
    res.status(500).json({
      success: false,
      message: 'Errore interno del server'
    });
  }
});

module.exports = router;