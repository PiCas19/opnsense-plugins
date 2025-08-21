const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');
const { getEnv, requireEnv } = require('../utils/env');

// Verifica variabili d'ambiente richieste all'avvio
requireEnv(['JWT_SECRET']);

// ===============================
// CONFIGURAZIONE JWT
// ===============================

const getJWTSecret = () => getEnv('JWT_SECRET');
const getJWTRefreshSecret = () => getEnv('JWT_REFRESH_SECRET', `${getJWTSecret()}_refresh`);
const getJWTExpiresIn = () => getEnv('JWT_EXPIRES_IN', '1h');
const getJWTRefreshExpiresIn = () => getEnv('JWT_REFRESH_EXPIRES_IN', '7d');

// ===============================
// FUNZIONI JWT
// ===============================

/**
 * Genera access token JWT
 */
const generateAccessToken = (payload) => {
  try {
    return jwt.sign(payload, getJWTSecret(), {
      expiresIn: getJWTExpiresIn(),
      issuer: 'opnsense-firewall-api',
      audience: 'opnsense-users',
      subject: String(payload.id)
    });
  } catch (error) {
    logger.error('Errore nella generazione access token', { 
      error: error.message,
      payload: { id: payload.id, username: payload.username }
    });
    throw new Error('Errore nella generazione del token di accesso');
  }
};

/**
 * Genera refresh token JWT
 */
const generateRefreshToken = (payload) => {
  try {
    return jwt.sign(payload, getJWTRefreshSecret(), {
      expiresIn: getJWTRefreshExpiresIn(),
      issuer: 'opnsense-firewall-api',
      audience: 'opnsense-users',
      subject: String(payload.id)
    });
  } catch (error) {
    logger.error('Errore nella generazione refresh token', { 
      error: error.message,
      payload: { id: payload.id, username: payload.username }
    });
    throw new Error('Errore nella generazione del refresh token');
  }
};

/**
 * Verifica access token JWT
 */
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, getJWTSecret(), {
      issuer: 'opnsense-firewall-api',
      audience: 'opnsense-users'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Token scaduto');
    }
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Token non valido');
    }
    if (error.name === 'NotBeforeError') {
      throw new Error('Token non ancora valido');
    }
    throw new Error('Errore nella verifica del token');
  }
};

/**
 * Verifica refresh token JWT
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, getJWTRefreshSecret(), {
      issuer: 'opnsense-firewall-api',
      audience: 'opnsense-users'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Refresh token scaduto');
    }
    if (error.name === 'JsonWebTokenError') {
      throw new Error('Refresh token non valido');
    }
    throw new Error('Errore nella verifica del refresh token');
  }
};

/**
 * Estrae token dall'header Authorization
 */
const extractTokenFromHeader = (authHeader) => {
  if (!authHeader) {
    return null;
  }
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return null;
  }
  
  return parts[1];
};

// ===============================
// MIDDLEWARE DI AUTENTICAZIONE
// ===============================

/**
 * Middleware di autenticazione principale
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token di accesso richiesto',
        code: 'MISSING_TOKEN'
      });
    }

    // Verifica token
    const decoded = verifyAccessToken(token);
    
    // Verifica che l'utente esista ancora nel database
    const user = await User.findByPk(decoded.id, {
      attributes: ['id', 'username', 'email', 'role', 'is_active', 'locked_until', 'failed_login_attempts']
    });
    
    if (!user) {
      logger.warn('Tentativo di accesso con token per utente inesistente', {
        user_id: decoded.id,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      return res.status(401).json({
        success: false,
        message: 'Utente non trovato',
        code: 'USER_NOT_FOUND'
      });
    }

    if (!user.is_active) {
      logger.warn('Tentativo di accesso da utente disattivato', {
        user_id: user.id,
        username: user.username,
        ip: req.ip
      });
      
      return res.status(401).json({
        success: false,
        message: 'Account disattivato',
        code: 'ACCOUNT_DISABLED'
      });
    }

    // Controlla se account è bloccato
    if (user.isAccountLocked && user.isAccountLocked()) {
      const lockTimeRemaining = Math.ceil((new Date(user.locked_until) - new Date()) / 1000 / 60);
      
      logger.warn('Tentativo di accesso da account bloccato', {
        user_id: user.id,
        username: user.username,
        locked_until: user.locked_until,
        ip: req.ip
      });
      
      return res.status(423).json({
        success: false,
        message: `Account temporaneamente bloccato. Riprova tra ${lockTimeRemaining} minuti.`,
        code: 'ACCOUNT_LOCKED',
        retry_after: lockTimeRemaining * 60
      });
    }
    
    // Aggiunge informazioni utente alla request
    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email
    };
    
    // Log accesso riuscito (solo in debug mode)
    if (process.env.NODE_ENV === 'development') {
      logger.debug('Autenticazione riuscita', {
        user_id: user.id,
        username: user.username,
        ip: req.ip,
        endpoint: `${req.method} ${req.originalUrl}`
      });
    }
    
    next();
    
  } catch (error) {
    logger.warn('Tentativo di accesso con token non valido', {
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: `${req.method} ${req.originalUrl}`
    });
    
    // Determina il codice di errore specifico
    let errorCode = 'INVALID_TOKEN';
    if (error.message.includes('scaduto')) {
      errorCode = 'TOKEN_EXPIRED';
    }
    
    return res.status(401).json({
      success: false,
      message: error.message || 'Token non valido o scaduto',
      code: errorCode
    });
  }
};

/**
 * Middleware per controllo permessi specifici
 */
const requirePermission = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Autenticazione richiesta',
          code: 'AUTHENTICATION_REQUIRED'
        });
      }

      const user = await User.findByPk(req.user.id);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Utente non trovato',
          code: 'USER_NOT_FOUND'
        });
      }

      if (!user.hasPermission || !user.hasPermission(permission)) {
        logger.warn('Accesso negato per mancanza permessi', {
          user_id: user.id,
          username: user.username,
          required_permission: permission,
          user_role: user.role,
          ip: req.ip,
          endpoint: `${req.method} ${req.originalUrl}`
        });
        
        return res.status(403).json({
          success: false,
          message: 'Permessi insufficienti',
          code: 'INSUFFICIENT_PERMISSIONS',
          required_permission: permission
        });
      }

      next();
    } catch (error) {
      logger.error('Errore nel controllo permessi', {
        error: error.message,
        user_id: req.user?.id,
        permission,
        ip: req.ip
      });
      
      return res.status(500).json({
        success: false,
        message: 'Errore interno del server',
        code: 'INTERNAL_ERROR'
      });
    }
  };
};

/**
 * Middleware per controllo ruoli
 */
const requireRole = (roles) => {
  const allowedRoles = Array.isArray(roles) ? roles : [roles];
  
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Autenticazione richiesta',
          code: 'AUTHENTICATION_REQUIRED'
        });
      }

      const user = await User.findByPk(req.user.id, {
        attributes: ['id', 'username', 'role']
      });
      
      if (!user) {
        return res.status(401).json({
          success: false,
          message: 'Utente non trovato',
          code: 'USER_NOT_FOUND'
        });
      }

      if (!allowedRoles.includes(user.role)) {
        logger.warn('Accesso negato per ruolo insufficiente', {
          user_id: user.id,
          username: user.username,
          user_role: user.role,
          required_roles: allowedRoles,
          ip: req.ip,
          endpoint: `${req.method} ${req.originalUrl}`
        });
        
        return res.status(403).json({
          success: false,
          message: 'Ruolo insufficiente',
          code: 'INSUFFICIENT_ROLE',
          required_roles: allowedRoles,
          current_role: user.role
        });
      }

      next();
    } catch (error) {
      logger.error('Errore nel controllo ruolo', {
        error: error.message,
        user_id: req.user?.id,
        required_roles: allowedRoles,
        ip: req.ip
      });
      
      return res.status(500).json({
        success: false,
        message: 'Errore interno del server',
        code: 'INTERNAL_ERROR'
      });
    }
  };
};

/**
 * Middleware di autenticazione opzionale per endpoint pubblici
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = extractTokenFromHeader(authHeader);
    
    if (!token) {
      // Nessun token presente, continua senza autenticazione
      return next();
    }

    // Token presente, tenta l'autenticazione
    const decoded = verifyAccessToken(token);
    const user = await User.findByPk(decoded.id, {
      attributes: ['id', 'username', 'email', 'role', 'is_active']
    });
    
    if (user && user.is_active && (!user.isAccountLocked || !user.isAccountLocked())) {
      req.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        email: user.email
      };
    }
    
    next();
  } catch (error) {
    // Ignora errori di token per endpoint opzionali
    logger.debug('Token opzionale non valido, continuo senza autenticazione', {
      error: error.message,
      ip: req.ip
    });
    next();
  }
};

/**
 * Middleware per prevenire accessi da utenti con sessioni multiple
 */
const preventConcurrentSessions = async (req, res, next) => {
  if (!req.user) {
    return next();
  }

  try {
    const user = await User.findByPk(req.user.id, {
      attributes: ['id', 'last_login_at', 'concurrent_sessions_allowed']
    });

    // Se l'utente consente sessioni multiple, passa oltre
    if (user.concurrent_sessions_allowed) {
      return next();
    }

    // Controlla se ci sono altre sessioni attive
    // Questo richiederebbe un sistema di tracking delle sessioni
    // Per ora saltiamo questa implementazione
    
    next();
  } catch (error) {
    logger.error('Errore nel controllo sessioni concorrenti', {
      error: error.message,
      user_id: req.user.id
    });
    next(); // Continua anche se il controllo fallisce
  }
};

/**
 * Middleware per logging delle attività utente
 */
const logUserActivity = (req, res, next) => {
  if (req.user) {
    const startTime = Date.now();
    
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      
      // Log solo per operazioni significative
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        logger.info('Attività utente', {
          user_id: req.user.id,
          username: req.user.username,
          method: req.method,
          url: req.originalUrl,
          status: res.statusCode,
          duration,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
      }
    });
  }
  
  next();
};

/**
 * Middleware per rate limiting per utente
 */
const userRateLimit = (maxRequests = 100, windowMs = 60000) => {
  const userRequests = new Map();
  
  return (req, res, next) => {
    if (!req.user) {
      return next();
    }
    
    const userId = req.user.id;
    const now = Date.now();
    
    if (!userRequests.has(userId)) {
      userRequests.set(userId, []);
    }
    
    const requests = userRequests.get(userId);
    const validRequests = requests.filter(timestamp => now - timestamp < windowMs);
    
    if (validRequests.length >= maxRequests) {
      logger.warn('Rate limit utente superato', {
        user_id: userId,
        username: req.user.username,
        requests_count: validRequests.length,
        ip: req.ip
      });
      
      return res.status(429).json({
        success: false,
        message: 'Troppe richieste. Riprova più tardi.',
        code: 'RATE_LIMIT_EXCEEDED',
        retry_after: Math.ceil(windowMs / 1000)
      });
    }
    
    validRequests.push(now);
    userRequests.set(userId, validRequests);
    
    next();
  };
};

// ===============================
// UTILITY
// ===============================

/**
 * Decodifica token senza verificarlo (per debug)
 */
const decodeToken = (token) => {
  try {
    return jwt.decode(token, { complete: true });
  } catch (error) {
    return null;
  }
};

/**
 * Verifica se un token è scaduto
 */
const isTokenExpired = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) return true;
    return Date.now() >= decoded.exp * 1000;
  } catch (error) {
    return true;
  }
};

/**
 * Ottiene il tempo rimanente di un token
 */
const getTokenTimeRemaining = (token) => {
  try {
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) return 0;
    const remaining = decoded.exp * 1000 - Date.now();
    return Math.max(0, remaining);
  } catch (error) {
    return 0;
  }
};

module.exports = {
  // Funzioni JWT
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  extractTokenFromHeader,
  
  // Middleware principali
  authenticate,
  requirePermission,
  requireRole,
  optionalAuth,
  
  // Middleware avanzati
  preventConcurrentSessions,
  logUserActivity,
  userRateLimit,
  
  // Utility
  decodeToken,
  isTokenExpired,
  getTokenTimeRemaining
};