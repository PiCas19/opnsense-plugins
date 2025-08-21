const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || `${JWT_SECRET}_refresh`;

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET è obbligatorio');
}

// Genera access token
const generateAccessToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || '1h'
  });
};

// Genera refresh token
const generateRefreshToken = (payload) => {
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d'
  });
};

// Verifica access token
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    throw new Error('Token non valido');
  }
};

// Verifica refresh token
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET);
  } catch (error) {
    throw new Error('Refresh token non valido');
  }
};

// Middleware di autenticazione
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Token di accesso richiesto'
      });
    }

    const token = authHeader.substring(7); // Rimuovi "Bearer "
    const decoded = verifyAccessToken(token);
    
    // Verifica che l'utente esista ancora nel database
    const user = await User.findByPk(decoded.id);
    if (!user || !user.is_active) {
      return res.status(401).json({
        success: false,
        message: 'Utente non valido o disattivato'
      });
    }

    // Controlla se account è bloccato
    if (user.isAccountLocked()) {
      return res.status(423).json({
        success: false,
        message: 'Account temporaneamente bloccato'
      });
    }
    
    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email
    };
    
    next();
  } catch (error) {
    logger.warn('Tentativo di accesso con token non valido', {
      ip: req.ip,
      error: error.message,
      userAgent: req.get('User-Agent')
    });
    
    return res.status(401).json({
      success: false,
      message: 'Token non valido o scaduto'
    });
  }
};

// Middleware per controllo permessi
const requirePermission = (permission) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Autenticazione richiesta'
        });
      }

      const user = await User.findByPk(req.user.id);
      if (!user || !user.hasPermission(permission)) {
        return res.status(403).json({
          success: false,
          message: 'Permessi insufficienti'
        });
      }

      next();
    } catch (error) {
      logger.error('Errore nel controllo permessi', {
        error: error.message,
        user_id: req.user?.id,
        permission
      });
      
      return res.status(500).json({
        success: false,
        message: 'Errore interno del server'
      });
    }
  };
};

// Middleware per controllo ruolo
const requireRole = (roles) => {
  const allowedRoles = Array.isArray(roles) ? roles : [roles];
  
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Autenticazione richiesta'
        });
      }

      const user = await User.findByPk(req.user.id);
      if (!user || !allowedRoles.includes(user.role)) {
        return res.status(403).json({
          success: false,
          message: 'Ruolo insufficiente'
        });
      }

      next();
    } catch (error) {
      logger.error('Errore nel controllo ruolo', {
        error: error.message,
        user_id: req.user?.id,
        required_roles: allowedRoles
      });
      
      return res.status(500).json({
        success: false,
        message: 'Errore interno del server'
      });
    }
  };
};

// Middleware opzionale per endpoint pubblici
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      const decoded = verifyAccessToken(token);
      
      const user = await User.findByPk(decoded.id);
      if (user && user.is_active && !user.isAccountLocked()) {
        req.user = {
          id: user.id,
          username: user.username,
          role: user.role,
          email: user.email
        };
      }
    }
    
    next();
  } catch (error) {
    // Ignora errori di token per endpoint opzionali
    next();
  }
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  authenticate,
  requirePermission,
  requireRole,
  optionalAuth
};