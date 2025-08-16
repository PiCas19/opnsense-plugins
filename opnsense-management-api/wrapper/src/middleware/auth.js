const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { cache } = require('../config/database');
const logger = require('../utils/logger');
const { auditSecurityEvent } = require('./audit');

// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '12h';
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters long');
}

// User roles and permissions
const ROLES = {
  ADMIN: 'admin',
  OPERATOR: 'operator',
  VIEWER: 'viewer',
  API_USER: 'api_user',
};

const PERMISSIONS = {
  // Firewall permissions
  FIREWALL_READ: 'firewall:read',
  FIREWALL_WRITE: 'firewall:write',
  FIREWALL_DELETE: 'firewall:delete',
  FIREWALL_TOGGLE: 'firewall:toggle',
  
  // Policy permissions
  POLICY_READ: 'policy:read',
  POLICY_WRITE: 'policy:write',
  POLICY_DELETE: 'policy:delete',
  
  // System permissions
  SYSTEM_READ: 'system:read',
  SYSTEM_WRITE: 'system:write',
  SYSTEM_ADMIN: 'system:admin',
  
  // Monitoring permissions
  MONITORING_READ: 'monitoring:read',
  MONITORING_WRITE: 'monitoring:write',
  
  // Admin permissions
  USER_MANAGE: 'user:manage',
  AUDIT_READ: 'audit:read',
  CONFIG_MANAGE: 'config:manage',
};

// Role-based permissions mapping
const ROLE_PERMISSIONS = {
  [ROLES.ADMIN]: Object.values(PERMISSIONS),
  [ROLES.OPERATOR]: [
    PERMISSIONS.FIREWALL_READ,
    PERMISSIONS.FIREWALL_WRITE,
    PERMISSIONS.FIREWALL_TOGGLE,
    PERMISSIONS.POLICY_READ,
    PERMISSIONS.POLICY_WRITE,
    PERMISSIONS.SYSTEM_READ,
    PERMISSIONS.MONITORING_READ,
  ],
  [ROLES.VIEWER]: [
    PERMISSIONS.FIREWALL_READ,
    PERMISSIONS.POLICY_READ,
    PERMISSIONS.SYSTEM_READ,
    PERMISSIONS.MONITORING_READ,
  ],
  [ROLES.API_USER]: [
    PERMISSIONS.FIREWALL_READ,
    PERMISSIONS.FIREWALL_WRITE,
    PERMISSIONS.FIREWALL_TOGGLE,
    PERMISSIONS.MONITORING_READ,
  ],
};

/**
 * Generate JWT token
 */
const generateToken = (payload, expiresIn = JWT_EXPIRES_IN) => {
  return jwt.sign(payload, JWT_SECRET, { 
    expiresIn,
    issuer: 'opnsense-management-api',
    audience: 'opnsense-users',
  });
};

/**
 * Generate refresh token
 */
const generateRefreshToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, { 
    expiresIn: JWT_REFRESH_EXPIRES_IN,
    issuer: 'opnsense-management-api',
    audience: 'opnsense-refresh',
  });
};

/**
 * Verify JWT token
 */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'opnsense-management-api',
      audience: 'opnsense-users',
    });
  } catch (error) {
    throw new Error(`Invalid token: ${error.message}`);
  }
};

/**
 * Verify refresh token
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET, {
      issuer: 'opnsense-management-api',
      audience: 'opnsense-refresh',
    });
  } catch (error) {
    throw new Error(`Invalid refresh token: ${error.message}`);
  }
};

/**
 * Hash password
 */
const hashPassword = async (password) => {
  const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
  return await bcrypt.hash(password, saltRounds);
};

/**
 * Compare password
 */
const comparePassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

/**
 * Check if token is blacklisted
 */
const isTokenBlacklisted = async (token) => {
  try {
    const blacklisted = await cache.get(`blacklist:${token}`);
    return !!blacklisted;
  } catch (error) {
    logger.error('Error checking token blacklist', { error: error.message });
    return false;
  }
};

/**
 * Blacklist token
 */
const blacklistToken = async (token, expiresIn = JWT_EXPIRES_IN) => {
  try {
    // Convert expiration time to seconds
    const ttl = typeof expiresIn === 'string' ? 
      parseExpiration(expiresIn) : 
      expiresIn;
    
    await cache.set(`blacklist:${token}`, true, ttl);
    return true;
  } catch (error) {
    logger.error('Error blacklisting token', { error: error.message });
    return false;
  }
};

/**
 * Parse expiration string to seconds
 */
const parseExpiration = (expiration) => {
  const match = expiration.match(/^(\d+)([smhd])$/);
  if (!match) return 3600; // Default 1 hour
  
  const [, amount, unit] = match;
  const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
  return parseInt(amount) * multipliers[unit];
};

/**
 * Extract token from request
 */
const extractToken = (req) => {
  // Check Authorization header
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  
  // Check query parameter (for WebSocket connections)
  if (req.query.token) {
    return req.query.token;
  }
  
  // Check cookie
  if (req.cookies && req.cookies.access_token) {
    return req.cookies.access_token;
  }
  
  return null;
};

/**
 * Authentication middleware
 */
const authenticate = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      await auditSecurityEvent(req, 'missing_token', 'low');
      return res.status(401).json({
        success: false,
        error: 'Authentication token required',
        code: 'TOKEN_MISSING',
      });
    }
    
    // Check if token is blacklisted
    if (await isTokenBlacklisted(token)) {
      await auditSecurityEvent(req, 'blacklisted_token', 'medium');
      return res.status(401).json({
        success: false,
        error: 'Token has been revoked',
        code: 'TOKEN_REVOKED',
      });
    }
    
    // Verify token
    const decoded = verifyToken(token);
    
    // Check if user still exists (optional - can be cached)
    const User = require('../models/User');
    const user = await User.findByPk(decoded.id, {
      attributes: ['id', 'username', 'email', 'role', 'is_active', 'last_login_at'],
    });
    
    if (!user) {
      await auditSecurityEvent(req, 'user_not_found', 'medium', { user_id: decoded.id });
      return res.status(401).json({
        success: false,
        error: 'User not found',
        code: 'USER_NOT_FOUND',
      });
    }
    
    if (!user.is_active) {
      await auditSecurityEvent(req, 'inactive_user', 'medium', { user_id: user.id });
      return res.status(401).json({
        success: false,
        error: 'User account is disabled',
        code: 'USER_DISABLED',
      });
    }
    
    // Attach user and permissions to request
    req.user = user;
    req.permissions = ROLE_PERMISSIONS[user.role] || [];
    req.token = token;
    
    // Update last activity (can be done asynchronously)
    setImmediate(() => {
      user.update({ last_activity_at: new Date() }).catch(err => {
        logger.error('Failed to update user activity', { error: err.message, user_id: user.id });
      });
    });
    
    next();
    
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      await auditSecurityEvent(req, 'expired_token', 'low');
      return res.status(401).json({
        success: false,
        error: 'Token has expired',
        code: 'TOKEN_EXPIRED',
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      await auditSecurityEvent(req, 'invalid_token', 'medium');
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'TOKEN_INVALID',
      });
    }
    
    logger.error('Authentication error', { 
      error: error.message,
      stack: error.stack,
    });
    
    return res.status(500).json({
      success: false,
      error: 'Authentication service error',
      code: 'AUTH_SERVICE_ERROR',
    });
  }
};

/**
 * Optional authentication middleware (doesn't fail if no token)
 */
const optionalAuth = async (req, res, next) => {
  const token = extractToken(req);
  
  if (!token) {
    return next();
  }
  
  try {
    const decoded = verifyToken(token);
    const User = require('../models/User');
    const user = await User.findByPk(decoded.id);
    
    if (user && user.is_active) {
      req.user = user;
      req.permissions = ROLE_PERMISSIONS[user.role] || [];
    }
  } catch (error) {
    // Silently fail for optional auth
    logger.debug('Optional auth failed', { error: error.message });
  }
  
  next();
};

/**
 * Authorization middleware - check permissions
 */
const authorize = (...requiredPermissions) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    }
    
    const userPermissions = req.permissions || [];
    const hasPermission = requiredPermissions.every(permission => 
      userPermissions.includes(permission)
    );
    
    if (!hasPermission) {
      auditSecurityEvent(req, 'unauthorized_access', 'medium', {
        required_permissions: requiredPermissions,
        user_permissions: userPermissions,
      });
      
      return res.status(403).json({
        success: false,
        error: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        required: requiredPermissions,
      });
    }
    
    next();
  };
};

/**
 * Role-based authorization middleware
 */
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED',
      });
    }
    
    if (!roles.includes(req.user.role)) {
      auditSecurityEvent(req, 'role_access_denied', 'medium', {
        required_roles: roles,
        user_role: req.user.role,
      });
      
      return res.status(403).json({
        success: false,
        error: 'Access denied - insufficient role',
        code: 'ROLE_ACCESS_DENIED',
        required_roles: roles,
      });
    }
    
    next();
  };
};

/**
 * API Key authentication middleware (for external systems)
 */
const authenticateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];
    
    if (!apiKey) {
      return res.status(401).json({
        success: false,
        error: 'API key required',
        code: 'API_KEY_MISSING',
      });
    }
    
    // Check API key in database
    const ApiKey = require('../models/ApiKey');
    const keyRecord = await ApiKey.findOne({
      where: { key: apiKey, is_active: true },
      include: ['user'],
    });
    
    if (!keyRecord) {
      await auditSecurityEvent(req, 'invalid_api_key', 'high');
      return res.status(401).json({
        success: false,
        error: 'Invalid API key',
        code: 'API_KEY_INVALID',
      });
    }
    
    // Check expiration
    if (keyRecord.expires_at && keyRecord.expires_at < new Date()) {
      await auditSecurityEvent(req, 'expired_api_key', 'medium');
      return res.status(401).json({
        success: false,
        error: 'API key has expired',
        code: 'API_KEY_EXPIRED',
      });
    }
    
    // Attach user and permissions
    req.user = keyRecord.user;
    req.permissions = ROLE_PERMISSIONS[keyRecord.user.role] || [];
    req.apiKey = keyRecord;
    
    // Update last used
    setImmediate(() => {
      keyRecord.update({ 
        last_used_at: new Date(),
        usage_count: keyRecord.usage_count + 1,
      }).catch(err => {
        logger.error('Failed to update API key usage', { error: err.message });
      });
    });
    
    next();
    
  } catch (error) {
    logger.error('API key authentication error', { error: error.message });
    return res.status(500).json({
      success: false,
      error: 'API key authentication service error',
      code: 'API_AUTH_SERVICE_ERROR',
    });
  }
};

module.exports = {
  authenticate,
  optionalAuth,
  authorize,
  requireRole,
  authenticateApiKey,
  generateToken,
  generateRefreshToken,
  verifyToken,
  verifyRefreshToken,
  hashPassword,
  comparePassword,
  blacklistToken,
  isTokenBlacklisted,
  extractToken,
  ROLES,
  PERMISSIONS,
  ROLE_PERMISSIONS,
};