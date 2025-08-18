// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { cache } = require('../config/database');
const logger = require('../utils/logger');
const { auditSecurityEvent } = require('./audit');

/* ====== CONFIG ====== */
const ACCESS_SECRET  = process.env.JWT_SECRET;                         // obbligatorio
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || ACCESS_SECRET; // opzionale, altrimenti stesso secret
const ACCESS_TTL     = process.env.JWT_EXPIRES_IN || '12h';
const REFRESH_TTL    = process.env.JWT_REFRESH_EXPIRES_IN || '7d';

if (!ACCESS_SECRET || ACCESS_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set and at least 32 characters long');
}

/* ====== ROLES / PERMISSIONS ====== */
const ROLES = { ADMIN: 'admin', OPERATOR: 'operator', VIEWER: 'viewer', API_USER: 'api_user' };

const PERMISSIONS = {
  FIREWALL_READ: 'firewall:read', FIREWALL_WRITE: 'firewall:write',
  FIREWALL_DELETE: 'firewall:delete', FIREWALL_TOGGLE: 'firewall:toggle',
  POLICY_READ: 'policy:read', POLICY_WRITE: 'policy:write', POLICY_DELETE: 'policy:delete',
  SYSTEM_READ: 'system:read', SYSTEM_WRITE: 'system:write', SYSTEM_ADMIN: 'system:admin',
  MONITORING_READ: 'monitoring:read', MONITORING_WRITE: 'monitoring:write',
  USER_MANAGE: 'user:manage', AUDIT_READ: 'audit:read', CONFIG_MANAGE: 'config:manage',
};

const ROLE_PERMISSIONS = {
  [ROLES.ADMIN]: Object.values(PERMISSIONS),
  [ROLES.OPERATOR]: [
    PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE, PERMISSIONS.FIREWALL_TOGGLE,
    PERMISSIONS.POLICY_READ, PERMISSIONS.POLICY_WRITE, PERMISSIONS.SYSTEM_READ, PERMISSIONS.MONITORING_READ,
  ],
  [ROLES.VIEWER]: [
    PERMISSIONS.FIREWALL_READ, PERMISSIONS.POLICY_READ, PERMISSIONS.SYSTEM_READ, PERMISSIONS.MONITORING_READ,
  ],
  [ROLES.API_USER]: [
    PERMISSIONS.FIREWALL_READ, PERMISSIONS.FIREWALL_WRITE, PERMISSIONS.FIREWALL_TOGGLE, PERMISSIONS.MONITORING_READ,
  ],
};

/* ====== HELPERS ====== */
const getBearer = (h) => {
  if (!h) return null;
  const m = String(h).trim().match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
};

const extractAccessToken = (req) =>
  getBearer(req.headers.authorization) || req.query?.token || req.cookies?.access_token || null;

const extractRefreshToken = (req) =>
  req.cookies?.refresh_token || getBearer(req.headers['x-refresh-token']) || req.body?.refresh_token || null;

const parseExpiration = (val) => {
  if (typeof val === 'number') return val;
  const m = String(val).match(/^(\d+)([smhd])$/i);
  if (!m) return 3600;
  const n = parseInt(m[1], 10);
  return { s:1, m:60, h:3600, d:86400 }[m[2].toLowerCase()] * n;
};

const mapJwtError = (e) => {
  if (e?.name === 'TokenExpiredError') return { code: 'TOKEN_EXPIRED', msg: 'Token has expired' };
  if (e?.name === 'JsonWebTokenError') return { code: 'TOKEN_INVALID', msg: e.message || 'Invalid token' };
  return { code: 'AUTH_SERVICE_ERROR', msg: 'Authentication service error' };
};

/* ====== SIGN / VERIFY ====== */
const signAccessToken = (payload, expiresIn = ACCESS_TTL) =>
  jwt.sign({ ...payload, type: 'access_token' }, ACCESS_SECRET, {
    expiresIn, issuer: 'opnsense-management-api', audience: 'opnsense-users', jwtid: uuidv4(),
  });

const signRefreshToken = (payload, expiresIn = REFRESH_TTL) =>
  jwt.sign({ ...payload, type: 'refresh_token' }, REFRESH_SECRET, {
    expiresIn, issuer: 'opnsense-management-api', audience: 'opnsense-refresh', jwtid: uuidv4(),
  });

const verifyAccessToken = (t) =>
  jwt.verify(t, ACCESS_SECRET, { issuer: 'opnsense-management-api', audience: 'opnsense-users' });

const verifyRefreshToken = (t) =>
  jwt.verify(t, REFRESH_SECRET, { issuer: 'opnsense-management-api', audience: 'opnsense-refresh' });

/* ====== COOKIE UTILS ====== */
const setRefreshCookie = (res, token, maxAgeMs) => {
  res.cookie('refresh_token', token, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production',
    sameSite: 'Lax', path: '/api/v1/auth', maxAge: maxAgeMs,
  });
};

const clearRefreshCookie = (res) => {
  res.clearCookie('refresh_token', { path: '/api/v1/auth' });
};

/* ====== REDIS (blacklist/allowlist) ====== */
// Access token blacklist by JTI
const blacklistAccessJti = async (jti, exp, iat) => {
  try {
    const ttl = Math.max(1, (exp - iat) || parseExpiration(ACCESS_TTL));
    if (cache?.set) await cache.set(`bl:acc:${jti}`, true, ttl);
  } catch (e) { logger.error('blacklistAccessJti', { error: e.message }); }
};
const isAccessBlacklisted = async (jti) => {
  try { return !!(await cache?.get?.(`bl:acc:${jti}`)); } catch { return false; }
};

// Refresh allowlist by JTI (abilita revoca/rotazione)
const allowRefreshJti = async (jti, userId, exp, iat) => {
  try {
    const ttl = Math.max(1, (exp - iat) || parseExpiration(REFRESH_TTL));
    if (cache?.set) await cache.set(`rt:${jti}`, String(userId), ttl);
  } catch (e) { logger.error('allowRefreshJti', { error: e.message }); }
};
const revokeRefreshJti = async (jti) => {
  try { if (cache?.del) await cache.del(`rt:${jti}`); } catch (e) { logger.error('revokeRefreshJti', { error: e.message }); }
};
const isRefreshAllowed = async (jti) => {
  try { return !!(await cache?.get?.(`rt:${jti}`)); } catch { return true; } // se niente Redis, allow
};

/* ====== PASSWORD ====== */
const hashPassword = async (password) => {
  const rounds = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10);
  return bcrypt.hash(password, rounds);
};
const comparePassword = (password, hash) => bcrypt.compare(password, hash);

/* ====== MIDDLEWARE ====== */
// Richiede un **access token**
const authenticate = async (req, res, next) => {
  try {
    const token = extractAccessToken(req);
    if (!token) {
      await auditSecurityEvent(req, 'missing_token', 'low');
      return res.status(401).json({ success:false, error:'Authentication token required', code:'TOKEN_MISSING' });
    }

    let payload;
    try { payload = verifyAccessToken(token); }
    catch (e) { const m = mapJwtError(e); await auditSecurityEvent(req, m.code.toLowerCase(), 'medium'); return res.status(401).json({ success:false, error:m.msg, code:m.code }); }

    if (payload.type !== 'access_token') return res.status(401).json({ success:false, error:'Access token required', code:'TOKEN_WRONG_TYPE' });
    if (await isAccessBlacklisted(payload.jti)) return res.status(401).json({ success:false, error:'Token revoked', code:'TOKEN_REVOKED' });

    const User = require('../models/User');
    const user = await User.findByPk(payload.id, { attributes: ['id','username','email','role','is_active','last_login'] });
    if (!user) return res.status(401).json({ success:false, error:'User not found', code:'USER_NOT_FOUND' });
    if (!user.is_active) return res.status(401).json({ success:false, error:'User account is disabled', code:'USER_DISABLED' });

    req.user = user;
    req.permissions = ROLE_PERMISSIONS[user.role] || [];
    req.tokenData = payload;
    setImmediate(() => user.update({ last_activity_at: new Date() }).catch(() => {}));
    return next();
  } catch (err) {
    logger.error('authenticate crashed', { error: err.message });
    try { await auditSecurityEvent(req, 'auth_error', 'medium', { message: err.message }); } catch {}
    return res.status(500).json({ success:false, error:'Authentication service error', code:'AUTH_SERVICE_ERROR' });
  }
};

/* ====== AUTHZ ====== */
const authorize = (...required) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success:false, error:'Authentication required', code:'AUTH_REQUIRED' });
  const ok = required.every(p => (req.permissions || []).includes(p));
  if (!ok) {
    auditSecurityEvent(req, 'unauthorized_access', 'medium', { required_permissions: required, user_permissions: req.permissions });
    return res.status(403).json({ success:false, error:'Insufficient permissions', code:'INSUFFICIENT_PERMISSIONS', required });
  }
  next();
};
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success:false, error:'Authentication required', code:'AUTH_REQUIRED' });
  if (!roles.includes(req.user.role)) {
    auditSecurityEvent(req, 'role_access_denied', 'medium', { required_roles: roles, user_role: req.user.role });
    return res.status(403).json({ success:false, error:'Access denied - insufficient role', code:'ROLE_ACCESS_DENIED', required_roles: roles });
  }
  next();
};

/* ====== EXPORT ====== */
module.exports = {
  // middleware
  authenticate, authorize, requireRole,

  // tokens
  signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken,

  // cookies
  setRefreshCookie, clearRefreshCookie,

  // redis utils
  blacklistAccessJti, isAccessBlacklisted,
  allowRefreshJti, revokeRefreshJti, isRefreshAllowed,

  // password
  hashPassword, comparePassword,

  // roles
  ROLES, PERMISSIONS, ROLE_PERMISSIONS,
};