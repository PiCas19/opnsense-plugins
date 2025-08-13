// src/middleware/rateLimit.js
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const logger = require('../utils/logger');

/** risposta standard quando si sfora il limite */
const rateLimitHandler = (label) => (req, res, _next, options) => {
  const resetMs = Math.max(0, (req.rateLimit?.resetTime || 0) - Date.now());
  logger.warn(`${label} exceeded`, {
    path: req.originalUrl,
    ip: req.ip,
    limit: options.max,
    windowMs: options.windowMs
  });
  return res.status(options.statusCode || 429).json({
    success: false,
    error: 'Too many requests',
    code: 'RATE_LIMIT_ERROR',
    retry_after_seconds: resetMs ? Math.ceil(resetMs / 1000) : undefined
  });
};

const createRateLimiter = (opts = {}) =>
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    handler: rateLimitHandler('rateLimit'),
    // niente onLimitReached (rimosso in v7)
    skip: (req) =>
      req.path.includes('/health') ||
      req.path.startsWith('/metrics') ||
      req.path.startsWith('/api-docs'),
    ...opts,
  });

const createSlowDown = (opts = {}) =>
  slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 100,               // richieste “gratis” prima del delay
    delayMs: () => 200,            // nuovo comportamento v2: delay fisso per richiesta extra
    headers: true,
    // per disattivare l’avviso informativo su delayMs
    validate: { delayMs: false },
    ...opts,
  });

/** utility per concatenare middlewares */
const chain = (middlewares) => (req, res, next) => {
  let i = 0;
  const run = () => (middlewares[i++] || next)(req, res, run);
  run();
};

// profili
const publicChain = chain([
  createRateLimiter({ max: 1000 }),
  createSlowDown({ delayAfter: 300, delayMs: () => 100 })
]);

const sensitiveChain = chain([
  createRateLimiter({ max: 200 }),
  createSlowDown({ delayAfter: 100, delayMs: () => 200 })
]);

/** rate limit “dinamico” per rotte */
const dynamicRateLimit = (req, res, next) => {
  const p = req.path || '';
  if (
    p.startsWith('/api/v1/health') ||
    p.startsWith('/metrics') ||
    p.startsWith('/api-docs')
  ) return next();

  if (
    p.startsWith('/api/v1/admin') ||
    p.startsWith('/api/v1/firewall') ||
    p.startsWith('/api/v1/policies') ||
    p.startsWith('/api/v1/monitoring')
  ) {
    return sensitiveChain(req, res, next);
  }
  return publicChain(req, res, next);
};

module.exports = {
  dynamicRateLimit,
  createRateLimiter,
  createSlowDown,
};