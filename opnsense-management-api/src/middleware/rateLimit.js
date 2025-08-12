const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const { cache } = require('../config/database');
const logger = require('../utils/logger');
const { RateLimitError } = require('./errorHandler');

// Rate limit configurations
const RATE_LIMIT_CONFIGS = {
  // General API rate limiting
  general: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Authentication endpoints (stricter)
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // 10 attempts per window
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Firewall operations (moderate)
  firewall: {
    windowMs: 5 * 60 * 1000, // 5 minutes
    max: 50, // 50 operations per window
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Critical operations (very strict)
  critical: {
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 5, // 5 operations per window
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Admin operations
  admin: {
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 20, // 20 operations per window
    standardHeaders: true,
    legacyHeaders: false,
  },
  
  // Monitoring endpoints (more permissive)
  monitoring: {
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 300, // 300 requests per minute
    standardHeaders: true,
    legacyHeaders: false,
  },
};

// Slowdown configurations for progressive delays
const SLOWDOWN_CONFIGS = {
  general: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 50, // Start slowing down after 50 requests
    delayMs: 100, // Add 100ms delay per request after delayAfter
    maxDelayMs: 20000, // Maximum delay of 20 seconds
  },
  
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    delayAfter: 5, // Start slowing down after 5 requests
    delayMs: 1000, // Add 1 second delay per request
    maxDelayMs: 30000, // Maximum delay of 30 seconds
  },
};

/**
 * Custom rate limit store using Redis
 */
class RedisStore {
  constructor(options = {}) {
    this.prefix = options.prefix || 'rl:';
    this.resetExpiryOnChange = options.resetExpiryOnChange || false;
  }

  async increment(key) {
    try {
      const prefixedKey = this.prefix + key;
      const current = await cache.get(prefixedKey);
      
      if (current) {
        const newValue = current.count + 1;
        await cache.set(prefixedKey, { count: newValue, resetTime: current.resetTime });
        return {
          totalHits: newValue,
          resetTime: current.resetTime,
        };
      } else {
        const resetTime = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now
        await cache.set(prefixedKey, { count: 1, resetTime }, 15 * 60); // 15 minutes TTL
        return {
          totalHits: 1,
          resetTime,
        };
      }
    } catch (error) {
      logger.error('Redis rate limit store error', { error: error.message, key });
      // Fallback to allowing the request
      return {
        totalHits: 1,
        resetTime: new Date(Date.now() + 15 * 60 * 1000),
      };
    }
  }

  async decrement(key) {
    try {
      const prefixedKey = this.prefix + key;
      const current = await cache.get(prefixedKey);
      
      if (current && current.count > 0) {
        const newValue = current.count - 1;
        await cache.set(prefixedKey, { count: newValue, resetTime: current.resetTime });
      }
    } catch (error) {
      logger.error('Redis rate limit decrement error', { error: error.message, key });
    }
  }

  async resetKey(key) {
    try {
      const prefixedKey = this.prefix + key;
      await cache.del(prefixedKey);
    } catch (error) {
      logger.error('Redis rate limit reset error', { error: error.message, key });
    }
  }
}

/**
 * Get client identifier for rate limiting
 */
const getClientId = (req) => {
  // Use user ID if authenticated
  if (req.user?.id) {
    return `user:${req.user.id}`;
  }
  
  // Use API key if present
  if (req.apiKey?.id) {
    return `apikey:${req.apiKey.id}`;
  }
  
  // Fall back to IP address
  return `ip:${req.ip}`;
};

/**
 * Custom key generator for rate limiting
 */
const keyGenerator = (req) => {
  const clientId = getClientId(req);
  const route = req.route?.path || req.path;
  return `${clientId}:${route}`;
};

/**
 * Custom handler for rate limit exceeded
 */
const rateLimitHandler = (req, res, next) => {
  const clientId = getClientId(req);
  
  // Log rate limit violation
  logger.warn('Rate limit exceeded', {
    client_id: clientId,
    ip: req.ip,
    user_id: req.user?.id,
    route: req.route?.path || req.path,
    method: req.method,
    user_agent: req.get('User-Agent'),
  });
  
  // Record metrics
  try {
    const { metricsHelpers } = require('../config/monitoring');
    metricsHelpers.recordRateLimitHit(req.ip, req.path);
  } catch (error) {
    // Monitoring not available
  }
  
  // Create error
  const error = new RateLimitError('Rate limit exceeded', {
    client_id: clientId,
    retry_after: res.get('Retry-After'),
    limit: res.get('X-RateLimit-Limit'),
    remaining: res.get('X-RateLimit-Remaining'),
    reset: res.get('X-RateLimit-Reset'),
  });
  
  next(error);
};

/**
 * Skip rate limiting based on conditions
 */
const skipRateLimit = (req) => {
  // Skip for health checks
  if (req.path === '/health' || req.path.startsWith('/health/')) {
    return true;
  }
  
  // Skip for metrics endpoint
  if (req.path === '/metrics') {
    return true;
  }
  
  // Skip for admin users in development
  if (process.env.NODE_ENV === 'development' && req.user?.role === 'admin') {
    return true;
  }
  
  // Skip based on custom header
  if (req.headers['x-skip-rate-limit'] === 'true' && req.user?.role === 'admin') {
    return true;
  }
  
  return false;
};

/**
 * Create rate limiter with custom configuration
 */
const createRateLimiter = (config = {}) => {
  const mergedConfig = {
    ...RATE_LIMIT_CONFIGS.general,
    ...config,
    store: new RedisStore({ prefix: `rl:${config.name || 'default'}:` }),
    keyGenerator,
    handler: rateLimitHandler,
    skip: skipRateLimit,
    onLimitReached: (req, res, options) => {
      logger.warn('Rate limit reached', {
        client_id: getClientId(req),
        ip: req.ip,
        route: req.route?.path || req.path,
        limit: options.max,
        window: options.windowMs,
      });
    },
  };
  
  return rateLimit(mergedConfig);
};

/**
 * Create progressive slowdown middleware
 */
const createSlowDown = (config = {}) => {
  const mergedConfig = {
    ...SLOWDOWN_CONFIGS.general,
    ...config,
    keyGenerator,
    skip: skipRateLimit,
    onLimitReached: (req, res, options) => {
      logger.warn('Slowdown activated', {
        client_id: getClientId(req),
        ip: req.ip,
        route: req.route?.path || req.path,
        delay: res.slowDown?.delay || 0,
      });
    },
  };
  
  return slowDown(mergedConfig);
};

// Pre-configured rate limiters
const rateLimiters = {
  // General API rate limiter
  general: createRateLimiter({
    name: 'general',
    ...RATE_LIMIT_CONFIGS.general,
  }),
  
  // Authentication rate limiter
  auth: createRateLimiter({
    name: 'auth',
    ...RATE_LIMIT_CONFIGS.auth,
  }),
  
  // Firewall operations rate limiter
  firewall: createRateLimiter({
    name: 'firewall',
    ...RATE_LIMIT_CONFIGS.firewall,
  }),
  
  // Critical operations rate limiter
  critical: createRateLimiter({
    name: 'critical',
    ...RATE_LIMIT_CONFIGS.critical,
  }),
  
  // Admin operations rate limiter
  admin: createRateLimiter({
    name: 'admin',
    ...RATE_LIMIT_CONFIGS.admin,
  }),
  
  // Monitoring endpoints rate limiter
  monitoring: createRateLimiter({
    name: 'monitoring',
    ...RATE_LIMIT_CONFIGS.monitoring,
  }),
};

// Progressive slowdown middlewares
const slowDowns = {
  general: createSlowDown({
    name: 'general',
    ...SLOWDOWN_CONFIGS.general,
  }),
  
  auth: createSlowDown({
    name: 'auth',
    ...SLOWDOWN_CONFIGS.auth,
  }),
};

/**
 * Dynamic rate limiter based on endpoint
 */
const dynamicRateLimit = (req, res, next) => {
  let limiter;
  
  // Determine which rate limiter to use based on route
  if (req.path.startsWith('/api/v1/auth/')) {
    limiter = rateLimiters.auth;
  } else if (req.path.startsWith('/api/v1/admin/')) {
    limiter = rateLimiters.admin;
  } else if (req.path.startsWith('/api/v1/firewall/')) {
    limiter = rateLimiters.firewall;
  } else if (req.path.startsWith('/api/v1/monitoring/') || req.path.startsWith('/api/v1/health/')) {
    limiter = rateLimiters.monitoring;
  } else if (req.path.includes('/reboot') || req.path.includes('/shutdown') || req.path.includes('/apply')) {
    limiter = rateLimiters.critical;
  } else {
    limiter = rateLimiters.general;
  }
  
  limiter(req, res, next);
};

/**
 * Whitelist certain IPs from rate limiting
 */
const createWhitelistRateLimit = (whitelist = []) => {
  return (req, res, next) => {
    if (whitelist.includes(req.ip)) {
      logger.debug('Rate limit bypassed for whitelisted IP', { ip: req.ip });
      return next();
    }
    
    dynamicRateLimit(req, res, next);
  };
};

/**
 * Rate limit status endpoint
 */
const getRateLimitStatus = async (req, res) => {
  try {
    const clientId = getClientId(req);
    const prefix = 'rl:';
    
    // Get status for different rate limiters
    const statuses = {};
    
    for (const [name, config] of Object.entries(RATE_LIMIT_CONFIGS)) {
      const key = `${prefix}${name}:${clientId}:${req.path}`;
      const data = await cache.get(key);
      
      statuses[name] = {
        requests_made: data?.count || 0,
        requests_remaining: Math.max(0, config.max - (data?.count || 0)),
        reset_time: data?.resetTime || new Date(Date.now() + config.windowMs),
        window_ms: config.windowMs,
        max_requests: config.max,
      };
    }
    
    res.json({
      success: true,
      client_id: clientId,
      rate_limits: statuses,
    });
  } catch (error) {
    logger.error('Rate limit status error', { error: error.message });
    res.status(500).json({
      success: false,
      error: 'Unable to retrieve rate limit status',
    });
  }
};

module.exports = {
  // Middleware
  dynamicRateLimit,
  createRateLimiter,
  createSlowDown,
  createWhitelistRateLimit,
  
  // Pre-configured limiters
  rateLimiters,
  slowDowns,
  
  // Utilities
  getClientId,
  keyGenerator,
  rateLimitHandler,
  skipRateLimit,
  getRateLimitStatus,
  
  // Store
  RedisStore,
  
  // Configurations
  RATE_LIMIT_CONFIGS,
  SLOWDOWN_CONFIGS,
};