// Load environment variables from .env file first
require('dotenv').config();

// Core modules
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const compression = require('compression');

// Custom modules
const logger = require('./utils/logger');
const {
  initializeDatabase,
  closeConnections,
  testDatabaseConnection,   // <-- Postgres
  testRedisConnection,      // <-- Redis
} = require('./config/database');
const {
  initializeErrorHandling,
  errorHandler,
  notFoundHandler,
} = require('./middleware/errorHandler');
const { auditMiddleware } = require('./middleware/audit');
const {
  createRateLimiter,
  dynamicRateLimit,
} = require('./middleware/rateLimit'); // no warnings
const { dynamicValidation } = require('./middleware/validation'); // zod dynamic mapping
const { asyncHandler } = require('./middleware/asyncHandler');
const {
  initializeMonitoring,
  performHealthChecks,
  getMetrics,
} = require('./config/monitoring');

// API routes (solo quelle presenti; niente auth)
const adminRoutes = require('./routes/admin');
const firewallRoutes = require('./routes/firewall');
const healthRoutes = require('./routes/health');
const monitoringRoutes = require('./routes/monitoring');
const policiesRoutes = require('./routes/policies');

// Configuration
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin:
    process.env.CORS_ORIGIN ||
    (process.env.NODE_ENV === 'production' ? false : '*'),
  healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL, 10) || 30000,
  shutdownTimeout: parseInt(process.env.SHUTDOWN_TIMEOUT, 10) || 10000,
  requestSizeLimit: process.env.REQUEST_SIZE_LIMIT || '10mb',
  enableSwagger: process.env.ENABLE_SWAGGER !== 'false',
};

// App state
let server;
let healthCheckInterval;
let isShuttingDown = false;

// Initialize error handling for uncaught exceptions and unhandled rejections
initializeErrorHandling();

// Create Express app
const app = express();

// Trust proxy if behind reverse proxy
if (config.nodeEnv === 'production') {
  app.set('trust proxy', 1);
}

// Graceful startup sequence
async function initializeApplication() {
  try {
    logger.info('Starting application initialization...');

    // --- Test connessioni esterne PRIMA di inizializzare ---
    logger.info('Testing PostgreSQL connection...');
    const dbOK = await testDatabaseConnection();
    if (!dbOK) {
      throw new Error('Database connection test failed');
    }
    logger.info('PostgreSQL connection test successful');

    logger.info('Testing Redis connection...');
    const redisOK = await testRedisConnection();
    if (!redisOK) {
      logger.warn('Redis connection test failed, continuing with cache disabled');
    } else {
      logger.info('Redis connection test successful');
    }

    // --- Inizializzazione DB (fa anche sync in dev) ---
    logger.info('Initializing database...');
    await initializeDatabase();
    logger.info('Database initialized successfully');

    // --- Monitoring subsystem ---
    logger.info('Initializing monitoring...');
    await initializeMonitoring();
    logger.info('Monitoring initialized successfully');

    setupMiddleware();
    setupRoutes();
    startHealthChecks();
    await startServer();

    logger.info('Application initialization completed successfully');
  } catch (error) {
    logger.error('Failed to initialize application:', {
      error: error.message,
      stack: error.stack,
    });
    await gracefulShutdown(1);
  }
}

// Middleware
function setupMiddleware() {
  app.use(
    compression({
      filter: (req, res) =>
        req.headers['x-no-compression'] ? false : compression.filter(req, res),
    })
  );

  app.use(
    helmet({
      contentSecurityPolicy:
        config.nodeEnv === 'production'
          ? {
              directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
                fontSrc: ["'self'", 'https://fonts.gstatic.com'],
                imgSrc: ["'self'", 'data:', 'https:'],
                scriptSrc: ["'self'"],
                connectSrc: ["'self'"],
              },
            }
          : false,
      crossOriginEmbedderPolicy: false,
      hsts:
        config.nodeEnv === 'production'
          ? { maxAge: 31536000, includeSubDomains: true, preload: true }
          : false,
    })
  );

  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true); // curl/mobile/no origin
        if (config.corsOrigin === '*') return callback(null, true);
        if (Array.isArray(config.corsOrigin))
          return callback(null, config.corsOrigin.includes(origin));
        if (typeof config.corsOrigin === 'string')
          return callback(null, config.corsOrigin === origin);
        return callback(new Error('Not allowed by CORS'));
      },
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-Api-Key',
        'X-Correlation-ID',
        'X-Request-ID',
        'X-User-Agent',
      ],
      credentials: true,
      optionsSuccessStatus: 200,
      maxAge: 86400, // 24h
    })
  );

  app.use(
    express.json({
      limit: config.requestSizeLimit,
      verify: (req, _res, buf) => {
        req.rawBody = buf;
      },
    })
  );
  app.use(express.urlencoded({ extended: true, limit: config.requestSizeLimit }));

  app.use(cookieParser(process.env.COOKIE_SECRET));

  app.use((req, res, next) => {
    req.id = req.headers['x-request-id'] || require('crypto').randomUUID();
    res.setHeader('X-Request-ID', req.id);
    next();
  });

  const morganFormat =
    config.nodeEnv === 'production'
      ? ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms'
      : ':method :url :status :res[content-length] - :response-time ms';

  app.use(
    morgan(morganFormat, {
      stream: { write: (message) => logger.http(message.trim()) },
      skip: (req, res) => {
        const skipPaths = ['/health', '/metrics', '/api/v1/health'];
        return (
          skipPaths.some((p) => req.originalUrl.includes(p)) ||
          (res.statusCode < 400 && config.nodeEnv === 'production')
        );
      },
    })
  );

  app.use(
    auditMiddleware({
      includeRequestBody: config.nodeEnv !== 'production',
      includeResponseBody: false,
      excludePaths: ['/api/v1/health', '/api/v1/monitoring/prometheus', '/metrics', '/api-docs'],
      sensitiveFields: ['password', 'token', 'secret', 'key'],
    })
  );

  // Global rate limiting (zero warning – nessuna opzione deprecata)
  app.use(
    '/api/',
    createRateLimiter({
      windowMs: 15 * 60 * 1000, // 15 minuti
      max: config.nodeEnv === 'production' ? 1000 : 10000,
      skip: (req) => req.path.includes('/health'),
    })
  );

  // Slow-down/limiter dinamico per endpoint sensibili (config senza warning)
  app.use(dynamicRateLimit);

  // Validazione Zod dinamica per rotta
  app.use(dynamicValidation);
}

// Routes
function setupRoutes() {
  // Health first
  app.use('/api/v1/health', healthRoutes);

  // Metrics (optional IP filter)
  app.get(
    '/metrics',
    asyncHandler(async (req, res) => {
      if (config.nodeEnv === 'production') {
        const allowedIPs = process.env.METRICS_ALLOWED_IPS?.split(',') || [];
        if (allowedIPs.length > 0 && !allowedIPs.includes(req.ip)) {
          return res.status(403).json({ error: 'Access denied' });
        }
      }

      try {
        const metrics = await getMetrics();
        // Supporta sia stringa che oggetto { contentType, data }
        const contentType =
          (metrics && metrics.contentType) || 'text/plain; version=0.0.4; charset=utf-8';
        const payload = (metrics && metrics.data) || metrics || '';
        res.set('Content-Type', contentType);
        res.end(payload);
      } catch (error) {
        logger.error('Failed to get metrics:', error);
        res.status(500).json({ error: 'Failed to retrieve metrics' });
      }
    })
  );

  // API Docs
  if (config.enableSwagger) {
    try {
      const swaggerDocument = YAML.load('./swagger.yaml');
      app.use(
        '/api-docs',
        swaggerUi.serve,
        swaggerUi.setup(swaggerDocument, {
          explorer: true,
          customCss: '.swagger-ui .topbar { display: none }',
          customSiteTitle: 'OPNsense Management API',
        })
      );
      logger.info('Swagger documentation enabled at /api-docs');
    } catch (error) {
      logger.warn('Failed to load Swagger documentation:', error.message);
    }
  }

  // App routes (NO auth middleware)
  app.use('/api/v1/admin', adminRoutes);
  app.use('/api/v1/firewall', firewallRoutes);
  app.use('/api/v1/monitoring', monitoringRoutes);
  app.use('/api/v1/policies', policiesRoutes);

  // API root
  app.get('/api/v1', (_req, res) => {
    res.json({
      name: 'OPNsense Management API',
      version: process.env.npm_package_version || '1.0.0',
      environment: config.nodeEnv,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      endpoints: {
        health: '/api/v1/health',
        docs: config.enableSwagger ? '/api-docs' : null,
        metrics: '/metrics',
      },
    });
  });

  // 404 + error handler
  app.use(notFoundHandler);
  app.use(errorHandler);
}

// Health checks
function startHealthChecks() {
  if (config.healthCheckInterval > 0) {
    healthCheckInterval = setInterval(async () => {
      if (!isShuttingDown) {
        try {
          await performHealthChecks();
        } catch (error) {
          logger.error('Health check failed:', error);
        }
      }
    }, config.healthCheckInterval);

    logger.info(`Health checks started with ${config.healthCheckInterval}ms interval`);
  }
}

// Server
function startServer() {
  return new Promise((resolve, reject) => {
    server = app.listen(config.port, (error) => {
      if (error) return reject(error);

      logger.info(`Server running on port ${config.port} in ${config.nodeEnv} mode`);
      if (config.enableSwagger)
        logger.info(
          `API Documentation available at http://localhost:${config.port}/api-docs`
        );
      logger.info(
        `Health endpoint available at http://localhost:${config.port}/api/v1/health`
      );
      logger.info(`Metrics endpoint available at http://localhost:${config.port}/metrics`);
      resolve();
    });

    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE')
        logger.error(`Port ${config.port} is already in use`);
      else logger.error('Server error:', error);
      reject(error);
    });

    server.timeout = 30000;
  });
}

// Graceful shutdown
async function gracefulShutdown(exitCode = 0) {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress...');
    return;
  }

  isShuttingDown = true;
  logger.info('Initiating graceful shutdown...');

  const shutdownPromise = new Promise((resolve) => {
    let steps = 0;
    const total = 4;
    const done = () => {
      steps += 1;
      if (steps >= total) resolve();
    };

    if (healthCheckInterval) {
      clearInterval(healthCheckInterval);
      logger.info('Health checks stopped');
    }
    done();

    if (server)
      server.close(() => {
        logger.info('HTTP server closed');
        done();
      });
    else done();

    closeConnections()
      .then(() => {
        logger.info('Database connections closed');
        done();
      })
      .catch((error) => {
        logger.error('Error closing database connections:', error);
        done();
      });

    setTimeout(() => {
      logger.info('Additional cleanup completed');
      done();
    }, 100);
  });

  const shutdownTimer = setTimeout(() => {
    logger.warn(`Graceful shutdown timeout after ${config.shutdownTimeout}ms, forcing exit`);
    process.exit(exitCode || 1);
  }, config.shutdownTimeout);

  try {
    await shutdownPromise;
    clearTimeout(shutdownTimer);
    logger.info('Graceful shutdown completed');
    process.exit(exitCode);
  } catch (error) {
    logger.error('Error during graceful shutdown:', error);
    clearTimeout(shutdownTimer);
    process.exit(1);
  }
}

// Signals
process.on('SIGTERM', () => {
  logger.info('Received SIGTERM signal');
  gracefulShutdown(0);
});
process.on('SIGINT', () => {
  logger.info('Received SIGINT signal (Ctrl+C)');
  gracefulShutdown(0);
});
process.on('SIGUSR2', () => {
  logger.info('Received SIGUSR2 signal (nodemon restart)');
  gracefulShutdown(0);
});

// Fatal handlers
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', { error: error.message, stack: error.stack });
  gracefulShutdown(1);
});
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown(1);
});

// Memory monitoring (prod)
if (config.nodeEnv === 'production') {
  setInterval(() => {
    const m = process.memoryUsage();
    const mb = {
      rss: Math.round(m.rss / 1024 / 1024),
      heapTotal: Math.round(m.heapTotal / 1024 / 1024),
      heapUsed: Math.round(m.heapUsed / 1024 / 1024),
      external: Math.round(m.external / 1024 / 1024),
    };
    logger.debug('Memory usage:', mb);
    if (mb.heapUsed > 500) logger.warn('High memory usage detected:', mb);
  }, 60000);
}

// Bootstrap
if (require.main === module) {
  initializeApplication().catch((error) => {
    logger.error('Failed to start application:', error);
    process.exit(1);
  });
}

module.exports = { app, gracefulShutdown };