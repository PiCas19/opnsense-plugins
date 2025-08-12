// Load environment variables from .env file first
require('dotenv').config();

// Import necessary modules
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

// Import custom modules
const logger = require('./utils/logger');
const { initializeDatabase, closeConnections, testConnection } = require('./config/database');
const { initializeErrorHandling, errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const { auditMiddleware } = require('./middleware/audit');
const { dynamicRateLimit } = require('./middleware/rateLimit');
const { authMiddleware } = require('./middleware/auth');
const { validationMiddleware } = require('./middleware/validation');
const { asyncHandler } = require('./middleware/asyncHandler');
const { initializeMonitoring, performHealthChecks, getMetrics } = require('./config/monitoring');

// Import API routes
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const firewallRoutes = require('./routes/firewall');
const healthRoutes = require('./routes/health');
const monitoringRoutes = require('./routes/monitoring');
const policiesRoutes = require('./routes/policies');

// Configuration
const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  corsOrigin: process.env.CORS_ORIGIN || (process.env.NODE_ENV === 'production' ? false : '*'),
  healthCheckInterval: parseInt(process.env.HEALTH_CHECK_INTERVAL) || 30000,
  shutdownTimeout: parseInt(process.env.SHUTDOWN_TIMEOUT) || 10000,
  requestSizeLimit: process.env.REQUEST_SIZE_LIMIT || '10mb',
  enableSwagger: process.env.ENABLE_SWAGGER !== 'false'
};

// Application state
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

    // 1. Test database connection
    logger.info('Testing database connection...');
    await testConnection();
    logger.info('Database connection test successful');

    // 2. Initialize database
    logger.info('Initializing database...');
    await initializeDatabase();
    logger.info('Database initialized successfully');

    // 3. Initialize monitoring
    logger.info('Initializing monitoring...');
    await initializeMonitoring();
    logger.info('Monitoring initialized successfully');

    // 4. Setup middleware
    setupMiddleware();

    // 5. Setup routes
    setupRoutes();

    // 6. Start health checks
    startHealthChecks();

    // 7. Start server
    await startServer();

    logger.info('Application initialization completed successfully');
  } catch (error) {
    logger.error('Failed to initialize application:', {
      error: error.message,
      stack: error.stack
    });
    await gracefulShutdown(1);
  }
}

// Setup middleware
function setupMiddleware() {
  // Compression middleware
  app.use(compression({
    filter: (req, res) => {
      if (req.headers['x-no-compression']) {
        return false;
      }
      return compression.filter(req, res);
    }
  }));

  // Security middleware with enhanced configuration
  app.use(helmet({
    contentSecurityPolicy: config.nodeEnv === 'production' ? {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'https:'],
        scriptSrc: ["'self'"],
        connectSrc: ["'self'"]
      }
    } : false,
    crossOriginEmbedderPolicy: false,
    hsts: config.nodeEnv === 'production' ? {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    } : false
  }));

  // CORS middleware with environment-specific configuration
  app.use(cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (like mobile apps or curl requests)
      if (!origin) return callback(null, true);

      if (config.corsOrigin === '*') {
        return callback(null, true);
      }

      if (Array.isArray(config.corsOrigin)) {
        return callback(null, config.corsOrigin.includes(origin));
      }

      if (typeof config.corsOrigin === 'string') {
        return callback(null, config.corsOrigin === origin);
      }

      return callback(new Error('Not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type', 
      'Authorization', 
      'X-Api-Key', 
      'X-Correlation-ID',
      'X-Request-ID',
      'X-User-Agent'
    ],
    credentials: true,
    optionsSuccessStatus: 200,
    maxAge: 86400 // 24 hours
  }));

  // Request parsing middleware
  app.use(express.json({ 
    limit: config.requestSizeLimit,
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  }));
  
  app.use(express.urlencoded({ 
    extended: true, 
    limit: config.requestSizeLimit 
  }));

  // Cookie parser
  app.use(cookieParser(process.env.COOKIE_SECRET));

  // Request ID middleware
  app.use((req, res, next) => {
    req.id = req.headers['x-request-id'] || require('crypto').randomUUID();
    res.setHeader('X-Request-ID', req.id);
    next();
  });

  // HTTP request logging with enhanced configuration
  const morganFormat = config.nodeEnv === 'production' ? 
    ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms' :
    ':method :url :status :res[content-length] - :response-time ms';

  app.use(morgan(morganFormat, {
    stream: {
      write: (message) => logger.http(message.trim())
    },
    skip: (req, res) => {
      // Skip health and metrics endpoints for cleaner logs
      const skipPaths = ['/health', '/metrics', '/api/v1/health'];
      return skipPaths.some(path => req.originalUrl.includes(path)) || 
             (res.statusCode < 400 && config.nodeEnv === 'production');
    }
  }));

  // Audit middleware
  app.use(auditMiddleware({
    includeRequestBody: config.nodeEnv !== 'production',
    includeResponseBody: false,
    excludePaths: [
      '/api/v1/health',
      '/api/v1/monitoring/prometheus',
      '/metrics',
      '/api-docs'
    ],
    sensitiveFields: ['password', 'token', 'secret', 'key']
  }));

  // Global rate limiting
  app.use('/api/', rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: config.nodeEnv === 'production' ? 1000 : 10000, // requests per windowMs
    message: {
      error: 'Too many requests from this IP, please try again later.',
      retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path.includes('/health');
    }
  }));

  // Dynamic rate limiting for sensitive endpoints
  app.use(dynamicRateLimit);

  // Request validation middleware
  app.use(validationMiddleware);
}

// Setup routes
function setupRoutes() {
  // Health check endpoint (before authentication)
  app.use('/api/v1/health', healthRoutes);

  // Prometheus metrics endpoint (unauthenticated but with IP filtering if needed)
  app.get('/metrics', asyncHandler(async (req, res) => {
    // Optional: Add IP filtering for metrics endpoint in production
    if (config.nodeEnv === 'production') {
      const allowedIPs = process.env.METRICS_ALLOWED_IPS?.split(',') || [];
      if (allowedIPs.length > 0 && !allowedIPs.includes(req.ip)) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    try {
      const metrics = await getMetrics();
      res.set('Content-Type', metrics.contentType || 'text/plain');
      res.end(metrics.data || metrics);
    } catch (error) {
      logger.error('Failed to get metrics:', error);
      res.status(500).json({ error: 'Failed to retrieve metrics' });
    }
  }));

  // API Documentation (conditionally enabled)
  if (config.enableSwagger) {
    try {
      const swaggerDocument = YAML.load('./swagger.yaml');
      app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
        explorer: true,
        customCss: '.swagger-ui .topbar { display: none }',
        customSiteTitle: 'OPNsense Management API'
      }));
      logger.info('Swagger documentation enabled at /api-docs');
    } catch (error) {
      logger.warn('Failed to load Swagger documentation:', error.message);
    }
  }

  // Authentication routes (no auth middleware)
  app.use('/api/v1/auth', authRoutes);

  // Protected API routes (with authentication middleware)
  app.use('/api/v1/admin', authMiddleware, adminRoutes);
  app.use('/api/v1/firewall', authMiddleware, firewallRoutes);
  app.use('/api/v1/monitoring', authMiddleware, monitoringRoutes);
  app.use('/api/v1/policies', authMiddleware, policiesRoutes);

  // API root endpoint
  app.get('/api/v1', (req, res) => {
    res.json({
      name: 'OPNsense Management API',
      version: process.env.npm_package_version || '1.0.0',
      environment: config.nodeEnv,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      endpoints: {
        health: '/api/v1/health',
        docs: config.enableSwagger ? '/api-docs' : null,
        metrics: '/metrics'
      }
    });
  });

  // Fallback handler for unknown routes
  app.use(notFoundHandler);

  // Global error handling middleware (must be last)
  app.use(errorHandler);
}

// Start health checks
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

// Start server
function startServer() {
  return new Promise((resolve, reject) => {
    server = app.listen(config.port, (error) => {
      if (error) {
        return reject(error);
      }

      logger.info(`Server running on port ${config.port} in ${config.nodeEnv} mode`);
      
      if (config.enableSwagger) {
        logger.info(`API Documentation available at http://localhost:${config.port}/api-docs`);
      }
      
      logger.info(`Health endpoint available at http://localhost:${config.port}/api/v1/health`);
      logger.info(`Metrics endpoint available at http://localhost:${config.port}/metrics`);
      
      resolve();
    });

    // Handle server errors
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`Port ${config.port} is already in use`);
      } else {
        logger.error('Server error:', error);
      }
      reject(error);
    });

    // Set server timeout
    server.timeout = 30000; // 30 seconds
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
    let shutdownSteps = 0;
    const totalSteps = 4;

    const checkComplete = () => {
      shutdownSteps++;
      if (shutdownSteps >= totalSteps) {
        resolve();
      }
    };

    // Stop health checks
    if (healthCheckInterval) {
      clearInterval(healthCheckInterval);
      logger.info('Health checks stopped');
    }
    checkComplete();

    // Close HTTP server
    if (server) {
      server.close(() => {
        logger.info('HTTP server closed');
        checkComplete();
      });
    } else {
      checkComplete();
    }

    // Close database connections
    closeConnections()
      .then(() => {
        logger.info('Database connections closed');
        checkComplete();
      })
      .catch((error) => {
        logger.error('Error closing database connections:', error);
        checkComplete();
      });

    // Additional cleanup
    setTimeout(() => {
      logger.info('Additional cleanup completed');
      checkComplete();
    }, 100);
  });

  // Wait for graceful shutdown or timeout
  const shutdownTimeout = setTimeout(() => {
    logger.warn(`Graceful shutdown timeout after ${config.shutdownTimeout}ms, forcing exit`);
    process.exit(exitCode || 1);
  }, config.shutdownTimeout);

  try {
    await shutdownPromise;
    clearTimeout(shutdownTimeout);
    logger.info('Graceful shutdown completed');
    process.exit(exitCode);
  } catch (error) {
    logger.error('Error during graceful shutdown:', error);
    clearTimeout(shutdownTimeout);
    process.exit(1);
  }
}

// Signal handlers
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

// Handle uncaught exceptions gracefully
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', {
    error: error.message,
    stack: error.stack
  });
  gracefulShutdown(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown(1);
});

// Memory monitoring
if (config.nodeEnv === 'production') {
  setInterval(() => {
    const memoryUsage = process.memoryUsage();
    const memoryUsageMB = {
      rss: Math.round(memoryUsage.rss / 1024 / 1024),
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024),
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024),
      external: Math.round(memoryUsage.external / 1024 / 1024)
    };

    logger.debug('Memory usage:', memoryUsageMB);

    // Alert if memory usage is high
    if (memoryUsageMB.heapUsed > 500) { // 500MB threshold
      logger.warn('High memory usage detected:', memoryUsageMB);
    }
  }, 60000); // Check every minute
}

// Start the application
if (require.main === module) {
  initializeApplication().catch((error) => {
    logger.error('Failed to start application:', error);
    process.exit(1);
  });
}

// Export app for testing
module.exports = { app, gracefulShutdown };