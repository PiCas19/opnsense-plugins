// src/app.js
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const compression = require('compression');

const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerConfig = require('./config/swagger.config');

const logger = require('./utils/logger');
const {
  initializeDatabase,
  closeConnections,
  testDatabaseConnection,
  testRedisConnection,
} = require('./config/database');
const {
  initializeErrorHandling,
  errorHandler,
  notFoundHandler,
} = require('./middleware/errorHandler');
const { auditMiddleware } = require('./middleware/audit');
const { createRateLimiter, dynamicRateLimit } = require('./middleware/rateLimit');
const { dynamicValidation } = require('./middleware/validation');
const { asyncHandler } = require('./middleware/asyncHandler');
const {
  initializeMonitoring,
  performHealthChecks,
  getMetrics,
} = require('./config/monitoring');

// ================ INIZIALIZZAZIONE MODELLI ================
// 1. Prima importa tutti i modelli
const User = require('./models/User');
const Rule = require('./models/Rule');
const Alert = require('./models/Alert');
// ... aggiungi altri modelli se li hai

// 2. Crea un oggetto con tutti i modelli
const models = {
  User,
  Rule,
  Alert,
  // ... altri modelli
};

// 3. Funzione per inizializzare le associazioni
function initializeModelAssociations() {
  logger.info('Initializing model associations...');
  
  try {
    // Inizializza le associazioni per ogni modello che le ha definite
    if (User.associate) {
      logger.debug('Setting up User associations');
      User.associate(models);
    }

    if (Rule.associate) {
      logger.debug('Setting up Rule associations');
      Rule.associate(models);
    }

    if (Alert.associate) {
      logger.debug('Setting up Alert associations');
      Alert.associate(models);
    }

    // Verifica che le associazioni siano state create
    const userAssociations = Object.keys(User.associations || {});
    const ruleAssociations = Object.keys(Rule.associations || {});
    const alertAssociations = Object.keys(Alert.associations || {});

    logger.info('Model associations initialized successfully:', {
      User: userAssociations,
      Rule: ruleAssociations,
      Alert: alertAssociations,
    });

    // Verifica che le associazioni chiave esistano
    if (!Rule.associations.createdBy) {
      logger.warn('Rule.createdBy association not found!');
    }
    if (!Rule.associations.updatedBy) {
      logger.warn('Rule.updatedBy association not found!');
    }
    if (!Alert.associations.rule) {
      logger.warn('Alert.rule association not found!');
    }

    return true;
  } catch (error) {
    logger.error('Failed to initialize model associations:', {
      error: error.message,
      stack: error.stack,
    });
    return false;
  }
}

// ================ END INIZIALIZZAZIONE MODELLI ================

// ---------------- Config ----------------
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

// ---------- Swagger (JSDoc → OpenAPI) ----------
const swaggerSpec = swaggerJsdoc(swaggerConfig);
const swaggerPathsCount = swaggerSpec?.paths ? Object.keys(swaggerSpec.paths).length : 0;
logger.info(`Swagger spec generata: ${swaggerPathsCount} path trovati`);

// ---------------- App state ----------------
let server;
let healthCheckInterval;
let isShuttingDown = false;

// Error handler globali uncaught/unhandled
initializeErrorHandling();

// App
const app = express();

// Trust proxy in prod (dietro reverse proxy)
if (config.nodeEnv === 'production') {
  app.set('trust proxy', parseInt(process.env.TRUST_PROXY || '1', 10));
}

// ---------------- Middleware ----------------

// Compression
app.use(
  compression({
    filter: (req, res) =>
      req.headers['x-no-compression'] ? false : compression.filter(req, res),
  })
);

// Helmet: applica **globalmente**, ma **saltando COMPLETAMENTE /api-docs**
const globalHelmet = helmet({
  contentSecurityPolicy:
    config.nodeEnv === 'production'
      ? {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:', 'https:'],
            scriptSrc: ["'self'"], // NO inline/eval a livello globale
            connectSrc: ["'self'"],
          },
        }
      : false,
  crossOriginEmbedderPolicy: false,
});
app.use((req, res, next) => {
  // SALTA COMPLETAMENTE Helmet per tutti i path che iniziano con /api-docs
  if (req.path.startsWith('/api-docs')) {
    return next();
  }
  return globalHelmet(req, res, next);
});

// CORS
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); // curl/mobile/no origin
      if (config.corsOrigin === '*') return callback(null, true);
      if (Array.isArray(config.corsOrigin)) {
        return callback(null, config.corsOrigin.includes(origin));
      }
      if (typeof config.corsOrigin === 'string') {
        return callback(null, config.corsOrigin.split(',').includes(origin));
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
      'X-User-Agent',
    ],
    credentials: true,
    optionsSuccessStatus: 200,
    maxAge: 86400,
  })
);

// Parser
app.use(
  express.json({
    limit: config.requestSizeLimit,
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);
app.use(express.urlencoded({ extended: true, limit: config.requestSizeLimit }));

// Cookie
app.use(cookieParser(process.env.COOKIE_SECRET));

// Request ID
app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || require('crypto').randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
});

// Log HTTP
const morganFormat =
  config.nodeEnv === 'production'
    ? ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms'
    : ':method :url :status :res[content-length] - :response-time ms';
app.use(
  morgan(morganFormat, {
    stream: { write: msg => logger.http(msg.trim()) },
    skip: (req, res) => {
      const skipPaths = ['/health', '/metrics', '/api/v1/health'];
      return (
        skipPaths.some(p => req.originalUrl.includes(p)) ||
        (res.statusCode < 400 && config.nodeEnv === 'production')
      );
    },
  })
);

// Audit (esclude anche /api-docs/)
app.use(
  auditMiddleware({
    includeRequestBody: config.nodeEnv !== 'production',
    includeResponseBody: false,
    excludePaths: [
      '/api/v1/health',
      '/api/v1/monitoring/prometheus',
      '/metrics',
      '/api-docs',
      '/api-docs/',
    ],
    sensitiveFields: ['password', 'token', 'secret', 'key'],
  })
);

// Rate limit solo sulle API
app.use(
  '/api/',
  createRateLimiter({
    windowMs: 15 * 60 * 1000,
    max: config.nodeEnv === 'production' ? 1000 : 10000,
    skip: req => req.path.includes('/health'),
  })
);
app.use(dynamicRateLimit);

// Validazione dinamica
app.use(dynamicValidation);

// ---------------- Routes ----------------
const adminRoutes = require('./routes/admin');
const firewallRoutes = require('./routes/firewall');
const healthRoutes = require('./routes/health');
const monitoringRoutes = require('./routes/monitoring');
const policiesRoutes = require('./routes/policies');
const authRoutes = require('./routes/auth');

// Health
app.use('/api/v1/health', healthRoutes);

// Metrics (Prometheus)
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
      res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
      res.end(typeof metrics === 'string' ? metrics : String(metrics));
    } catch (error) {
      logger.error('Failed to get metrics:', error);
      res.status(500).json({ error: 'Failed to retrieve metrics' });
    }
  })
);

// ---- Swagger UI (solo se abilitato) ----
if (config.enableSwagger) {
  // DISABILITA COMPLETAMENTE HELMET per /api-docs
  app.use('/api-docs*', (req, res, next) => {
    // Rimuovi tutti gli header di sicurezza per permettere a Swagger di funzionare
    res.removeHeader('Content-Security-Policy');
    res.removeHeader('X-Content-Security-Policy');
    res.removeHeader('X-WebKit-CSP');
    next();
  });

  // Endpoint per lo spec JSON
  app.get('/api-docs.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json(swaggerSpec);
  });

  // Swagger UI con configurazione semplificata
  app.use(
    '/api-docs',
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec, {
      explorer: true,
      swaggerOptions: {
        displayRequestDuration: true,
        tryItOutEnabled: true,
        docExpansion: 'list',
        filter: true,
        showRequestHeaders: true,
      },
      customCss: '.swagger-ui .topbar { display: none }',
      customSiteTitle: 'OPNsense Management API',
    })
  );

  logger.info('Swagger documentation enabled at /api-docs');
  if (swaggerPathsCount === 0) {
    logger.warn('Swagger spec caricata ma senza paths. Aggiungi commenti @swagger nelle routes.');
  }
}

// API vere e proprie
app.use('/api/v1/admin', adminRoutes);
app.use('/api/v1/firewall', firewallRoutes);
app.use('/api/v1/monitoring', monitoringRoutes);
app.use('/api/v1/policies', policiesRoutes);
app.use('/api/v1/auth', authRoutes);

// Root API info
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

// ---------------- Health loop ----------------
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

// ---------------- Server bootstrap ----------------
async function initializeApplication() {
  try {
    logger.info('Starting application initialization...');

    // PROVA il database, ma NON FERMARE L'APP se fallisce
    try {
      logger.info('Testing PostgreSQL connection...');
      const dbOK = await testDatabaseConnection();
      if (dbOK) {
        logger.info('PostgreSQL connection test successful');
        
        logger.info('Initializing database...');
        await initializeDatabase();
        logger.info('Database initialized successfully');
        
        logger.info('Initializing model associations...');
        const associationsOK = initializeModelAssociations();
        if (associationsOK) {
          logger.info('Model associations initialized successfully');
        }
      }
    } catch (dbError) {
      logger.warn('Database failed, continuing anyway:', dbError.message);
    }

    // PROVA Redis
    try {
      logger.info('Testing Redis connection...');
      const redisOK = await testRedisConnection();
      if (redisOK) {
        logger.info('Redis connection test successful');
      }
    } catch (redisError) {
      logger.warn('Redis failed, continuing anyway:', redisError.message);
    }

    // Il resto...
    startHealthChecks();
    await startServer();
    
    logger.info('Application started successfully');
  } catch (error) {
    logger.error('Failed to start:', error.message);
    process.exit(1);
  }
}

function startServer() {
  return new Promise((resolve, reject) => {
    server = app.listen(config.port, err => {
      if (err) return reject(err);
      logger.info(`Server running on port ${config.port} in ${config.nodeEnv} mode`);
      if (config.enableSwagger)
        logger.info(`API Documentation available at http://localhost:${config.port}/api-docs`);
      logger.info(`Health endpoint available at http://localhost:${config.port}/api/v1/health`);
      logger.info(`Metrics endpoint available at http://localhost:${config.port}/metrics`);
      resolve();
    });

    server.on('error', err => {
      if (err.code === 'EADDRINUSE') logger.error(`Port ${config.port} is already in use`);
      else logger.error('Server error:', err);
      reject(err);
    });

    server.timeout = 30000;
  });
}

async function gracefulShutdown(exitCode = 0) {
  if (isShuttingDown) {
    logger.warn('Shutdown already in progress...');
    return;
  }
  isShuttingDown = true;
  logger.info('Initiating graceful shutdown...');

  const shutdownPromise = new Promise(resolve => {
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
      .catch(err => {
        logger.error('Error closing database connections:', err);
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
  } catch (err) {
    logger.error('Error during graceful shutdown:', err);
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
process.on('uncaughtException', err => {
  logger.error('Uncaught Exception:', { error: err.message, stack: err.stack });
  gracefulShutdown(1);
});
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown(1);
});

// Memory monitor (prod)
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
  initializeApplication().catch(err => {
    logger.error('Failed to start application:', err);
    process.exit(1);
  });
}

// ================ ESPORTA I MODELLI INIZIALIZZATI ================
module.exports = { 
  app, 
  gracefulShutdown,
  models: { User, Rule, Alert } // Esporta i modelli per usarli nelle route se necessario
};