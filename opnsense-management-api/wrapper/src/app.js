// FORZA disabilitazione SSL PRIMA di tutto
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');

const logger = require('./utils/logger');
const { errorHandler, notFound } = require('./middleware/errorHandler');
const { initializeDatabase, testConnection, closeDatabase } = require('./config/database');
const { swaggerSpec, swaggerUi, swaggerUiOptions } = require('./config/swagger');

// Log SSL configuration
logger.info('🔓 SSL TLS verification DISABILITATA globalmente', {
  NODE_TLS_REJECT_UNAUTHORIZED: process.env.NODE_TLS_REJECT_UNAUTHORIZED
});

// Routes
const authRoutes = require('./routes/auth');
const rulesRoutes = require('./routes/rules');
const usersRoutes = require('./routes/users');
const healthRoutes = require('./routes/health');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy per rate limiting
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false // Disabilita CSP per API e Swagger UI
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));

app.use(compression());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minuti
  max: 100, // massimo 100 richieste per IP
  message: {
    error: 'Troppe richieste da questo IP, riprova più tardi'
  }
});
app.use('/api', limiter);

// Body parsing
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf, encoding) => {
    try {
      JSON.parse(buf);
    } catch (e) {
      logger.error('JSON non valido nel body della richiesta', {
        error: e.message,
        body: buf.toString().substring(0, 200),
        url: req.originalUrl,
        method: req.method
      });
      res.status(400).json({
        success: false,
        message: 'JSON non valido nel body della richiesta',
        error: 'Invalid JSON syntax'
      });
      throw new Error('Invalid JSON');
    }
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  next();
});

/**
 * @swagger
 * /:
 *   get:
 *     summary: Root endpoint
 *     description: Informazioni generali sull'API
 *     tags: [General]
 *     responses:
 *       200:
 *         description: Informazioni API
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 version:
 *                   type: string
 *                 status:
 *                   type: string
 *                 endpoints:
 *                   type: object
 */
app.get('/', (req, res) => {
  res.json({
    message: 'OPNsense Firewall API',
    version: process.env.npm_package_version || '1.0.0',
    status: 'running',
    environment: process.env.NODE_ENV || 'development',
    ssl_disabled: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0',
    endpoints: {
      auth: '/api/auth',
      rules: '/api/rules',
      users: '/api/users',
      health: '/api/health',
      docs: '/api-docs'
    }
  });
});

// Swagger documentation
app.use('/api-docs', swaggerUi.serve);
app.get('/api-docs', swaggerUi.setup(swaggerSpec, swaggerUiOptions));

// Swagger JSON endpoint
app.get('/api-docs.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/health', healthRoutes);

// 404 handler
app.use(notFound);

// Error handler
app.use(errorHandler);

// Database initialization and server startup
async function startServer() {
  try {
    // Test database connection
    logger.info('Testing database connection...');
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Database connection failed');
    }

    // Initialize database
    logger.info('Initializing database...');
    await initializeDatabase();

    // Log OPNsense configuration
    logger.info('OPNsense Configuration Status:', {
      host: process.env.OPNSENSE_HOST || 'NOT SET',
      hasApiKey: !!process.env.OPNSENSE_API_KEY,
      hasApiSecret: !!process.env.OPNSENSE_API_SECRET,
      verifySSL: process.env.OPNSENSE_VERIFY_SSL,
      sslGloballyDisabled: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
    });

    // Start server
    const server = app.listen(PORT, () => {
      logger.info(`Server avviato sulla porta ${PORT}`, {
        environment: process.env.NODE_ENV || 'development',
        database: 'SQLite',
        swagger_docs: `http://localhost:${PORT}/api-docs`,
        ssl_verification: process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? 'DISABLED' : 'ENABLED'
      });
      
      console.log('\n🚀 OPNsense Firewall Management API');
      console.log('=====================================');
      console.log(`📊 Server: http://localhost:${PORT}`);
      console.log(`📚 Swagger UI: http://localhost:${PORT}/api-docs`);
      console.log(`📋 JSON Schema: http://localhost:${PORT}/api-docs.json`);
      console.log(`🔓 SSL Verification: ${process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' ? 'DISABLED (OK per certificati auto-firmati)' : 'ENABLED'}`);
      console.log(`🏠 OPNsense Host: ${process.env.OPNSENSE_HOST || 'NOT CONFIGURED'}`);
      console.log('=====================================\n');
    });

    // Graceful shutdown handlers
    const gracefulShutdown = async (signal) => {
      logger.info(`${signal} ricevuto, chiusura server...`);
      
      server.close(async () => {
        logger.info('Server chiuso');
        
        // Close database connection
        try {
          await closeDatabase();
          logger.info('Database connection chiusa');
        } catch (error) {
          logger.error('Errore nella chiusura database:', error);
        }
        
        process.exit(0);
      });

      // Force close after 10 seconds
      setTimeout(() => {
        logger.error('Forzata chiusura server dopo timeout');
        process.exit(1);
      }, 10000);
    };

    // Signal handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', {
        message: error.message,
        stack: error.stack
      });
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection:', {
        reason: reason instanceof Error ? reason.message : reason,
        stack: reason instanceof Error ? reason.stack : undefined,
        promise: promise.toString()
      });
      process.exit(1);
    });

    // Log startup completion
    logger.info('🎉 Server startup completato con successo');

  } catch (error) {
    logger.error('❌ Failed to start server:', {
      message: error.message,
      stack: error.stack
    });
    process.exit(1);
  }
}

// Start server only if not in test environment
if (process.env.NODE_ENV !== 'test') {
  startServer();
}

module.exports = app;