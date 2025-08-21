const express = require('express');
const OpnsenseService = require('../services/OpnsenseService');
const { optionalAuth } = require('../middleware/auth');
const asyncHandler = require('express-async-handler');

const router = express.Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     HealthResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         message:
 *           type: string
 *           example: API funzionante
 *         timestamp:
 *           type: string
 *           format: date-time
 *         uptime:
 *           type: number
 *           description: Uptime del server in secondi
 *         version:
 *           type: string
 *           example: "1.0.0"
 * 
 *     DetailedHealthResponse:
 *       type: object
 *       properties:
 *         success:
 *           type: boolean
 *           example: true
 *         status:
 *           type: string
 *           enum: [healthy, degraded, unhealthy]
 *           example: healthy
 *         timestamp:
 *           type: string
 *           format: date-time
 *         responseTime:
 *           type: string
 *           example: "45ms"
 *         services:
 *           type: object
 *           properties:
 *             opnsense:
 *               type: object
 *               properties:
 *                 status:
 *                   type: string
 *                   enum: [healthy, unhealthy]
 *                 message:
 *                   type: string
 *                 responseTime:
 *                   type: number
 *                 version:
 *                   type: string
 *         system:
 *           type: object
 *           properties:
 *             nodeVersion:
 *               type: string
 *             platform:
 *               type: string
 *             architecture:
 *               type: string
 *             environment:
 *               type: string
 *             uptime:
 *               type: number
 *             memory:
 *               type: object
 *               properties:
 *                 rss:
 *                   type: string
 *                 heapTotal:
 *                   type: string
 *                 heapUsed:
 *                   type: string
 *                 external:
 *                   type: string
 */

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Health check semplice
 *     description: Verifica di base dello stato dell'API
 *     tags: [Health Check]
 *     responses:
 *       200:
 *         description: API funzionante
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/HealthResponse'
 */
router.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'API funzionante',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

/**
 * @swagger
 * /api/health/detailed:
 *   get:
 *     summary: Health check dettagliato
 *     description: Verifica completa dello stato dell'API e dei servizi collegati
 *     tags: [Health Check]
 *     responses:
 *       200:
 *         description: Health check dettagliato completato
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/DetailedHealthResponse'
 *       503:
 *         description: Uno o più servizi non sono disponibili
 *         content:
 *           application/json:
 *             schema:
 *               allOf:
 *                 - $ref: '#/components/schemas/DetailedHealthResponse'
 *                 - type: object
 *                   properties:
 *                     status:
 *                       example: degraded
 */
router.get('/detailed', asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  // Test connessione OPNsense
  let opnsenseStatus = {
    status: 'unknown',
    message: 'Non testato',
    responseTime: null
  };

  try {
    const opnsenseStart = Date.now();
    const result = await OpnsenseService.testConnection();
    opnsenseStatus = {
      status: result.success ? 'healthy' : 'unhealthy',
      message: result.success ? result.message || 'Connessione riuscita' : result.error,
      responseTime: Date.now() - opnsenseStart,
      version: result.system_version || result.api_version
    };
  } catch (error) {
    opnsenseStatus = {
      status: 'unhealthy',
      message: error.message,
      responseTime: Date.now() - startTime || null
    };
  }

  // Informazioni sistema
  const memoryUsage = process.memoryUsage();
  const systemInfo = {
    nodeVersion: process.version,
    platform: process.platform,
    architecture: process.arch,
    environment: process.env.NODE_ENV || 'development',
    uptime: Math.floor(process.uptime()),
    memory: {
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + ' MB',
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + ' MB',
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + ' MB',
      external: Math.round(memoryUsage.external / 1024 / 1024) + ' MB'
    }
  };

  // Status generale
  const overallStatus = opnsenseStatus.status === 'healthy' ? 'healthy' : 'degraded';
  
  const responseTime = Date.now() - startTime;
  const statusCode = overallStatus === 'healthy' ? 200 : 503;

  res.status(statusCode).json({
    success: true,
    status: overallStatus,
    timestamp: new Date().toISOString(),
    responseTime: responseTime + 'ms',
    services: {
      opnsense: opnsenseStatus
    },
    system: systemInfo
  });
}));

/**
 * @swagger
 * /api/health/opnsense:
 *   get:
 *     summary: Test connessione OPNsense
 *     description: Verifica specifica della connessione a OPNsense
 *     tags: [Health Check]
 *     responses:
 *       200:
 *         description: Connessione OPNsense riuscita
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 status:
 *                   type: string
 *                   example: healthy
 *                 message:
 *                   type: string
 *                   example: Connessione a OPNsense riuscita
 *                 responseTime:
 *                   type: string
 *                   example: "150ms"
 *                 version:
 *                   type: string
 *                   example: "23.7.1"
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *       503:
 *         description: Connessione OPNsense fallita
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 status:
 *                   type: string
 *                   example: unhealthy
 *                 message:
 *                   type: string
 *                   example: Errore di connessione
 *                 responseTime:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 */
router.get('/opnsense', asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const result = await OpnsenseService.testConnection();
    const responseTime = Date.now() - startTime;
    
    if (result.success) {
      res.json({
        success: true,
        status: 'healthy',
        message: result.message || 'Connessione a OPNsense riuscita',
        responseTime: responseTime + 'ms',
        version: result.system_version || result.api_version,
        ssl_config: result.ssl_config,
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(503).json({
        success: false,
        status: 'unhealthy',
        message: result.error || 'Connessione fallita',
        responseTime: responseTime + 'ms',
        ssl_config: result.ssl_config,
        timestamp: new Date().toISOString()
      });
    }
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    res.status(503).json({
      success: false,
      status: 'unhealthy',
      message: error.message,
      responseTime: responseTime + 'ms',
      timestamp: new Date().toISOString()
    });
  }
}));

/**
 * @swagger
 * /api/health/database:
 *   get:
 *     summary: Test connessione database
 *     description: Verifica lo stato della connessione al database
 *     tags: [Health Check]
 *     responses:
 *       200:
 *         description: Database funzionante
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 status:
 *                   type: string
 *                   example: healthy
 *                 message:
 *                   type: string
 *                   example: Database connesso
 *                 responseTime:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                   format: date-time
 *       503:
 *         description: Database non disponibile
 */
router.get('/database', asyncHandler(async (req, res) => {
  const startTime = Date.now();
  
  try {
    const { sequelize } = require('../config/database');
    await sequelize.authenticate();
    const responseTime = Date.now() - startTime;
    
    res.json({
      success: true,
      status: 'healthy',
      message: 'Database connesso',
      responseTime: responseTime + 'ms',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    const responseTime = Date.now() - startTime;
    
    res.status(503).json({
      success: false,
      status: 'unhealthy',
      message: 'Errore connessione database: ' + error.message,
      responseTime: responseTime + 'ms',
      timestamp: new Date().toISOString()
    });
  }
}));

module.exports = router;