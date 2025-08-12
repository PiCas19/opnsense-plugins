const express = require('express');
const { rateLimiters } = require('../middleware/rateLimit');
const { asyncHandler } = require('../middleware/errorHandler');
const { 
  testDatabaseConnection, 
  testRedisConnection,
  sequelize,
  redis 
} = require('../config/database');
const { testConnection: testOpnsenseConnection } = require('../config/opnsense');
const logger = require('../utils/logger');
const os = require('os');
const process = require('process');

const router = express.Router();

// Apply monitoring rate limiting (more permissive)
router.use(rateLimiters.monitoring);

/**
 * @swagger
 * /api/v1/health:
 *   get:
 *     summary: Basic health check endpoint
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Service is healthy
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Service is healthy"
 *                 data:
 *                   type: object
 *                   properties:
 *                     status:
 *                       type: string
 *                       example: "healthy"
 *                     timestamp:
 *                       type: string
 *                       format: date-time
 *                     uptime:
 *                       type: number
 *                       description: "Process uptime in seconds"
 *       503:
 *         description: Service is unhealthy
 */
router.get('/',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    
    try {
      // Basic health indicators
      const health = {
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: {
          used: process.memoryUsage().heapUsed,
          total: process.memoryUsage().heapTotal,
          external: process.memoryUsage().external,
          rss: process.memoryUsage().rss
        },
        cpu: {
          load_average: os.loadavg(),
          cpu_count: os.cpus().length
        },
        response_time: Date.now() - startTime
      };
      
      res.json({
        success: true,
        message: 'Service is healthy',
        data: health
      });
    } catch (error) {
      logger.error('Health check failed', { error: error.message });
      
      res.status(503).json({
        success: false,
        message: 'Service is unhealthy',
        error: 'HEALTH_CHECK_FAILED',
        data: {
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          error: error.message
        }
      });
    }
  })
);

/**
 * @swagger
 * /api/v1/health/live:
 *   get:
 *     summary: Kubernetes liveness probe endpoint
 *     tags: [Health]
 *     description: Simple endpoint to check if the service is alive (for K8s liveness probe)
 *     responses:
 *       200:
 *         description: Service is alive
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     status:
 *                       type: string
 *                       example: "alive"
 */
router.get('/live',
  asyncHandler(async (req, res) => {
    // Minimal health check - just confirm the process is running
    res.json({
      success: true,
      message: 'Service is alive',
      data: {
        status: 'alive',
        timestamp: new Date().toISOString(),
        pid: process.pid,
        uptime: process.uptime()
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/health/ready:
 *   get:
 *     summary: Kubernetes readiness probe endpoint
 *     tags: [Health]
 *     description: Comprehensive readiness check including dependencies (for K8s readiness probe)
 *     responses:
 *       200:
 *         description: Service is ready to handle requests
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     status:
 *                       type: string
 *                       example: "ready"
 *                     dependencies:
 *                       type: object
 *       503:
 *         description: Service is not ready
 */
router.get('/ready',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    const dependencies = {};
    let allReady = true;
    
    // Check database connectivity
    try {
      const dbHealthy = await testDatabaseConnection();
      dependencies.database = {
        status: dbHealthy ? 'healthy' : 'unhealthy',
        type: 'postgresql',
        response_time: Date.now() - startTime
      };
      if (!dbHealthy) allReady = false;
    } catch (error) {
      dependencies.database = {
        status: 'unhealthy',
        type: 'postgresql',
        error: error.message,
        response_time: Date.now() - startTime
      };
      allReady = false;
    }
    
    // Check Redis connectivity (optional - cache can be down)
    try {
      const redisHealthy = await testRedisConnection();
      dependencies.cache = {
        status: redisHealthy ? 'healthy' : 'degraded',
        type: 'redis',
        response_time: Date.now() - startTime,
        optional: true
      };
      // Redis is optional, don't fail readiness if it's down
    } catch (error) {
      dependencies.cache = {
        status: 'degraded',
        type: 'redis',
        error: error.message,
        response_time: Date.now() - startTime,
        optional: true
      };
    }
    
    // Check OPNsense API connectivity
    try {
      const opnsenseHealthy = await testOpnsenseConnection();
      dependencies.opnsense_api = {
        status: opnsenseHealthy ? 'healthy' : 'unhealthy',
        type: 'external_api',
        response_time: Date.now() - startTime
      };
      if (!opnsenseHealthy) allReady = false;
    } catch (error) {
      dependencies.opnsense_api = {
        status: 'unhealthy',
        type: 'external_api',
        error: error.message,
        response_time: Date.now() - startTime
      };
      allReady = false;
    }
    
    const statusCode = allReady ? 200 : 503;
    const status = allReady ? 'ready' : 'not_ready';
    
    res.status(statusCode).json({
      success: allReady,
      message: allReady ? 'Service is ready' : 'Service is not ready',
      data: {
        status: status,
        timestamp: new Date().toISOString(),
        total_response_time: Date.now() - startTime,
        dependencies: dependencies
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/health/database:
 *   get:
 *     summary: Database health check
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Database is healthy
 *       503:
 *         description: Database is unhealthy
 */
router.get('/database',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    
    try {
      // Test basic connectivity
      const isConnected = await testDatabaseConnection();
      
      if (!isConnected) {
        throw new Error('Database connection test failed');
      }
      
      // Test query performance
      const [results] = await sequelize.query('SELECT 1 as health_check, NOW() as server_time');
      
      // Get database statistics
      const stats = await sequelize.query(`
        SELECT 
          schemaname,
          tablename,
          n_tup_ins as inserts,
          n_tup_upd as updates,
          n_tup_del as deletes
        FROM pg_stat_user_tables 
        ORDER BY schemaname, tablename
      `);
      
      const poolInfo = {
        max_connections: sequelize.options.pool.max,
        min_connections: sequelize.options.pool.min,
        idle_timeout: sequelize.options.pool.idle,
        acquire_timeout: sequelize.options.pool.acquire
      };
      
      res.json({
        success: true,
        message: 'Database is healthy',
        data: {
          status: 'healthy',
          type: 'postgresql',
          response_time: Date.now() - startTime,
          server_time: results[0].server_time,
          version: await sequelize.databaseVersion(),
          pool: poolInfo,
          table_stats: stats[0]?.slice(0, 10) || [] // Limit to first 10 tables
        }
      });
    } catch (error) {
      logger.error('Database health check failed', { error: error.message });
      
      res.status(503).json({
        success: false,
        message: 'Database is unhealthy',
        error: 'DATABASE_UNHEALTHY',
        data: {
          status: 'unhealthy',
          type: 'postgresql',
          response_time: Date.now() - startTime,
          error: error.message
        }
      });
    }
  })
);

/**
 * @swagger
 * /api/v1/health/cache:
 *   get:
 *     summary: Redis cache health check
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Cache is healthy
 *       503:
 *         description: Cache is unhealthy
 */
router.get('/cache',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    
    try {
      // Test basic connectivity
      const isConnected = await testRedisConnection();
      
      if (!isConnected) {
        throw new Error('Redis connection test failed');
      }
      
      // Test read/write operations
      const testKey = 'health_check:' + Date.now();
      const testValue = { timestamp: new Date().toISOString(), test: true };
      
      await redis.setEx(testKey, 10, JSON.stringify(testValue)); // 10 second TTL
      const retrieved = await redis.get(testKey);
      const parsedValue = JSON.parse(retrieved);
      
      await redis.del(testKey); // Cleanup
      
      // Get Redis info
      const info = await redis.info();
      const memoryInfo = await redis.info('memory');
      
      res.json({
        success: true,
        message: 'Cache is healthy',
        data: {
          status: 'healthy',
          type: 'redis',
          response_time: Date.now() - startTime,
          test_passed: parsedValue.test === true,
          server_info: {
            version: info.split('\r\n').find(line => line.startsWith('redis_version:'))?.split(':')[1],
            uptime: info.split('\r\n').find(line => line.startsWith('uptime_in_seconds:'))?.split(':')[1],
            connected_clients: info.split('\r\n').find(line => line.startsWith('connected_clients:'))?.split(':')[1]
          },
          memory_info: {
            used_memory: memoryInfo.split('\r\n').find(line => line.startsWith('used_memory_human:'))?.split(':')[1],
            max_memory: memoryInfo.split('\r\n').find(line => line.startsWith('maxmemory_human:'))?.split(':')[1]
          }
        }
      });
    } catch (error) {
      logger.error('Cache health check failed', { error: error.message });
      
      res.status(503).json({
        success: false,
        message: 'Cache is unhealthy',
        error: 'CACHE_UNHEALTHY',
        data: {
          status: 'unhealthy',
          type: 'redis',
          response_time: Date.now() - startTime,
          error: error.message
        }
      });
    }
  })
);

/**
 * @swagger
 * /api/v1/health/opnsense:
 *   get:
 *     summary: OPNsense API health check
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: OPNsense API is healthy
 *       503:
 *         description: OPNsense API is unhealthy
 */
router.get('/opnsense',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    
    try {
      const { getSystemInfo } = require('../config/opnsense');
      
      // Test connectivity and get system info
      const result = await getSystemInfo();
      
      if (!result.success) {
        throw new Error(result.error || 'OPNsense API call failed');
      }
      
      res.json({
        success: true,
        message: 'OPNsense API is healthy',
        data: {
          status: 'healthy',
          type: 'external_api',
          response_time: Date.now() - startTime,
          system_info: {
            version: result.data?.version || 'unknown',
            product: result.data?.product || 'OPNsense',
            platform: result.data?.platform
          }
        }
      });
    } catch (error) {
      logger.error('OPNsense health check failed', { error: error.message });
      
      res.status(503).json({
        success: false,
        message: 'OPNsense API is unhealthy',
        error: 'OPNSENSE_API_UNHEALTHY',
        data: {
          status: 'unhealthy',
          type: 'external_api',
          response_time: Date.now() - startTime,
          error: error.message
        }
      });
    }
  })
);

/**
 * @swagger
 * /api/v1/health/version:
 *   get:
 *     summary: Get service version and build information
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Version information retrieved successfully
 */
router.get('/version',
  asyncHandler(async (req, res) => {
    const packageJson = require('../../package.json');
    
    const versionInfo = {
      service: {
        name: packageJson.name,
        version: packageJson.version,
        description: packageJson.description,
        author: packageJson.author
      },
      runtime: {
        node_version: process.version,
        platform: process.platform,
        architecture: process.arch,
        environment: process.env.NODE_ENV || 'development'
      },
      build: {
        timestamp: process.env.BUILD_TIMESTAMP || 'unknown',
        git_commit: process.env.GIT_COMMIT || 'unknown',
        git_branch: process.env.GIT_BRANCH || 'unknown',
        build_number: process.env.BUILD_NUMBER || 'unknown'
      },
      dependencies: {
        express: packageJson.dependencies?.express,
        sequelize: packageJson.dependencies?.sequelize,
        redis: packageJson.dependencies?.redis,
        axios: packageJson.dependencies?.axios
      }
    };
    
    res.json({
      success: true,
      message: 'Version information retrieved successfully',
      data: versionInfo
    });
  })
);

/**
 * @swagger
 * /api/v1/health/metrics:
 *   get:
 *     summary: Get basic system metrics
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: System metrics retrieved successfully
 */
router.get('/metrics',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    
    // System metrics
    const systemMetrics = {
      memory: {
        total: os.totalmem(),
        free: os.freemem(),
        used: os.totalmem() - os.freemem(),
        usage_percent: ((os.totalmem() - os.freemem()) / os.totalmem() * 100).toFixed(2)
      },
      cpu: {
        count: os.cpus().length,
        model: os.cpus()[0]?.model,
        load_average: os.loadavg(),
        usage_percent: (os.loadavg()[0] * 100 / os.cpus().length).toFixed(2)
      },
      system: {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        uptime: os.uptime(),
        release: os.release(),
        type: os.type()
      }
    };
    
    // Process metrics
    const processMetrics = {
      pid: process.pid,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu_usage: process.cpuUsage(),
      versions: process.versions
    };
    
    // Network interfaces
    const networkInterfaces = {};
    const interfaces = os.networkInterfaces();
    for (const [name, nets] of Object.entries(interfaces)) {
      networkInterfaces[name] = nets.map(net => ({
        address: net.address,
        family: net.family,
        internal: net.internal
      }));
    }
    
    res.json({
      success: true,
      message: 'System metrics retrieved successfully',
      data: {
        timestamp: new Date().toISOString(),
        response_time: Date.now() - startTime,
        system: systemMetrics,
        process: processMetrics,
        network: networkInterfaces
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/health/dependencies:
 *   get:
 *     summary: Check all external dependencies
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Dependencies status retrieved successfully
 *       207:
 *         description: Some dependencies are unhealthy (multi-status)
 */
router.get('/dependencies',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    const dependencies = [];
    let allHealthy = true;
    
    // Database check
    try {
      const dbStart = Date.now();
      const dbHealthy = await testDatabaseConnection();
      dependencies.push({
        name: 'PostgreSQL Database',
        type: 'database',
        status: dbHealthy ? 'healthy' : 'unhealthy',
        critical: true,
        response_time: Date.now() - dbStart,
        endpoint: process.env.POSTGRES_HOST
      });
      if (!dbHealthy) allHealthy = false;
    } catch (error) {
      dependencies.push({
        name: 'PostgreSQL Database',
        type: 'database',
        status: 'unhealthy',
        critical: true,
        response_time: Date.now() - startTime,
        error: error.message,
        endpoint: process.env.POSTGRES_HOST
      });
      allHealthy = false;
    }
    
    // Redis check
    try {
      const redisStart = Date.now();
      const redisHealthy = await testRedisConnection();
      dependencies.push({
        name: 'Redis Cache',
        type: 'cache',
        status: redisHealthy ? 'healthy' : 'degraded',
        critical: false,
        response_time: Date.now() - redisStart,
        endpoint: process.env.REDIS_HOST
      });
      // Redis is optional, don't mark as unhealthy if it fails
    } catch (error) {
      dependencies.push({
        name: 'Redis Cache',
        type: 'cache',
        status: 'degraded',
        critical: false,
        response_time: Date.now() - startTime,
        error: error.message,
        endpoint: process.env.REDIS_HOST
      });
    }
    
    // OPNsense API check
    try {
      const opnsenseStart = Date.now();
      const opnsenseHealthy = await testOpnsenseConnection();
      dependencies.push({
        name: 'OPNsense API',
        type: 'external_api',
        status: opnsenseHealthy ? 'healthy' : 'unhealthy',
        critical: true,
        response_time: Date.now() - opnsenseStart,
        endpoint: process.env.OPNSENSE_BASE_URL
      });
      if (!opnsenseHealthy) allHealthy = false;
    } catch (error) {
      dependencies.push({
        name: 'OPNsense API',
        type: 'external_api',
        status: 'unhealthy',
        critical: true,
        response_time: Date.now() - startTime,
        error: error.message,
        endpoint: process.env.OPNSENSE_BASE_URL
      });
      allHealthy = false;
    }
    
    // Summary stats
    const summary = {
      total: dependencies.length,
      healthy: dependencies.filter(d => d.status === 'healthy').length,
      degraded: dependencies.filter(d => d.status === 'degraded').length,
      unhealthy: dependencies.filter(d => d.status === 'unhealthy').length,
      critical_failures: dependencies.filter(d => d.critical && d.status === 'unhealthy').length
    };
    
    const statusCode = allHealthy ? 200 : 207; // 207 = Multi-Status
    
    res.status(statusCode).json({
      success: allHealthy,
      message: allHealthy ? 
        'All dependencies are healthy' : 
        'Some dependencies are unhealthy',
      data: {
        overall_status: allHealthy ? 'healthy' : 'degraded',
        timestamp: new Date().toISOString(),
        total_response_time: Date.now() - startTime,
        summary: summary,
        dependencies: dependencies
      }
    });
  })
);

/**
 * @swagger
 * /api/v1/health/status:
 *   get:
 *     summary: Comprehensive health status (aggregated)
 *     tags: [Health]
 *     responses:
 *       200:
 *         description: Service is fully operational
 *       207:
 *         description: Service is operational with some issues
 *       503:
 *         description: Service is not operational
 */
router.get('/status',
  asyncHandler(async (req, res) => {
    const startTime = Date.now();
    const checks = [];
    let overallHealth = 'healthy';
    let httpStatus = 200;
    
    // Database health
    try {
      const dbHealthy = await testDatabaseConnection();
      checks.push({
        component: 'database',
        status: dbHealthy ? 'pass' : 'fail',
        time: new Date().toISOString()
      });
      if (!dbHealthy) {
        overallHealth = 'unhealthy';
        httpStatus = 503;
      }
    } catch (error) {
      checks.push({
        component: 'database',
        status: 'fail',
        time: new Date().toISOString(),
        output: error.message
      });
      overallHealth = 'unhealthy';
      httpStatus = 503;
    }
    
    // Cache health (non-critical)
    try {
      const cacheHealthy = await testRedisConnection();
      checks.push({
        component: 'cache',
        status: cacheHealthy ? 'pass' : 'warn',
        time: new Date().toISOString()
      });
      if (!cacheHealthy && overallHealth === 'healthy') {
        overallHealth = 'warn';
        httpStatus = 207;
      }
    } catch (error) {
      checks.push({
        component: 'cache',
        status: 'warn',
        time: new Date().toISOString(),
        output: error.message
      });
      if (overallHealth === 'healthy') {
        overallHealth = 'warn';
        httpStatus = 207;
      }
    }
    
    // OPNsense API health
    try {
      const opnsenseHealthy = await testOpnsenseConnection();
      checks.push({
        component: 'opnsense_api',
        status: opnsenseHealthy ? 'pass' : 'fail',
        time: new Date().toISOString()
      });
      if (!opnsenseHealthy) {
        overallHealth = 'unhealthy';
        httpStatus = 503;
      }
    } catch (error) {
      checks.push({
        component: 'opnsense_api',
        status: 'fail',
        time: new Date().toISOString(),
        output: error.message
      });
      overallHealth = 'unhealthy';
      httpStatus = 503;
    }
    
    // RFC 7807 compliant health check response
    const healthResponse = {
      status: overallHealth,
      version: require('../../package.json').version,
      releaseId: process.env.BUILD_NUMBER || 'dev',
      notes: ['OPNsense Firewall Management API'],
      output: '',
      serviceId: process.env.SERVICE_ID || 'opnsense-mgmt-api',
      description: 'Health status of OPNsense Management API and its dependencies',
      checks: checks,
      links: {
        about: '/api/v1/health/version',
        metrics: '/api/v1/health/metrics'
      }
    };
    
    // Add response time
    healthResponse.responseTime = Date.now() - startTime;
    
    res.status(httpStatus).json(healthResponse);
  })
);

module.exports = router;