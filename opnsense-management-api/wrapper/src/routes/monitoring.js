// src/routes/monitoring.js
'use strict';

const express = require('express');
const { authenticate, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { createRateLimiter } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError } = require('../middleware/errorHandler');
const MonitoringService = require('../services/MonitoringService');
const { getMetrics, performHealthChecks, monitoringConfig } = require('../config/monitoring');
const Alert = require('../models/Alert');
const AuditLog = require('../models/AuditLog');
const Rule = require('../models/Rule');
const logger = require('../utils/logger');
const { Op, fn } = require('sequelize');

const router = express.Router();

// Monitoring rate limiter
const monitoringLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: process.env.NODE_ENV === 'production' ? 300 : 5000,
});

// Apply rate limit and auth
router.use(monitoringLimiter);
router.use(authenticate);

/**
 * @swagger
 * /api/v1/monitoring/metrics:
 *   get:
 *     summary: Get current system and network metrics
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/metrics',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (_req, res) => {
    const monitoringService = new MonitoringService();

    const [system, interfaces] = await Promise.all([
      monitoringService.collectSystemMetrics(),
      monitoringService.collectNetworkMetrics().catch(() => []),
    ]);

    res.json({
      success: true,
      message: 'Metrics retrieved',
      data: { system, interfaces },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/interface/{interface_name}:
 *   get:
 *     summary: Get metrics for a specific network interface
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/interface/:interface_name',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { interface_name } = req.params;

    const monitoringService = new MonitoringService();

    try {
      const metrics = await monitoringService.collectNetworkMetrics(interface_name);

      if (!metrics || metrics.length === 0) {
        throw new NotFoundError(`Interface ${interface_name} not found`);
      }

      res.json({
        success: true,
        message: `Interface ${interface_name} metrics retrieved`,
        data: metrics,
      });
    } catch (error) {
      if (error.message && error.message.toLowerCase().includes('not found')) {
        throw new NotFoundError(`Interface ${interface_name} not found`);
      }
      throw error;
    }
  })
);

/**
 * @swagger
 * /api/v1/monitoring/alerts:
 *   get:
 *     summary: Get active monitoring alerts
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/alerts',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { severity, type, status = 'active' } = req.query;

    const whereClause = { status };
    if (severity) whereClause.severity = severity;
    if (type) whereClause.type = type;

    const alerts = await Alert.findAll({
      where: whereClause,
      order: [
        ['severity', 'DESC'],
        ['created_at', 'DESC'],
      ],
      limit: 100,
      include: [
        {
          model: Rule,
          as: 'rule',
          attributes: ['id', 'description', 'interface'],
        },
      ],
    });

    const stats = await Alert.getStatistics();

    res.json({
      success: true,
      message: 'Alerts retrieved',
      data: alerts,
      metadata: {
        count: alerts.length,
        filters: { severity, type, status },
        statistics: stats,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/alerts/{id}/acknowledge:
 *   post:
 *     summary: Acknowledge a monitoring alert
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/alerts/:id/acknowledge',
  validators.idParam,
  authorize(PERMISSIONS.MONITORING_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { note } = req.body;

    const alert = await Alert.findByPk(id);
    if (!alert) throw new NotFoundError('Alert not found');

    await alert.acknowledge(req.user.id, note);

    logger.info('Alert acknowledged', {
      alert_id: alert.id,
      user_id: req.user.id,
      note,
    });

    res.json({
      success: true,
      message: 'Alert acknowledged',
      data: {
        id: alert.id,
        status: alert.status,
        acknowledged_at: alert.acknowledged_at,
        response_time: alert.getResponseTime(),
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/dashboard:
 *   get:
 *     summary: Get compact monitoring dashboard data
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/dashboard',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (_req, res) => {
    const monitoringService = new MonitoringService();

    const [system, interfaces, health] = await Promise.all([
      monitoringService.collectSystemMetrics(),
      monitoringService.collectNetworkMetrics().catch(() => []),
      performHealthChecks(),
    ]);

    const alertStats = await Alert.getStatistics();
    const criticalAlerts = await Alert.findCritical();
    const unacknowledgedAlerts = await Alert.findUnacknowledged();

    const ruleStats = await Rule.getStatistics();
    const totalRules = await Rule.count();
    const activeRules = await Rule.count({ where: { enabled: true, suspended: false } });

    const securityEvents = await AuditLog.findSecurityEvents(20);

    const dashboardData = {
      timestamp: new Date().toISOString(),
      system_metrics: {
        cpu_usage: system.cpu_usage,
        memory_usage: system.memory_usage,
        disk_usage: system.disk_usage,
        uptime: system.uptime,
      },
      alerts: {
        total: criticalAlerts.length + unacknowledgedAlerts.length,
        critical: criticalAlerts.length,
        unacknowledged: unacknowledgedAlerts.length,
        statistics: alertStats,
      },
      firewall: {
        total_rules: totalRules,
        active_rules: activeRules,
        inactive_rules: totalRules - activeRules,
        statistics: ruleStats,
      },
      security: {
        recent_events: securityEvents.slice(0, 10),
        event_count_24h: securityEvents.length,
      },
      system_health: {
        database: health.database === 'healthy',
        cache: health.cache === 'healthy',
        opnsense_api: health.opnsense_api === 'healthy',
      },
      network_interfaces: interfaces,
    };

    res.json({
      success: true,
      message: 'Dashboard data retrieved',
      data: dashboardData,
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/prometheus:
 *   get:
 *     summary: Get Prometheus-formatted metrics
 *     tags: [Monitoring]
 */
router.get(
  '/prometheus',
  asyncHandler(async (_req, res) => {
    const metrics = await getMetrics();
    res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(metrics);
  })
);

/**
 * @swagger
 * /api/v1/monitoring/events:
 *   get:
 *     summary: Get recent monitoring events
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/events',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { limit = 100, level, hours = 24 } = req.query;

    const whereClause = {
      timestamp: {
        [Op.gte]: new Date(Date.now() - parseInt(hours, 10) * 60 * 60 * 1000),
      },
    };
    if (level) whereClause.level = level;

    const events = await AuditLog.findAll({
      where: whereClause,
      limit: parseInt(limit, 10),
      order: [['timestamp', 'DESC']],
      attributes: [
        'audit_id',
        'timestamp',
        'level',
        'action',
        'username',
        'client_ip',
        'method',
        'url',
        'status_code',
        'risk_score',
      ],
    });

    const eventStats = await AuditLog.findAll({
      attributes: ['level', [fn('COUNT', '*'), 'count']],
      where: whereClause,
      group: ['level'],
      raw: true,
    });

    res.json({
      success: true,
      message: 'Events retrieved',
      data: events,
      metadata: {
        count: events.length,
        hours: parseInt(hours, 10),
        statistics: eventStats.reduce((acc, stat) => {
          acc[stat.level] = parseInt(stat.count, 10);
          return acc;
        }, {}),
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/health:
 *   get:
 *     summary: Get monitoring health
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/health',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (_req, res) => {
    const monitoringService = new MonitoringService();
    const healthStatus = await monitoringService.getHealthStatus();

    res.json({
      success: true,
      message: 'Health status retrieved',
      data: healthStatus,
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/thresholds:
 *   get:
 *     summary: Get monitoring thresholds
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/thresholds',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (_req, res) => {
    const thresholds = {
      alerts: monitoringConfig.alerting.thresholds,
      nagios: monitoringConfig.nagios.criticalThresholds,
      system: {
        cpu_critical: 90,
        cpu_warning: 75,
        memory_critical: 95,
        memory_warning: 85,
        disk_critical: 95,
        disk_warning: 85,
        response_time_critical: 5000,
        response_time_warning: 2000,
      },
      firewall: {
        rule_count_warning: 1000,
        rule_count_critical: 5000,
        sync_failures_warning: 5,
        sync_failures_critical: 20,
      },
    };

    res.json({
      success: true,
      message: 'Thresholds retrieved',
      data: thresholds,
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/thresholds:
 *   put:
 *     summary: Update monitoring thresholds
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.put(
  '/thresholds',
  authorize(PERMISSIONS.MONITORING_WRITE),
  asyncHandler(async (req, res) => {
    const { system, firewall, alerts } = req.body;

    if (system && system.cpu_warning >= system.cpu_critical) {
      return res.status(400).json({
        success: false,
        error: 'Warning threshold must be less than critical threshold',
      });
    }

    logger.info('Monitoring thresholds updated', {
      user_id: req.user.id,
      updates: { system, firewall, alerts },
    });

    res.json({
      success: true,
      message: 'Thresholds updated',
      data: {
        updated_at: new Date().toISOString(),
        updated_by: req.user.username,
      },
    });
  })
);

module.exports = router;