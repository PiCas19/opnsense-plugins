// src/routes/monitoring.js
const express = require('express');
const { authenticate, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { createRateLimiter } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError } = require('../middleware/errorHandler');
const MonitoringService = require('../services/MonitoringService');
const { getMetrics } = require('../config/monitoring');
const Alert = require('../models/Alert');
const AuditLog = require('../models/AuditLog');
const Rule = require('../models/Rule');
const logger = require('../utils/logger');
const { Op, fn } = require('sequelize');

const router = express.Router();

// Limiter "monitoring" (sostituisce rateLimiters.monitoring)
const monitoringLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minuto
  max: process.env.NODE_ENV === 'production' ? 300 : 5000,
});

// Applica rate limit + auth
router.use(monitoringLimiter);
router.use(authenticate);

/**
 * @swagger
 * /api/v1/monitoring/metrics:
 *   get:
 *     summary: Get comprehensive system monitoring data
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/metrics',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const monitoringService = new MonitoringService();
    const metrics = await monitoringService.getCurrentMetrics();

    res.json({
      success: true,
      message: 'Monitoring data retrieved successfully',
      data: metrics,
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/metrics/history:
 *   get:
 *     summary: Get historical monitoring data
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/metrics/history',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { hours = 24, interval = '15m' } = req.query;

    const monitoringService = new MonitoringService();
    const history = await monitoringService.getMetricsHistory(parseInt(hours, 10), interval);

    res.json({
      success: true,
      message: `${history.length} data points retrieved`,
      data: history,
      metadata: {
        hours: parseInt(hours, 10),
        interval,
        data_points: history.length,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/interface/{interface_name}:
 *   get:
 *     summary: Get monitoring data for a specific network interface
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/interface/:interface_name',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { interface_name } = req.params;
    const { hours = 1 } = req.query;

    const monitoringService = new MonitoringService();

    try {
      const interfaceMetrics = await monitoringService.getInterfaceMetrics(
        interface_name,
        parseInt(hours, 10)
      );

      res.json({
        success: true,
        message: `Interface ${interface_name} data retrieved successfully`,
        data: interfaceMetrics,
      });
    } catch (error) {
      if (error.message.includes('not found')) {
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
      message: 'Alerts retrieved successfully',
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
      message: 'Alert acknowledged successfully',
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
 *     summary: Get monitoring dashboard data
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/dashboard',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const monitoringService = new MonitoringService();

    const currentMetrics = await monitoringService.getCurrentMetrics();

    const alertStats = await Alert.getStatistics();
    const criticalAlerts = await Alert.findCritical();
    const unacknowledgedAlerts = await Alert.findUnacknowledged();

    const ruleStats = await Rule.getStatistics();
    const totalRules = await Rule.count();
    const activeRules = await Rule.count({ where: { enabled: true, suspended: false } });

    const securityEvents = await AuditLog.findSecurityEvents(20);

    const systemHealth = {
      database: currentMetrics.dependencies?.database?.status === 'healthy',
      cache: currentMetrics.dependencies?.cache?.status !== 'unhealthy',
      opnsense_api: currentMetrics.dependencies?.opnsense_api?.status === 'healthy',
    };

    const dashboardData = {
      timestamp: new Date().toISOString(),
      system_metrics: {
        cpu_usage: currentMetrics.system.cpu_usage,
        memory_usage: currentMetrics.system.memory_usage,
        disk_usage: currentMetrics.system.disk_usage,
        uptime: currentMetrics.system.uptime,
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
      system_health: systemHealth,
      network_interfaces: currentMetrics.interfaces,
    };

    res.json({
      success: true,
      message: 'Dashboard data retrieved successfully',
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
  asyncHandler(async (req, res) => {
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
      message: 'Monitoring events retrieved successfully',
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
 *     summary: Get monitoring system health
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/health',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const monitoringService = new MonitoringService();
    const healthStatus = await monitoringService.getMonitoringHealth();

    res.json({
      success: true,
      message: 'Monitoring health status retrieved successfully',
      data: healthStatus,
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/performance:
 *   get:
 *     summary: Get system performance metrics
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/performance',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { timeframe = '24h' } = req.query;

    const monitoringService = new MonitoringService();
    const performanceData = await monitoringService.getPerformanceMetrics(timeframe);

    res.json({
      success: true,
      message: 'Performance metrics retrieved successfully',
      data: performanceData,
      metadata: {
        timeframe,
        data_points: performanceData.length,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/reports:
 *   get:
 *     summary: Get monitoring reports
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/reports',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { type = 'daily', format = 'json' } = req.query;

    const monitoringService = new MonitoringService();
    const report = await monitoringService.generateReport(type);

    if (format === 'csv') {
      const fields = Object.keys(report.data[0] || {});
      const csvData = [
        fields.join(','),
        ...report.data.map((row) =>
          fields
            .map((field) => (typeof row[field] === 'string' ? `"${row[field]}"` : row[field]))
            .join(',')
        ),
      ].join('\n');

      res.set({
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="monitoring-report-${type}-${new Date()
          .toISOString()
          .split('T')[0]}.csv"`,
      });

      return res.send(csvData);
    }

    res.json({
      success: true,
      message: `${type} monitoring report generated successfully`,
      data: report,
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/thresholds:
 *   get:
 *     summary: Get monitoring thresholds and limits
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.get(
  '/thresholds',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { monitoringConfig } = require('../config/monitoring');

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
      message: 'Monitoring thresholds retrieved successfully',
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
      message: 'Monitoring thresholds updated successfully',
      data: {
        updated_at: new Date().toISOString(),
        updated_by: req.user.username,
      },
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/export:
 *   post:
 *     summary: Export monitoring data
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 */
router.post(
  '/export',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { start_date, end_date, data_types = ['metrics', 'alerts'], format = 'json' } = req.body;

    const monitoringService = new MonitoringService();
    const exportData = await monitoringService.exportData(
      new Date(start_date),
      new Date(end_date),
      data_types
    );

    const filename = `monitoring-export-${start_date}-${end_date}`;

    switch (format) {
      case 'csv': {
        res.set({
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="${filename}.csv"`,
        });
        return res.send(monitoringService.convertToCSV(exportData));
      }
      case 'xlsx': {
        const xlsxBuffer = await monitoringService.convertToXLSX(exportData);
        res.set({
          'Content-Type':
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'Content-Disposition': `attachment; filename="${filename}.xlsx"`,
        });
        return res.send(xlsxBuffer);
      }
      default: {
        res.set({
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="${filename}.json"`,
        });
        return res.json({
          success: true,
          message: 'Data exported successfully',
          data: exportData,
          metadata: {
            start_date,
            end_date,
            data_types,
            record_count: Object.values(exportData).reduce(
              (sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0),
              0
            ),
          },
        });
      }
    }
  })
);

module.exports = router;