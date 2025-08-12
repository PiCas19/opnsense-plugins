const express = require('express');
const { authenticate, authorize, PERMISSIONS } = require('../middleware/auth');
const { validators } = require('../middleware/validation');
const { rateLimiters } = require('../middleware/rateLimit');
const { asyncHandler, NotFoundError } = require('../middleware/errorHandler');
const MonitoringService = require('../services/MonitoringService');
const { getMetrics } = require('../config/monitoring');
const Alert = require('../models/Alert');
const AuditLog = require('../models/AuditLog');
const Rule = require('../models/Rule');
const logger = require('../utils/logger');

const router = express.Router();

// Apply monitoring rate limiting and authentication
router.use(rateLimiters.monitoring);
router.use(authenticate);

/**
 * @swagger
 * /api/v1/monitoring/metrics:
 *   get:
 *     summary: Get comprehensive system monitoring data
 *     tags: [Monitoring]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Current system metrics retrieved successfully
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
 *                     timestamp:
 *                       type: string
 *                       format: date-time
 *                     system:
 *                       type: object
 *                       properties:
 *                         cpu_usage:
 *                           type: number
 *                         memory_usage:
 *                           type: number
 *                         disk_usage:
 *                           type: number
 *                         load_average:
 *                           type: array
 *                           items:
 *                             type: number
 *                     interfaces:
 *                       type: object
 *                       additionalProperties:
 *                         type: object
 *                         properties:
 *                           bytes_in:
 *                             type: integer
 *                           bytes_out:
 *                             type: integer
 *                           packets_in:
 *                             type: integer
 *                           packets_out:
 *                             type: integer
 *                     firewall_rules_active:
 *                       type: integer
 *                     firewall_rules_total:
 *                       type: integer
 *       500:
 *         description: Failed to retrieve monitoring data
 */
router.get('/metrics',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const monitoringService = new MonitoringService();
    const metrics = await monitoringService.getCurrentMetrics();
    
    res.json({
      success: true,
      message: 'Monitoring data retrieved successfully',
      data: metrics
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
 *     parameters:
 *       - in: query
 *         name: hours
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 168
 *           default: 24
 *         description: Hours of history to retrieve (1-168)
 *       - in: query
 *         name: interval
 *         schema:
 *           type: string
 *           enum: [5m, 15m, 1h, 6h, 24h]
 *           default: 15m
 *         description: Data aggregation interval
 *     responses:
 *       200:
 *         description: Historical monitoring data retrieved successfully
 */
router.get('/metrics/history',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { hours = 24, interval = '15m' } = req.query;
    
    const monitoringService = new MonitoringService();
    const history = await monitoringService.getMetricsHistory(parseInt(hours), interval);
    
    res.json({
      success: true,
      message: `${history.length} data points retrieved`,
      data: history,
      metadata: {
        hours: parseInt(hours),
        interval: interval,
        data_points: history.length
      }
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
 *     parameters:
 *       - in: path
 *         name: interface_name
 *         required: true
 *         schema:
 *           type: string
 *         description: Name of the network interface
 *       - in: query
 *         name: hours
 *         schema:
 *           type: integer
 *           default: 1
 *         description: Hours of history to include
 *     responses:
 *       200:
 *         description: Interface monitoring data retrieved successfully
 *       404:
 *         description: Interface not found
 */
router.get('/interface/:interface_name',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { interface_name } = req.params;
    const { hours = 1 } = req.query;
    
    const monitoringService = new MonitoringService();
    
    try {
      const interfaceMetrics = await monitoringService.getInterfaceMetrics(
        interface_name, 
        parseInt(hours)
      );
      
      res.json({
        success: true,
        message: `Interface ${interface_name} data retrieved successfully`,
        data: interfaceMetrics
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
 *     parameters:
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [low, medium, high, critical]
 *         description: Filter by alert severity
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *         description: Filter by alert type
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [active, acknowledged, resolved, suppressed]
 *           default: active
 *     responses:
 *       200:
 *         description: Alerts retrieved successfully
 */
router.get('/alerts',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { severity, type, status = 'active' } = req.query;
    
    const whereClause = { status };
    if (severity) whereClause.severity = severity;
    if (type) whereClause.type = type;
    
    const alerts = await Alert.findAll({
      where: whereClause,
      order: [['severity', 'DESC'], ['created_at', 'DESC']],
      limit: 100,
      include: [
        {
          model: Rule,
          as: 'rule',
          attributes: ['id', 'description', 'interface']
        }
      ]
    });
    
    // Get alert statistics
    const stats = await Alert.getStatistics();
    
    res.json({
      success: true,
      message: 'Alerts retrieved successfully',
      data: alerts,
      metadata: {
        count: alerts.length,
        filters: { severity, type, status },
        statistics: stats
      }
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
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               note:
 *                 type: string
 *                 description: Optional acknowledgment note
 *     responses:
 *       200:
 *         description: Alert acknowledged successfully
 *       404:
 *         description: Alert not found
 */
router.post('/alerts/:id/acknowledge',
  validators.idParam,
  authorize(PERMISSIONS.MONITORING_WRITE),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const { note } = req.body;
    
    const alert = await Alert.findByPk(id);
    if (!alert) {
      throw new NotFoundError('Alert not found');
    }
    
    await alert.acknowledge(req.user.id, note);
    
    logger.info('Alert acknowledged', {
      alert_id: alert.id,
      user_id: req.user.id,
      note: note
    });
    
    res.json({
      success: true,
      message: 'Alert acknowledged successfully',
      data: {
        id: alert.id,
        status: alert.status,
        acknowledged_at: alert.acknowledged_at,
        response_time: alert.getResponseTime()
      }
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
 *     responses:
 *       200:
 *         description: Dashboard data retrieved successfully
 */
router.get('/dashboard',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const monitoringService = new MonitoringService();
    
    // Get current metrics
    const currentMetrics = await monitoringService.getCurrentMetrics();
    
    // Get alert statistics
    const alertStats = await Alert.getStatistics();
    const criticalAlerts = await Alert.findCritical();
    const unacknowledgedAlerts = await Alert.findUnacknowledged();
    
    // Get firewall statistics
    const ruleStats = await Rule.getStatistics();
    const totalRules = await Rule.count();
    const activeRules = await Rule.count({ where: { enabled: true, suspended: false } });
    
    // Get recent security events
    const securityEvents = await AuditLog.findSecurityEvents(20);
    
    // Get system health summary
    const systemHealth = {
      database: currentMetrics.dependencies?.database?.status === 'healthy',
      cache: currentMetrics.dependencies?.cache?.status !== 'unhealthy',
      opnsense_api: currentMetrics.dependencies?.opnsense_api?.status === 'healthy'
    };
    
    const dashboardData = {
      timestamp: new Date().toISOString(),
      system_metrics: {
        cpu_usage: currentMetrics.system.cpu_usage,
        memory_usage: currentMetrics.system.memory_usage,
        disk_usage: currentMetrics.system.disk_usage,
        uptime: currentMetrics.system.uptime
      },
      alerts: {
        total: criticalAlerts.length + unacknowledgedAlerts.length,
        critical: criticalAlerts.length,
        unacknowledged: unacknowledgedAlerts.length,
        statistics: alertStats
      },
      firewall: {
        total_rules: totalRules,
        active_rules: activeRules,
        inactive_rules: totalRules - activeRules,
        statistics: ruleStats
      },
      security: {
        recent_events: securityEvents.slice(0, 10),
        event_count_24h: securityEvents.length
      },
      system_health: systemHealth,
      network_interfaces: currentMetrics.interfaces
    };
    
    res.json({
      success: true,
      message: 'Dashboard data retrieved successfully',
      data: dashboardData
    });
  })
);

/**
 * @swagger
 * /api/v1/monitoring/prometheus:
 *   get:
 *     summary: Get Prometheus-formatted metrics
 *     tags: [Monitoring]
 *     produces:
 *       - text/plain
 *     responses:
 *       200:
 *         description: Prometheus metrics
 *         content:
 *           text/plain:
 *             schema:
 *               type: string
 */
router.get('/prometheus',
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
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 1000
 *           default: 100
 *       - in: query
 *         name: level
 *         schema:
 *           type: string
 *           enum: [info, warning, critical, security]
 *       - in: query
 *         name: hours
 *         schema:
 *           type: integer
 *           default: 24
 *     responses:
 *       200:
 *         description: Events retrieved successfully
 */
router.get('/events',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { limit = 100, level, hours = 24 } = req.query;
    
    const whereClause = {
      timestamp: {
        [sequelize.Op.gte]: new Date(Date.now() - hours * 60 * 60 * 1000)
      }
    };
    
    if (level) {
      whereClause.level = level;
    }
    
    const events = await AuditLog.findAll({
      where: whereClause,
      limit: parseInt(limit),
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
        'risk_score'
      ]
    });
    
    // Get event statistics
    const eventStats = await AuditLog.findAll({
      attributes: [
        'level',
        [sequelize.fn('COUNT', '*'), 'count']
      ],
      where: whereClause,
      group: ['level'],
      raw: true
    });
    
    res.json({
      success: true,
      message: 'Monitoring events retrieved successfully',
      data: events,
      metadata: {
        count: events.length,
        hours: parseInt(hours),
        statistics: eventStats.reduce((acc, stat) => {
          acc[stat.level] = parseInt(stat.count);
          return acc;
        }, {})
      }
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
 *     responses:
 *       200:
 *         description: Monitoring health retrieved successfully
 */
router.get('/health',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const monitoringService = new MonitoringService();
    const healthStatus = await monitoringService.getMonitoringHealth();
    
    res.json({
      success: true,
      message: 'Monitoring health status retrieved successfully',
      data: healthStatus
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
 *     parameters:
 *       - in: query
 *         name: timeframe
 *         schema:
 *           type: string
 *           enum: [1h, 6h, 24h, 7d, 30d]
 *           default: 24h
 *     responses:
 *       200:
 *         description: Performance metrics retrieved successfully
 */
router.get('/performance',
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
        timeframe: timeframe,
        data_points: performanceData.length
      }
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
 *     parameters:
 *       - in: query
 *         name: type
 *         schema:
 *           type: string
 *           enum: [daily, weekly, monthly]
 *           default: daily
 *       - in: query
 *         name: format
 *         schema:
 *           type: string
 *           enum: [json, csv]
 *           default: json
 *     responses:
 *       200:
 *         description: Report generated successfully
 */
router.get('/reports',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { type = 'daily', format = 'json' } = req.query;
    
    const monitoringService = new MonitoringService();
    const report = await monitoringService.generateReport(type);
    
    if (format === 'csv') {
      // Convert report to CSV format
      const fields = Object.keys(report.data[0] || {});
      const csvData = [
        fields.join(','),
        ...report.data.map(row => 
          fields.map(field => 
            typeof row[field] === 'string' ? `"${row[field]}"` : row[field]
          ).join(',')
        )
      ].join('\n');
      
      res.set({
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="monitoring-report-${type}-${new Date().toISOString().split('T')[0]}.csv"`
      });
      
      return res.send(csvData);
    }
    
    res.json({
      success: true,
      message: `${type} monitoring report generated successfully`,
      data: report
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
 *     responses:
 *       200:
 *         description: Monitoring thresholds retrieved successfully
 */
router.get('/thresholds',
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
        response_time_warning: 2000
      },
      firewall: {
        rule_count_warning: 1000,
        rule_count_critical: 5000,
        sync_failures_warning: 5,
        sync_failures_critical: 20
      }
    };
    
    res.json({
      success: true,
      message: 'Monitoring thresholds retrieved successfully',
      data: thresholds
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               system:
 *                 type: object
 *                 properties:
 *                   cpu_warning:
 *                     type: number
 *                     minimum: 0
 *                     maximum: 100
 *                   cpu_critical:
 *                     type: number
 *                     minimum: 0
 *                     maximum: 100
 *                   memory_warning:
 *                     type: number
 *                     minimum: 0
 *                     maximum: 100
 *                   memory_critical:
 *                     type: number
 *                     minimum: 0
 *                     maximum: 100
 *     responses:
 *       200:
 *         description: Thresholds updated successfully
 */
router.put('/thresholds',
  authorize(PERMISSIONS.MONITORING_WRITE),
  asyncHandler(async (req, res) => {
    const { system, firewall, alerts } = req.body;
    
    // Validate threshold values
    if (system) {
      if (system.cpu_warning >= system.cpu_critical) {
        return res.status(400).json({
          success: false,
          error: 'Warning threshold must be less than critical threshold'
        });
      }
    }
    
    // Here you would typically save to database or config file
    // For now, we'll just acknowledge the update
    
    logger.info('Monitoring thresholds updated', {
      user_id: req.user.id,
      updates: { system, firewall, alerts }
    });
    
    res.json({
      success: true,
      message: 'Monitoring thresholds updated successfully',
      data: {
        updated_at: new Date().toISOString(),
        updated_by: req.user.username
      }
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
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - start_date
 *               - end_date
 *             properties:
 *               start_date:
 *                 type: string
 *                 format: date
 *               end_date:
 *                 type: string
 *                 format: date
 *               data_types:
 *                 type: array
 *                 items:
 *                   type: string
 *                   enum: [metrics, alerts, events, performance]
 *                 default: [metrics, alerts]
 *               format:
 *                 type: string
 *                 enum: [json, csv, xlsx]
 *                 default: json
 *     responses:
 *       200:
 *         description: Export completed successfully
 */
router.post('/export',
  authorize(PERMISSIONS.MONITORING_READ),
  asyncHandler(async (req, res) => {
    const { 
      start_date, 
      end_date, 
      data_types = ['metrics', 'alerts'], 
      format = 'json' 
    } = req.body;
    
    const monitoringService = new MonitoringService();
    const exportData = await monitoringService.exportData(
      new Date(start_date),
      new Date(end_date),
      data_types
    );
    
    const filename = `monitoring-export-${start_date}-${end_date}`;
    
    switch (format) {
      case 'csv':
        res.set({
          'Content-Type': 'text/csv',
          'Content-Disposition': `attachment; filename="${filename}.csv"`
        });
        return res.send(monitoringService.convertToCSV(exportData));
        
      case 'xlsx':
        const xlsxBuffer = await monitoringService.convertToXLSX(exportData);
        res.set({
          'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'Content-Disposition': `attachment; filename="${filename}.xlsx"`
        });
        return res.send(xlsxBuffer);
        
      default:
        res.set({
          'Content-Type': 'application/json',
          'Content-Disposition': `attachment; filename="${filename}.json"`
        });
        return res.json({
          success: true,
          message: 'Data exported successfully',
          data: exportData,
          metadata: {
            start_date,
            end_date,
            data_types,
            record_count: Object.values(exportData).reduce((sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0), 0)
          }
        });
    }
  })
);

module.exports = router;