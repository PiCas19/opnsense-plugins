const Alert = require('../models/Alert');
const Rule = require('../models/Rule');
const Policy = require('../models/Policy');
const User = require('../models/User');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');
const { Op } = require('sequelize');

class AlertService {
  constructor(user = null) {
    this.user = user;
    this.cacheTimeout = process.env.CACHE_TIMEOUT || 60;
    this.maxRetries = process.env.MAX_RETRIES || 3;
  }

  /**
   * Validate alert data
   * @param {Object} alertData - Alert data to validate
   * @private
   */
  validateAlertData(alertData) {
    const requiredFields = ['title', 'message', 'type', 'severity'];
    const validSeverities = ['low', 'medium', 'high', 'critical'];
    
    for (const field of requiredFields) {
      if (!alertData[field]) {
        throw new Error(`${field} is required`);
      }
    }
    
    if (!validSeverities.includes(alertData.severity)) {
      throw new Error('Invalid severity level');
    }
    
    if (alertData.title.length > 255) {
      throw new Error('Title too long (max 255 characters)');
    }
    
    if (alertData.source_ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(alertData.source_ip)) {
      throw new Error('Invalid IP address format');
    }
  }

  /**
   * Safely get from cache with error handling
   * @param {string} key - Cache key
   * @returns {any|null} Cached value or null
   * @private
   */
  async safeGetCache(key) {
    try {
      return await cache.get(key);
    } catch (error) {
      logger.warn('Cache get failed', { key, error: error.message });
      return null;
    }
  }

  /**
   * Safely set cache with error handling
   * @param {string} key - Cache key
   * @param {any} value - Value to cache
   * @param {number} ttl - Time to live
   * @private
   */
  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttl);
    } catch (error) {
      logger.warn('Cache set failed', { key, error: error.message });
    }
  }

  /**
   * Invalidate cache by pattern
   * @param {string} pattern - Cache key pattern
   * @private
   */
  async invalidateCachePattern(pattern) {
    try {
      const keys = await cache.keys(pattern);
      if (keys.length > 0) {
        await cache.del(keys);
        logger.info('Cache invalidated', { pattern, keys_count: keys.length });
      }
    } catch (error) {
      logger.warn('Cache invalidation failed', { pattern, error: error.message });
    }
  }

  /**
   * Create a new alert with transaction support
   * @param {Object} alertData - Alert data
   * @returns {Object} Created alert
   */
  async createAlert(alertData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate input
      this.validateAlertData(alertData);

      // Set default values
      const alert = await Alert.create({
        ...alertData,
        first_occurrence: new Date(),
        last_occurrence: new Date(),
        occurrence_count: 1,
        notifications_sent: 0
      }, { transaction });

      // Record metrics
      metricsHelpers.recordSecurityAlert(
        alert.severity,
        alert.type,
        alert.source
      );

      // Check for auto-resolution settings
      if (alert.auto_resolve && alert.auto_resolve_after) {
        this.scheduleAutoResolution(alert.id, alert.auto_resolve_after);
      }

      // Commit transaction before external operations
      await transaction.commit();

      // Trigger notifications if needed (after commit)
      await this.processAlertNotifications(alert);

      // Invalidate related cache
      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert created successfully', {
        alert_id: alert.id,
        type: alert.type,
        severity: alert.severity,
        source: alert.source
      });

      return alert;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to create alert', { 
        error: error.message,
        alertData: alertData 
      });
      throw error;
    }
  }

  /**
   * Get alerts with filtering and pagination
   * @param {Object} filters - Filter criteria
   * @param {Object} pagination - Pagination options
   * @returns {Object} Paginated alerts
   */
  async getAlerts(filters = {}, pagination = { page: 1, limit: 20 }) {
    try {
      // Validate pagination
      const page = Math.max(1, parseInt(pagination.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(pagination.limit) || 20));

      // Generate cache key based on filters and pagination
      const cacheKey = `alerts_${JSON.stringify(filters)}_${page}_${limit}`;
      const cachedResult = await this.safeGetCache(cacheKey);

      if (cachedResult) {
        logger.info('Returning cached alerts', { cache_key: cacheKey });
        return cachedResult;
      }

      const whereClause = {};
      
      // Apply filters with validation
      if (filters.severity) {
        const validSeverities = ['low', 'medium', 'high', 'critical'];
        const severities = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
        const validatedSeverities = severities.filter(s => validSeverities.includes(s));
        if (validatedSeverities.length > 0) {
          whereClause.severity = { [Op.in]: validatedSeverities };
        }
      }
      
      if (filters.status) {
        const validStatuses = ['active', 'acknowledged', 'resolved', 'suppressed'];
        if (validStatuses.includes(filters.status)) {
          whereClause.status = filters.status;
        }
      }
      
      if (filters.type) {
        whereClause.type = filters.type;
      }
      
      if (filters.source) {
        whereClause.source = { [Op.iLike]: `%${filters.source}%` };
      }
      
      if (filters.source_ip) {
        // Validate IP format
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(filters.source_ip)) {
          whereClause.source_ip = filters.source_ip;
        }
      }
      
      if (filters.start_date || filters.end_date) {
        whereClause.created_at = {};
        if (filters.start_date) {
          const startDate = new Date(filters.start_date);
          if (!isNaN(startDate.getTime())) {
            whereClause.created_at[Op.gte] = startDate;
          }
        }
        if (filters.end_date) {
          const endDate = new Date(filters.end_date);
          if (!isNaN(endDate.getTime())) {
            whereClause.created_at[Op.lte] = endDate;
          }
        }
      }

      const { count, rows } = await Alert.findAndCountAll({
        where: whereClause,
        limit: limit,
        offset: (page - 1) * limit,
        order: [
          ['severity', 'DESC'],
          ['created_at', 'DESC']
        ],
        include: [
          {
            model: Rule,
            as: 'rule',
            attributes: ['id', 'description', 'interface', 'action'],
            required: false
          },
          {
            model: Policy,
            as: 'policy',
            attributes: ['id', 'name', 'type'],
            required: false
          },
          {
            model: User,
            as: 'acknowledgedBy',
            attributes: ['id', 'username', 'email'],
            required: false
          },
          {
            model: User,
            as: 'resolvedBy',
            attributes: ['id', 'username', 'email'],
            required: false
          },
          {
            model: User,
            as: 'suppressedBy',
            attributes: ['id', 'username', 'email'],
            required: false
          }
        ]
      });

      const result = {
        data: rows,
        pagination: {
          total: count,
          page: page,
          limit: limit,
          total_pages: Math.ceil(count / limit)
        }
      };

      // Cache the result
      await this.safeSetCache(cacheKey, result, this.cacheTimeout);

      return result;
    } catch (error) {
      logger.error('Failed to get alerts', { 
        error: error.message,
        filters: filters 
      });
      throw error;
    }
  }

  /**
   * Acknowledge an alert with transaction support
   * @param {number} alertId - Alert ID
   * @param {number} userId - User ID acknowledging the alert
   * @param {string} note - Optional acknowledgment note
   * @returns {Object} Updated alert
   */
  async acknowledgeAlert(alertId, userId, note = null) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!alertId || !userId) {
        throw new Error('Alert ID and User ID are required');
      }

      // Verify user exists and has appropriate role
      const user = await User.findByPk(userId, { transaction });
      if (!user) {
        throw new Error('User not found');
      }
      if (!['admin', 'operator'].includes(user.role)) {
        throw new Error('User does not have permission to acknowledge alerts');
      }

      const alert = await Alert.findByPk(alertId, { transaction });
      if (!alert) {
        throw new Error('Alert not found');
      }

      if (alert.status !== 'active') {
        throw new Error('Only active alerts can be acknowledged');
      }

      const updatedAlert = await alert.update({
        status: 'acknowledged',
        acknowledged_at: new Date(),
        acknowledged_by: userId,
        acknowledgment_note: note
      }, { transaction });

      await transaction.commit();

      // Record response time metric
      const responseTime = updatedAlert.getResponseTime();
      if (responseTime !== null) {
        metricsHelpers.recordAlertResponseTime(alert.type, 'acknowledge', responseTime);
      }

      // Invalidate related cache
      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert acknowledged', {
        alert_id: alertId,
        acknowledged_by: userId,
        username: user.username,
        response_time_minutes: responseTime,
        note: note
      });

      return updatedAlert;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to acknowledge alert', { 
        error: error.message,
        alert_id: alertId,
        user_id: userId 
      });
      throw error;
    }
  }

  /**
   * Resolve an alert with transaction support
   * @param {number} alertId - Alert ID
   * @param {number} userId - User ID resolving the alert
   * @param {string} resolution - Resolution description
   * @returns {Object} Updated alert
   */
  async resolveAlert(alertId, userId, resolution = null) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!alertId || !userId) {
        throw new Error('Alert ID and User ID are required');
      }

      // Verify user exists and has appropriate role
      const user = await User.findByPk(userId, { transaction });
      if (!user) {
        throw new Error('User not found');
      }
      if (!['admin', 'operator'].includes(user.role)) {
        throw new Error('User does not have permission to resolve alerts');
      }

      const alert = await Alert.findByPk(alertId, { transaction });
      if (!alert) {
        throw new Error('Alert not found');
      }

      if (alert.status === 'resolved') {
        throw new Error('Alert is already resolved');
      }

      const updatedAlert = await alert.update({
        status: 'resolved',
        resolved_at: new Date(),
        resolved_by: userId,
        resolution: resolution
      }, { transaction });

      await transaction.commit();

      // Record response time metric
      const responseTime = updatedAlert.getResponseTime();
      if (responseTime !== null) {
        metricsHelpers.recordAlertResponseTime(alert.type, 'resolve', responseTime);
      }

      // Invalidate related cache
      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert resolved', {
        alert_id: alertId,
        resolved_by: userId,
        username: user.username,
        resolution_time_minutes: responseTime,
        resolution: resolution
      });

      return updatedAlert;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to resolve alert', { 
        error: error.message,
        alert_id: alertId,
        user_id: userId 
      });
      throw error;
    }
  }

  /**
   * Suppress an alert with transaction support
   * @param {number} alertId - Alert ID
   * @param {number} userId - User ID suppressing the alert
   * @param {number} durationMinutes - Suppression duration in minutes
   * @param {string} reason - Suppression reason
   * @returns {Object} Updated alert
   */
  async suppressAlert(alertId, userId, durationMinutes, reason) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!alertId || !userId || !durationMinutes || !reason) {
        throw new Error('Alert ID, User ID, duration, and reason are required');
      }

      if (durationMinutes <= 0 || durationMinutes > 10080) { // Max 7 days
        throw new Error('Duration must be between 1 and 10080 minutes (7 days)');
      }

      // Verify user exists and has appropriate role
      const user = await User.findByPk(userId, { transaction });
      if (!user) {
        throw new Error('User not found');
      }
      if (!['admin', 'operator'].includes(user.role)) {
        throw new Error('User does not have permission to suppress alerts');
      }

      const alert = await Alert.findByPk(alertId, { transaction });
      if (!alert) {
        throw new Error('Alert not found');
      }

      const suppressedUntil = new Date(Date.now() + durationMinutes * 60 * 1000);

      const updatedAlert = await alert.update({
        status: 'suppressed',
        suppressed_until: suppressedUntil,
        suppressed_by: userId,
        suppression_reason: reason
      }, { transaction });

      await transaction.commit();

      // Invalidate related cache
      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert suppressed', {
        alert_id: alertId,
        suppressed_by: userId,
        username: user.username,
        suppressed_until: suppressedUntil,
        duration_minutes: durationMinutes,
        reason: reason
      });

      return updatedAlert;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to suppress alert', { 
        error: error.message,
        alert_id: alertId,
        user_id: userId 
      });
      throw error;
    }
  }

  /**
   * Create security alert from firewall rule violation
   * @param {Object} ruleViolation - Rule violation data
   * @returns {Object} Created alert
   */
  async createSecurityAlert(ruleViolation) {
    try {
      // Validate input
      if (!ruleViolation || !ruleViolation.source_ip) {
        throw new Error('Invalid rule violation data');
      }

      const { rule_id, source_ip, source_port, destination_ip, destination_port, protocol } = ruleViolation;

      // Check if similar alert exists in the last hour
      const existingAlert = await this.findSimilarAlert({
        type: 'firewall_rule_violation',
        rule_id,
        source_ip,
        timeWindow: 60 // minutes
      });

      if (existingAlert) {
        // Update existing alert
        return await this.incrementAlertOccurrence(existingAlert.id);
      }

      // Get rule details
      const rule = rule_id ? await Rule.findByPk(rule_id) : null;

      const alertData = {
        title: 'Firewall Rule Violation',
        message: `Traffic blocked by firewall rule: ${rule?.description || 'Unknown rule'}`,
        type: 'firewall_rule_violation',
        severity: this.determineSeverityFromRule(rule),
        source: 'firewall',
        source_ip,
        source_port,
        rule_id,
        metadata: {
          destination_ip,
          destination_port,
          protocol,
          rule_description: rule?.description,
          rule_interface: rule?.interface
        }
      };

      return await this.createAlert(alertData);
    } catch (error) {
      logger.error('Failed to create security alert', { 
        error: error.message,
        ruleViolation: ruleViolation 
      });
      throw error;
    }
  }

  /**
   * Create system alert
   * @param {Object} systemEvent - System event data
   * @returns {Object} Created alert
   */
  async createSystemAlert(systemEvent) {
    try {
      // Validate input
      if (!systemEvent || !systemEvent.type || !systemEvent.message) {
        throw new Error('Invalid system event data');
      }

      const { type, message, severity, source, metadata } = systemEvent;

      const alertData = {
        title: this.generateAlertTitle(type),
        message,
        type,
        severity: severity || 'medium',
        source: source || 'system',
        metadata
      };

      return await this.createAlert(alertData);
    } catch (error) {
      logger.error('Failed to create system alert', { 
        error: error.message,
        systemEvent: systemEvent 
      });
      throw error;
    }
  }

  /**
   * Get alert statistics with improved caching
   * @param {Object} timeRange - Time range for statistics
   * @returns {Object} Alert statistics
   */
  async getAlertStatistics(timeRange = { hours: 24 }) {
    try {
      // Validate time range
      const hours = Math.min(8760, Math.max(1, parseInt(timeRange.hours) || 24)); // Max 1 year

      const cacheKey = `alert_statistics_${hours}`;
      const cachedStats = await this.safeGetCache(cacheKey);

      if (cachedStats) {
        logger.info('Returning cached alert statistics', { cache_key: cacheKey });
        return cachedStats;
      }

      const since = new Date(Date.now() - hours * 60 * 60 * 1000);

      // Get statistics from database
      const stats = await Alert.findAll({
        attributes: [
          'status',
          'severity',
          'type',
          [Alert.sequelize.fn('COUNT', '*'), 'count']
        ],
        where: {
          created_at: { [Op.gte]: since }
        },
        group: ['status', 'severity', 'type'],
        raw: true
      });

      // Format statistics
      const formattedStats = {
        total: 0,
        by_status: {},
        by_severity: {},
        by_type: {},
        recent_critical: 0,
        response_rate: 0,
        time_range_hours: hours
      };

      stats.forEach(stat => {
        const count = parseInt(stat.count);
        formattedStats.total += count;

        formattedStats.by_status[stat.status] = (formattedStats.by_status[stat.status] || 0) + count;
        formattedStats.by_severity[stat.severity] = (formattedStats.by_severity[stat.severity] || 0) + count;
        formattedStats.by_type[stat.type] = (formattedStats.by_type[stat.type] || 0) + count;

        if (stat.severity === 'critical') {
          formattedStats.recent_critical += count;
        }
      });

      // Calculate response rate
      const acknowledgedCount = formattedStats.by_status['acknowledged'] || 0;
      const resolvedCount = formattedStats.by_status['resolved'] || 0;
      formattedStats.response_rate = formattedStats.total > 0 
        ? Math.round(((acknowledgedCount + resolvedCount) / formattedStats.total) * 100)
        : 0;

      // Cache the result
      await this.safeSetCache(cacheKey, formattedStats, this.cacheTimeout);

      return formattedStats;
    } catch (error) {
      logger.error('Failed to get alert statistics', { 
        error: error.message,
        timeRange: timeRange 
      });
      throw error;
    }
  }

  /**
   * Process alert notifications with rate limiting
   * @param {Object} alert - Alert object
   * @private
   */
  async processAlertNotifications(alert) {
    try {
      // Check notification thresholds
      if (alert.severity === 'critical' || alert.type === 'security_breach') {
        // Send immediate notification
        await this.sendNotification(alert, 'immediate');
      } else if (alert.severity === 'high') {
        // Send notification after 5 minutes if not acknowledged
        setTimeout(async () => {
          const currentAlert = await Alert.findByPk(alert.id);
          if (currentAlert && !currentAlert.acknowledged_at) {
            await this.sendNotification(currentAlert, 'delayed');
          }
        }, 5 * 60 * 1000);
      }
    } catch (error) {
      logger.error('Failed to process alert notifications', { 
        error: error.message,
        alert_id: alert.id 
      });
    }
  }

  /**
   * Send alert notification with retry logic
   * @param {Object} alert - Alert object
   * @param {string} type - Notification type
   * @private
   */
  async sendNotification(alert, type = 'immediate') {
    let retries = 0;
    
    while (retries < this.maxRetries) {
      try {
        // Update notification count
        await alert.update({
          notifications_sent: alert.notifications_sent + 1,
          last_notification_at: new Date()
        });

        // Here you would integrate with your notification system
        // (email, Slack, PagerDuty, etc.)
        logger.info('Alert notification sent', {
          alert_id: alert.id,
          notification_type: type,
          severity: alert.severity,
          title: alert.title,
          attempt: retries + 1
        });

        return; // Success, exit retry loop
      } catch (error) {
        retries++;
        logger.warn('Alert notification failed', { 
          alert_id: alert.id,
          attempt: retries,
          error: error.message
        });
        
        if (retries < this.maxRetries) {
          await new Promise(resolve => setTimeout(resolve, 1000 * retries)); // Exponential backoff
        }
      }
    }
    
    logger.error('Alert notification failed after all retries', { 
      alert_id: alert.id,
      max_retries: this.maxRetries
    });
  }

  /**
   * Find similar alert within time window with improved caching
   * @param {Object} criteria - Search criteria
   * @returns {Object|null} Existing alert or null
   * @private
   */
  async findSimilarAlert(criteria) {
    try {
      const { type, rule_id, source_ip, timeWindow } = criteria;
      const cacheKey = `similar_alert_${type}_${rule_id}_${source_ip}_${timeWindow}`;
      const cachedAlert = await this.safeGetCache(cacheKey);

      if (cachedAlert) {
        return cachedAlert;
      }

      const since = new Date(Date.now() - timeWindow * 60 * 1000);

      const alert = await Alert.findOne({
        where: {
          type,
          rule_id,
          source_ip,
          status: 'active',
          created_at: { [Op.gte]: since }
        },
        order: [['created_at', 'DESC']]
      });

      // Cache the result
      await this.safeSetCache(cacheKey, alert, 60);

      return alert;
    } catch (error) {
      logger.error('Failed to find similar alert', { 
        error: error.message,
        criteria: criteria 
      });
      return null;
    }
  }

  /**
   * Increment alert occurrence count with transaction
   * @param {number} alertId - Alert ID
   * @returns {Object} Updated alert
   * @private
   */
  async incrementAlertOccurrence(alertId) {
    const transaction = await sequelize.transaction();
    
    try {
      const alert = await Alert.findByPk(alertId, { transaction });
      if (!alert) {
        throw new Error('Alert not found');
      }

      const updatedAlert = await alert.update({
        last_occurrence: new Date(),
        occurrence_count: alert.occurrence_count + 1
      }, { transaction });

      await transaction.commit();

      // Invalidate related cache
      await this.invalidateCachePattern(`similar_alert_${alert.type}_${alert.rule_id}_${alert.source_ip}_*`);

      return updatedAlert;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to increment alert occurrence', { 
        error: error.message,
        alert_id: alertId 
      });
      throw error;
    }
  }

  /**
   * Determine severity from firewall rule
   * @param {Object} rule - Rule object
   * @returns {string} Severity level
   * @private
   */
  determineSeverityFromRule(rule) {
    if (!rule) return 'medium';

    // Business logic for determining severity
    if (rule.action === 'block' && rule.interface === 'wan') {
      return 'high';
    }
    if (rule.action === 'reject') {
      return 'medium';
    }
    return 'low';
  }

  /**
   * Generate alert title based on type
   * @param {string} type - Alert type
   * @returns {string} Generated title
   * @private
   */
  generateAlertTitle(type) {
    const titleMap = {
      'system_error': 'System Error Detected',
      'performance_issue': 'Performance Issue',
      'configuration_change': 'Configuration Change',
      'authentication_failure': 'Authentication Failure',
      'network_anomaly': 'Network Anomaly',
      'service_failure': 'Service Failure'
    };

    return titleMap[type] || 'System Alert';
  }

  /**
   * Schedule auto-resolution for an alert
   * @param {number} alertId - Alert ID
   * @param {number} minutes - Minutes until auto-resolution
   * @private
   */
  scheduleAutoResolution(alertId, minutes) {
    setTimeout(async () => {
      try {
        const alert = await Alert.findByPk(alertId);
        if (alert && alert.status === 'active') {
          await this.resolveAlert(alertId, null, 'Auto-resolved after configured time period');
          logger.info('Alert auto-resolved', { alert_id: alertId });
        }
      } catch (error) {
        logger.error('Failed to auto-resolve alert', { 
          error: error.message,
          alert_id: alertId 
        });
      }
    }, minutes * 60 * 1000);
  }

  /**
   * Cleanup old resolved alerts with improved batch processing
   * @param {number} daysOld - Days to keep resolved alerts
   * @returns {number} Number of alerts cleaned up
   */
  async cleanupOldAlerts(daysOld = 90) {
    const transaction = await sequelize.transaction();
    
    try {
      const cutoffDate = new Date(Date.now() - daysOld * 24 * 60 * 60 * 1000);

      const deletedCount = await Alert.destroy({
        where: {
          status: 'resolved',
          resolved_at: { [Op.lt]: cutoffDate }
        },
        transaction
      });

      await transaction.commit();

      // Invalidate related cache
      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Old alerts cleaned up', { 
        deleted_count: deletedCount,
        cutoff_date: cutoffDate 
      });

      return deletedCount;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to cleanup old alerts', { error: error.message });
      throw error;
    }
  }
}

module.exports = AlertService;