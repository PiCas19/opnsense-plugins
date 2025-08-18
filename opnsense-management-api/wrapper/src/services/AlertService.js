// src/services/AlertService.js

const Alert = require('../models/Alert');
const Rule = require('../models/Rule');
const Policy = require('../models/Policy');
const User = require('../models/User');
const { cache, sequelize } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const logger = require('../utils/logger');
const { Op } = require('sequelize');

class AlertService {
  /**
   * Service for creating, querying and managing security/system alerts.
   * All inputs are normalized against model enums to avoid DB enum errors.
   *
   * @param {Object|null} user - Current authenticated user (optional).
   */
  constructor(user = null) {
    this.user = user;
    this.cacheTimeout = parseInt(process.env.CACHE_TIMEOUT || '60', 10);
    this.maxRetries = parseInt(process.env.MAX_RETRIES || '3', 10);

    // Pre-read enum sets from Sequelize model when available
    this.allowedTypes =
      Alert?.rawAttributes?.type?.values ??
      [
        // conservative superset fallback (kept in sync with migrations)
        'system_error',
        'performance_issue',
        'configuration_change',
        'authentication_failure',
        'network_anomaly',
        'service_failure',
        'firewall_rule_violation',
        'security_breach',
        'info',
        'warning',
        'error',
      ];

    this.allowedSeverities =
      Alert?.rawAttributes?.severity?.values ?? ['low', 'medium', 'high', 'critical'];

    this.allowedStatuses =
      Alert?.rawAttributes?.status?.values ?? ['active', 'acknowledged', 'resolved', 'suppressed'];
  }

  /* ----------------------------- helpers -------------------------------- */

  /**
   * Normalize an alert type against enum values.
   * Maps legacy/unknown values to a safe fallback that exists in DB.
   * @param {string} type
   * @returns {string}
   */
  normalizeType(type) {
    if (!type || typeof type !== 'string') return 'system_error';

    const t = String(type).trim();

    // Legacy aliases → canonical values
    const aliases = {
      configuration_error: 'system_error',
      config_error: 'system_error',
      auth_error: 'authentication_failure',
      perf_issue: 'performance_issue',
      net_anomaly: 'network_anomaly',
    };

    const candidate = aliases[t] || t;
    if (this.allowedTypes.includes(candidate)) return candidate;

    logger.warn('Unknown alert type, falling back to system_error', { type });
    return 'system_error';
  }

  /**
   * Normalize a severity against enum values.
   * Falls back to 'medium' if invalid.
   * @param {string} severity
   * @returns {string}
   */
  normalizeSeverity(severity) {
    if (this.allowedSeverities.includes(severity)) return severity;
    logger.warn('Unknown severity, falling back to medium', { severity });
    return 'medium';
  }

  /**
   * Normalize a status against enum values.
   * Falls back to 'active' if invalid.
   * @param {string} status
   * @returns {string}
   */
  normalizeStatus(status) {
    if (this.allowedStatuses.includes(status)) return status;
    return 'active';
  }

  /**
   * Basic IPv4 validation.
   * @param {string} ip
   * @returns {boolean}
   */
  isValidIPv4(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip || '');
  }

  /**
   * Defensive cache get.
   * @param {string} key
   * @returns {Promise<any|null>}
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
   * Defensive cache set.
   * @param {string} key
   * @param {any} value
   * @param {number} ttl
   */
  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttl);
    } catch (error) {
      logger.warn('Cache set failed', { key, error: error.message });
    }
  }

  /**
   * Invalidate keys by pattern (best-effort).
   * @param {string} pattern
   */
  async invalidateCachePattern(pattern) {
    try {
      const keys = await cache.keys(pattern);
      if (keys?.length) {
        await cache.del(keys);
        logger.info('Cache invalidated', { pattern, keys_count: keys.length });
      }
    } catch (error) {
      logger.warn('Cache invalidation failed', { pattern, error: error.message });
    }
  }

  /**
   * Validate/normalize a payload before persisting.
   * Throws on structural errors; coerces enums.
   * @param {Object} alertData
   * @returns {Object} sanitized copy
   */
  sanitizeAlertData(alertData) {
    const data = { ...(alertData || {}) };

    // Required fields
    const required = ['title', 'message'];
    for (const f of required) {
      if (!data[f]) throw new Error(`${f} is required`);
    }

    if (String(data.title).length > 255) {
      throw new Error('Title too long (max 255 characters)');
    }

    // Normalize enums
    data.type = this.normalizeType(data.type || 'system_error');
    data.severity = this.normalizeSeverity(data.severity || 'medium');
    data.status = this.normalizeStatus(data.status || 'active');

    // Optional IPv4
    if (data.source_ip && !this.isValidIPv4(data.source_ip)) {
      throw new Error('Invalid IP address format');
    }

    return data;
  }

  /* ------------------------------ create -------------------------------- */

  /**
   * Create a new alert (transactional).
   * Data is sanitized to match DB enums to avoid enum errors.
   * @param {Object} alertData
   * @returns {Promise<Alert>}
   */
  async createAlert(alertData) {
    const tx = await sequelize.transaction();
    try {
      const data = this.sanitizeAlertData(alertData);

      const alert = await Alert.create(
        {
          ...data,
          first_occurrence: new Date(),
          last_occurrence: new Date(),
          occurrence_count: 1,
          notifications_sent: 0,
        },
        { transaction: tx }
      );

      // Metrics
      metricsHelpers.recordSecurityAlert(alert.severity, alert.type, alert.source);

      await tx.commit();

      // Async post-commit side effects
      await this.processAlertNotifications(alert);
      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert created successfully', {
        alert_id: alert.id,
        type: alert.type,
        severity: alert.severity,
        source: alert.source,
      });

      return alert;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to create alert', { error: error.message, alertData });
      throw error;
    }
  }

  /**
   * Create system alert from a system event.
   * Unknown/legacy types are normalized safely.
   * @param {{type:string,message:string,severity?:string,source?:string,metadata?:Object,title?:string}} systemEvent
   * @returns {Promise<Alert>}
   */
  async createSystemAlert(systemEvent) {
    try {
      if (!systemEvent || !systemEvent.type || !systemEvent.message) {
        throw new Error('Invalid system event data');
      }

      const data = this.sanitizeAlertData({
        title: systemEvent.title || this.generateAlertTitle(systemEvent.type),
        message: systemEvent.message,
        type: this.normalizeType(systemEvent.type),
        severity: this.normalizeSeverity(systemEvent.severity || 'medium'),
        source: systemEvent.source || 'system',
        metadata: systemEvent.metadata,
      });

      return await this.createAlert(data);
    } catch (error) {
      logger.error('Failed to create system alert', { error: error.message, systemEvent });
      throw error;
    }
  }

  /**
   * Create a security alert from a firewall violation.
   * @param {Object} ruleViolation
   * @returns {Promise<Alert>}
   */
  async createSecurityAlert(ruleViolation) {
    try {
      if (!ruleViolation || !ruleViolation.source_ip) {
        throw new Error('Invalid rule violation data');
      }

      const { rule_id, source_ip, source_port, destination_ip, destination_port, protocol } =
        ruleViolation;

      // De-duplicate within last hour
      const existing = await this.findSimilarAlert({
        type: 'firewall_rule_violation',
        rule_id,
        source_ip,
        timeWindow: 60,
      });
      if (existing) return await this.incrementAlertOccurrence(existing.id);

      const rule = rule_id ? await Rule.findByPk(rule_id) : null;

      const data = this.sanitizeAlertData({
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
          rule_interface: rule?.interface,
        },
      });

      return await this.createAlert(data);
    } catch (error) {
      logger.error('Failed to create security alert', { error: error.message, ruleViolation });
      throw error;
    }
  }

  /* ----------------------------- querying ------------------------------- */

  /**
   * Get alerts with filtering & pagination (cached).
   * All incoming filter values are validated against enums.
   * @param {Object} filters
   * @param {{page:number,limit:number}} pagination
   * @returns {Promise<{data:Alert[], pagination:Object}>}
   */
  async getAlerts(filters = {}, pagination = { page: 1, limit: 20 }) {
    try {
      const page = Math.max(1, parseInt(pagination.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(pagination.limit) || 20));

      const cacheKey = `alerts_${JSON.stringify(filters)}_${page}_${limit}`;
      const cached = await this.safeGetCache(cacheKey);
      if (cached) {
        logger.info('Returning cached alerts', { cache_key: cacheKey });
        return cached;
      }

      const where = {};

      // type filter (enum-safe)
      if (filters.type) {
        const types = Array.isArray(filters.type) ? filters.type : [filters.type];
        const valid = types.map((t) => this.normalizeType(t)).filter((t, i, a) => a.indexOf(t) === i);
        if (valid.length) where.type = { [Op.in]: valid };
      }

      // severity filter (enum-safe)
      if (filters.severity) {
        const severities = Array.isArray(filters.severity) ? filters.severity : [filters.severity];
        const valid = severities
          .map((s) => this.normalizeSeverity(s))
          .filter((s, i, a) => a.indexOf(s) === i);
        if (valid.length) where.severity = { [Op.in]: valid };
      }

      // status filter (enum-safe)
      if (filters.status) {
        const s = this.normalizeStatus(filters.status);
        where.status = s;
      }

      if (filters.source) where.source = { [Op.iLike]: `%${String(filters.source).trim()}%` };
      if (filters.source_ip && this.isValidIPv4(filters.source_ip)) where.source_ip = filters.source_ip;

      if (filters.start_date || filters.end_date) {
        where.created_at = {};
        if (filters.start_date) {
          const d = new Date(filters.start_date);
          if (!isNaN(d)) where.created_at[Op.gte] = d;
        }
        if (filters.end_date) {
          const d = new Date(filters.end_date);
          if (!isNaN(d)) where.created_at[Op.lte] = d;
        }
      }

      const { count, rows } = await Alert.findAndCountAll({
        where,
        limit,
        offset: (page - 1) * limit,
        order: [
          ['severity', 'DESC'],
          ['created_at', 'DESC'],
        ],
        include: [
          { model: Rule, as: 'rule', attributes: ['id, description', 'interface', 'action'], required: false },
          { model: Policy, as: 'policy', attributes: ['id', 'name', 'type'], required: false },
          { model: User, as: 'acknowledgedBy', attributes: ['id', 'username', 'email'], required: false },
          { model: User, as: 'resolvedBy', attributes: ['id', 'username', 'email'], required: false },
          { model: User, as: 'suppressedBy', attributes: ['id', 'username', 'email'], required: false },
        ],
      });

      const result = {
        data: rows,
        pagination: { total: count, page, limit, total_pages: Math.ceil(count / limit) },
      };

      await this.safeSetCache(cacheKey, result, this.cacheTimeout);
      return result;
    } catch (error) {
      logger.error('Failed to get alerts', { error: error.message, filters });
      throw error;
    }
  }

  /* ------------------------------ actions ------------------------------- */

  /**
   * Acknowledge an alert (transactional).
   * @param {number} alertId
   * @param {number} userId
   * @param {string|null} note
   * @returns {Promise<Alert>}
   */
  async acknowledgeAlert(alertId, userId, note = null) {
    const tx = await sequelize.transaction();
    try {
      if (!alertId || !userId) throw new Error('Alert ID and User ID are required');

      const user = await User.findByPk(userId, { transaction: tx });
      if (!user) throw new Error('User not found');
      if (!['admin', 'operator'].includes(user.role)) {
        throw new Error('User does not have permission to acknowledge alerts');
      }

      const alert = await Alert.findByPk(alertId, { transaction: tx });
      if (!alert) throw new Error('Alert not found');
      if (alert.status !== 'active') throw new Error('Only active alerts can be acknowledged');

      const updated = await alert.update(
        {
          status: 'acknowledged',
          acknowledged_at: new Date(),
          acknowledged_by: userId,
          acknowledgment_note: note,
        },
        { transaction: tx }
      );

      await tx.commit();

      const minutes = updated.getResponseTime?.();
      if (minutes != null) metricsHelpers.recordAlertResponseTime(alert.type, 'acknowledge', minutes);

      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert acknowledged', {
        alert_id: alertId,
        acknowledged_by: userId,
        username: user.username,
        response_time_minutes: minutes,
      });

      return updated;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to acknowledge alert', { error: error.message, alert_id: alertId, user_id: userId });
      throw error;
    }
  }

  /**
   * Resolve an alert (transactional). `userId` can be null for auto-resolution.
   * @param {number} alertId
   * @param {number|null} userId
   * @param {string|null} resolution
   * @returns {Promise<Alert>}
   */
  async resolveAlert(alertId, userId = null, resolution = null) {
    const tx = await sequelize.transaction();
    try {
      if (!alertId) throw new Error('Alert ID is required');

      let user = null;
      if (userId != null) {
        user = await User.findByPk(userId, { transaction: tx });
        if (!user) throw new Error('User not found');
        if (!['admin', 'operator'].includes(user.role)) {
          throw new Error('User does not have permission to resolve alerts');
        }
      }

      const alert = await Alert.findByPk(alertId, { transaction: tx });
      if (!alert) throw new Error('Alert not found');
      if (alert.status === 'resolved') throw new Error('Alert is already resolved');

      const updated = await alert.update(
        {
          status: 'resolved',
          resolved_at: new Date(),
          resolved_by: userId || null,
          resolution: resolution,
        },
        { transaction: tx }
      );

      await tx.commit();

      const minutes = updated.getResponseTime?.();
      if (minutes != null) metricsHelpers.recordAlertResponseTime(alert.type, 'resolve', minutes);

      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert resolved', {
        alert_id: alertId,
        resolved_by: userId || 'auto',
        resolution_time_minutes: minutes,
      });

      return updated;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to resolve alert', { error: error.message, alert_id: alertId, user_id: userId });
      throw error;
    }
  }

  /**
   * Suppress an alert for a period (transactional).
   * @param {number} alertId
   * @param {number} userId
   * @param {number} durationMinutes
   * @param {string} reason
   * @returns {Promise<Alert>}
   */
  async suppressAlert(alertId, userId, durationMinutes, reason) {
    const tx = await sequelize.transaction();
    try {
      if (!alertId || !userId || !durationMinutes || !reason) {
        throw new Error('Alert ID, User ID, duration, and reason are required');
      }
      if (durationMinutes <= 0 || durationMinutes > 10080) {
        throw new Error('Duration must be between 1 and 10080 minutes (7 days)');
      }

      const user = await User.findByPk(userId, { transaction: tx });
      if (!user) throw new Error('User not found');
      if (!['admin', 'operator'].includes(user.role)) {
        throw new Error('User does not have permission to suppress alerts');
      }

      const alert = await Alert.findByPk(alertId, { transaction: tx });
      if (!alert) throw new Error('Alert not found');

      const until = new Date(Date.now() + durationMinutes * 60 * 1000);

      const updated = await alert.update(
        {
          status: 'suppressed',
          suppressed_until: until,
          suppressed_by: userId,
          suppression_reason: reason,
        },
        { transaction: tx }
      );

      await tx.commit();

      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Alert suppressed', {
        alert_id: alertId,
        suppressed_by: userId,
        suppressed_until: until,
        duration_minutes: durationMinutes,
      });

      return updated;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to suppress alert', { error: error.message, alert_id: alertId, user_id: userId });
      throw error;
    }
  }

  /* ---------------------- similarity / notifications -------------------- */

  /**
   * Find similar alert within time window (cached).
   * @param {{type:string,rule_id:number,source_ip:string,timeWindow:number}} criteria
   * @returns {Promise<Alert|null>}
   */
  async findSimilarAlert(criteria) {
    try {
      const type = this.normalizeType(criteria?.type);
      const rule_id = criteria?.rule_id ?? null;
      const source_ip = criteria?.source_ip ?? null;
      const window = Math.max(1, parseInt(criteria?.timeWindow || 60, 10));
      const cacheKey = `similar_alert_${type}_${rule_id}_${source_ip}_${window}`;

      const cached = await this.safeGetCache(cacheKey);
      if (cached) return cached;

      const since = new Date(Date.now() - window * 60 * 1000);

      const alert = await Alert.findOne({
        where: {
          type,
          rule_id,
          source_ip,
          status: 'active',
          created_at: { [Op.gte]: since },
        },
        order: [['created_at', 'DESC']],
      });

      await this.safeSetCache(cacheKey, alert, 60);
      return alert;
    } catch (error) {
      logger.error('Failed to find similar alert', { error: error.message, criteria });
      return null;
    }
  }

  /**
   * Increment alert occurrence counter (transactional).
   * @param {number} alertId
   * @returns {Promise<Alert>}
   */
  async incrementAlertOccurrence(alertId) {
    const tx = await sequelize.transaction();
    try {
      const alert = await Alert.findByPk(alertId, { transaction: tx });
      if (!alert) throw new Error('Alert not found');

      const updated = await alert.update(
        { last_occurrence: new Date(), occurrence_count: alert.occurrence_count + 1 },
        { transaction: tx }
      );

      await tx.commit();
      await this.invalidateCachePattern(`similar_alert_${alert.type}_${alert.rule_id}_${alert.source_ip}_*`);
      return updated;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to increment alert occurrence', { error: error.message, alert_id: alertId });
      throw error;
    }
  }

  /**
   * Decide default severity from a firewall rule.
   * @param {Rule|null} rule
   * @returns {'low'|'medium'|'high'|'critical'}
   */
  determineSeverityFromRule(rule) {
    if (!rule) return 'medium';
    if (rule.action === 'block' && rule.interface === 'wan') return 'high';
    if (rule.action === 'reject') return 'medium';
    return 'low';
  }

  /**
   * Generate a human readable title from a type token.
   * @param {string} type
   * @returns {string}
   */
  generateAlertTitle(type) {
    const t = this.normalizeType(type);
    const map = {
      system_error: 'System Error Detected',
      performance_issue: 'Performance Issue',
      configuration_change: 'Configuration Change',
      authentication_failure: 'Authentication Failure',
      network_anomaly: 'Network Anomaly',
      service_failure: 'Service Failure',
      firewall_rule_violation: 'Firewall Rule Violation',
      security_breach: 'Security Breach',
      info: 'Information',
      warning: 'Warning',
      error: 'Error',
    };
    return map[t] || 'System Alert';
  }

  /**
   * Send alert notifications with retries (no-op placeholder for external integrations).
   * @param {Alert} alert
   * @param {'immediate'|'delayed'} type
   */
  async sendNotification(alert, type = 'immediate') {
    let retries = 0;
    while (retries < this.maxRetries) {
      try {
        await alert.update({
          notifications_sent: alert.notifications_sent + 1,
          last_notification_at: new Date(),
        });

        // hook integration here (email/Slack/etc.)
        logger.info('Alert notification sent', {
          alert_id: alert.id,
          notification_type: type,
          severity: alert.severity,
          title: alert.title,
          attempt: retries + 1,
        });
        return;
      } catch (error) {
        retries++;
        logger.warn('Alert notification failed', {
          alert_id: alert.id,
          attempt: retries,
          error: error.message,
        });
        if (retries < this.maxRetries) {
          await new Promise((r) => setTimeout(r, 1000 * retries));
        }
      }
    }
    logger.error('Alert notification failed after all retries', {
      alert_id: alert.id,
      max_retries: this.maxRetries,
    });
  }

  /**
   * Notification policy:
   * - critical or security_breach → immediate
   * - high → delayed (5 minutes) unless acknowledged before
   * @param {Alert} alert
   */
  async processAlertNotifications(alert) {
    try {
      if (alert.severity === 'critical' || alert.type === 'security_breach') {
        await this.sendNotification(alert, 'immediate');
      } else if (alert.severity === 'high') {
        setTimeout(async () => {
          try {
            const current = await Alert.findByPk(alert.id);
            if (current && !current.acknowledged_at) {
              await this.sendNotification(current, 'delayed');
            }
          } catch (e) {
            logger.error('Delayed notification failed', { alert_id: alert.id, error: e.message });
          }
        }, 5 * 60 * 1000);
      }
    } catch (error) {
      logger.error('Failed to process alert notifications', { error: error.message, alert_id: alert.id });
    }
  }

  /* ----------------------------- statistics ----------------------------- */

  /**
   * Aggregate alert statistics (cached).
   * @param {{hours:number}} timeRange
   * @returns {Promise<Object>}
   */
  async getAlertStatistics(timeRange = { hours: 24 }) {
    try {
      const hours = Math.min(8760, Math.max(1, parseInt(timeRange.hours || 24, 10)));
      const cacheKey = `alert_statistics_${hours}`;
      const cached = await this.safeGetCache(cacheKey);
      if (cached) {
        logger.info('Returning cached alert statistics', { cache_key: cacheKey });
        return cached;
      }

      const since = new Date(Date.now() - hours * 3600 * 1000);

      const rows = await Alert.findAll({
        attributes: ['status', 'severity', 'type', [Alert.sequelize.fn('COUNT', '*'), 'count']],
        where: { created_at: { [Op.gte]: since } },
        group: ['status', 'severity', 'type'],
        raw: true,
      });

      const stats = {
        total: 0,
        by_status: {},
        by_severity: {},
        by_type: {},
        recent_critical: 0,
        response_rate: 0,
        time_range_hours: hours,
      };

      for (const r of rows) {
        const count = parseInt(r.count, 10);
        stats.total += count;
        stats.by_status[r.status] = (stats.by_status[r.status] || 0) + count;
        stats.by_severity[r.severity] = (stats.by_severity[r.severity] || 0) + count;
        stats.by_type[r.type] = (stats.by_type[r.type] || 0) + count;
        if (r.severity === 'critical') stats.recent_critical += count;
      }

      const ack = stats.by_status['acknowledged'] || 0;
      const res = stats.by_status['resolved'] || 0;
      stats.response_rate = stats.total ? Math.round(((ack + res) / stats.total) * 100) : 0;

      await this.safeSetCache(cacheKey, stats, this.cacheTimeout);
      return stats;
    } catch (error) {
      logger.error('Failed to get alert statistics', { error: error.message, timeRange });
      throw error;
    }
  }

  /* ------------------------------ cleanup ------------------------------- */

  /**
   * Schedule auto-resolution after N minutes (best-effort).
   * @param {number} alertId
   * @param {number} minutes
   */
  scheduleAutoResolution(alertId, minutes) {
    const ms = Math.max(1, parseInt(minutes || 0, 10)) * 60 * 1000;
    setTimeout(async () => {
      try {
        const alert = await Alert.findByPk(alertId);
        if (alert && alert.status === 'active') {
          await this.resolveAlert(alertId, null, 'Auto-resolved after configured time period');
          logger.info('Alert auto-resolved', { alert_id: alertId });
        }
      } catch (error) {
        logger.error('Failed to auto-resolve alert', { error: error.message, alert_id: alertId });
      }
    }, ms);
  }

  /**
   * Permanently delete resolved alerts older than N days (transactional).
   * @param {number} daysOld
   * @returns {Promise<number>} number of rows deleted
   */
  async cleanupOldAlerts(daysOld = 90) {
    const tx = await sequelize.transaction();
    try {
      const cutoff = new Date(Date.now() - Math.max(1, parseInt(daysOld, 10)) * 24 * 3600 * 1000);
      const deleted = await Alert.destroy(
        { where: { status: 'resolved', resolved_at: { [Op.lt]: cutoff } }, transaction: tx }
      );
      await tx.commit();

      await this.invalidateCachePattern('alerts_*');
      await this.invalidateCachePattern('alert_statistics_*');

      logger.info('Old alerts cleaned up', { deleted_count: deleted, cutoff_date: cutoff });
      return deleted;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to cleanup old alerts', { error: error.message });
      throw error;
    }
  }
}

module.exports = AlertService;