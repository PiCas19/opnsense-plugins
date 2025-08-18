// src/services/RulesService.js
'use strict';

const { Op } = require('sequelize');
const Rule = require('../models/Rule');
const User = require('../models/User');
const AlertService = require('./AlertService');
const OpnsenseService = require('./OpnsenseService');
const { cache, sequelize } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const logger = require('../utils/logger');

/**
 * Service responsible for CRUD operations, synchronization and analytics
 * around firewall rules. It encapsulates:
 *  - input validation
 *  - permission checks
 *  - DB transactions
 *  - cache usage
 *  - integration with OPNsense
 *  - metrics and alerting
 */
class RulesService {
  /**
   * @param {Object|null} user - Authenticated user context (id, role, ...)
   */
  constructor(user = null) {
    this.user = user;
    this.alertService = new AlertService(user);
    this.opnsenseService = new OpnsenseService(user);
    this.cacheTimeout = Number(process.env.RULES_CACHE_TIMEOUT) || 60; // seconds
    this.maxRetries = Number(process.env.MAX_RETRIES) || 3;
  }

  // ---------------------------------------------------------------------------
  // Validation helpers
  // ---------------------------------------------------------------------------

  /**
   * Validate rule payload before DB operations.
   * Throws on invalid input.
   * @param {Object} ruleData
   * @private
   */
  validateRuleData(ruleData) {
    const required = ['description', 'interface', 'action'];
    const validActions = ['pass', 'block', 'reject'];
    const validInterfaces = ['wan', 'lan', 'opt1', 'opt2', 'opt3', 'lo0'];
    const validProtocols = ['tcp', 'udp', 'icmp', 'any'];

    // required fields
    for (const f of required) {
      if (!ruleData[f]) throw new Error(`${f} is required`);
    }

    // enums / ranges
    if (!validActions.includes(ruleData.action)) {
      throw new Error(`Invalid action. Must be one of: ${validActions.join(', ')}`);
    }
    if (!validInterfaces.includes(ruleData.interface)) {
      throw new Error(`Invalid interface. Must be one of: ${validInterfaces.join(', ')}`);
    }
    if (typeof ruleData.description !== 'string' ||
        ruleData.description.length < 3 || ruleData.description.length > 255) {
      throw new Error('Description must be between 3 and 255 characters');
    }
    if (ruleData.protocol && !validProtocols.includes(ruleData.protocol)) {
      throw new Error(`Invalid protocol. Must be one of: ${validProtocols.join(', ')}`);
    }

    // IP/CIDR
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (ruleData.source && ruleData.source !== 'any' && !cidrRegex.test(ruleData.source)) {
      throw new Error('Invalid source IP/CIDR format');
    }
    if (ruleData.destination && ruleData.destination !== 'any' && !cidrRegex.test(ruleData.destination)) {
      throw new Error('Invalid destination IP/CIDR format');
    }

    // Ports
    const validatePortRange = (label, value) => {
      if (!/^\d+(-\d+)?$/.test(value)) {
        throw new Error(`Invalid ${label} format (use single port or range like 80-90)`);
      }
      const [a, b] = value.split('-');
      const start = parseInt(a, 10);
      const end = b ? parseInt(b, 10) : start;
      if ([start, end].some(n => isNaN(n) || n < 1 || n > 65535) || start > end) {
        throw new Error(`Invalid ${label} range (must be 1-65535)`);
      }
    };
    if (ruleData.source_port && ruleData.source_port !== 'any') {
      validatePortRange('source port', ruleData.source_port);
    }
    if (ruleData.destination_port && ruleData.destination_port !== 'any') {
      validatePortRange('destination port', ruleData.destination_port);
    }

    // Priority / sequence
    if (ruleData.priority !== undefined) {
      const p = parseInt(ruleData.priority, 10);
      if (isNaN(p) || p < 0 || p > 1000) {
        throw new Error('Priority must be a number between 0 and 1000');
      }
    }
    if (ruleData.sequence !== undefined) {
      const s = parseInt(ruleData.sequence, 10);
      if (isNaN(s) || s < 1) {
        throw new Error('Sequence must be a positive integer');
      }
    }
  }

  /**
   * Check user permissions and account status.
   * @param {string} action - Permission key to check (e.g. 'create_rules')
   * @returns {Promise<User>}
   * @private
   */
  async validateUserPermissions(action) {
    if (!this.user) throw new Error('User authentication required');

    const user = await User.findByPk(this.user.id);
    if (!user) throw new Error('User not found');
    if (!user.is_active) throw new Error('User account is disabled');
    if (user.isAccountLocked?.()) throw new Error('User account is locked');
    if (!user.hasPermission?.(action)) {
      throw new Error(`User does not have permission to ${action}`);
    }
    return user;
  }

  // ---------------------------------------------------------------------------
  // Cache helpers
  // ---------------------------------------------------------------------------

  /**
   * Safe cache get with error shielding.
   * @param {string} key
   * @returns {Promise<*>}
   * @private
   */
  async safeGetCache(key) {
    try {
      return await cache.get(key);
    } catch (e) {
      logger.warn('Cache get failed', { key, error: e.message });
      return null;
    }
  }

  /**
   * Safe cache set with error shielding.
   * @param {string} key
   * @param {*} value
   * @param {number} ttlSeconds
   * @private
   */
  async safeSetCache(key, value, ttlSeconds = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttlSeconds);
    } catch (e) {
      logger.warn('Cache set failed', { key, error: e.message });
    }
  }

  /**
   * Invalidate a family of cache keys by pattern.
   * @param {string} pattern
   * @private
   */
  async invalidateCachePattern(pattern) {
    try {
      const keys = await cache.keys(pattern);
      if (Array.isArray(keys) && keys.length) {
        await cache.del(keys);
        logger.info('Cache invalidated', { pattern, keys_count: keys.length });
      }
    } catch (e) {
      logger.warn('Cache invalidation failed', { pattern, error: e.message });
    }
  }

  // ---------------------------------------------------------------------------
  // CRUD
  // ---------------------------------------------------------------------------

  /**
   * Create a new firewall rule (with transaction and optional OPNsense sync).
   * @param {Object} ruleData
   * @returns {Promise<Object>} created Rule
   */
  async createRule(ruleData) {
    const tx = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('create_rules');
      this.validateRuleData(ruleData);

      // prevent duplicate description on same interface
      const dup = await Rule.findOne({
        where: { description: ruleData.description, interface: ruleData.interface },
        transaction: tx,
      });
      if (dup) {
        throw new Error(
          `Rule with description '${ruleData.description}' already exists on interface '${ruleData.interface}'`
        );
      }

      // auto-sequence
      let sequence = ruleData.sequence;
      if (!sequence) {
        const last = await Rule.findOne({
          where: { interface: ruleData.interface },
          order: [['sequence', 'DESC']],
          transaction: tx,
        });
        sequence = last ? last.sequence + 10 : 100;
      }

      const rule = await Rule.create(
        {
          ...ruleData,
          sequence,
          created_by: this.user.id,
          updated_by: this.user.id,
          created_at: new Date(),
          updated_at: new Date(),
          priority: ruleData.priority ?? 100,
          enabled: ruleData.enabled ?? true,
          protocol: ruleData.protocol || 'any',
          source: ruleData.source || 'any',
          destination: ruleData.destination || 'any',
          source_port: ruleData.source_port || 'any',
          destination_port: ruleData.destination_port || 'any',
        },
        { transaction: tx }
      );

      // optional OPNsense sync
      let opnsenseRuleId = null;
      if (ruleData.sync_to_opnsense) {
        try {
          const created = await this.opnsenseService.createFirewallRule({
            description: rule.description,
            enabled: rule.enabled ? 1 : 0,
            interface: rule.interface,
            action: rule.action,
            protocol: rule.protocol || 'any',
            source: rule.source || 'any',
            destination: rule.destination || 'any',
            source_port: rule.source_port || 'any',
            destination_port: rule.destination_port || 'any',
            sequence: rule.sequence,
          });
          opnsenseRuleId = created.uuid;
          await rule.update({ opnsense_rule_id: opnsenseRuleId }, { transaction: tx });
        } catch (err) {
          logger.warn('Failed to sync rule to OPNsense', { rule_id: rule.id, error: err.message });
          // do not fail creation on remote error
        }
      }

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rule_created', {
        interface: rule.interface,
        action: rule.action,
        protocol: rule.protocol,
        synced_to_opnsense: !!opnsenseRuleId,
        user_id: this.user.id,
      });
      logger.info('Firewall rule created', {
        rule_id: rule.id,
        user_id: this.user.id,
        username: user.username,
        interface: rule.interface,
        action: rule.action,
        sequence: rule.sequence,
        synced_to_opnsense: !!opnsenseRuleId,
      });

      return rule;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to create rule', { error: error.message, ruleData, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to create firewall rule: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { ruleData, error_type: 'creation_failure' },
      });
      throw error;
    }
  }

  /**
   * Retrieve rules with filters and pagination.
   * @param {Object} filters
   * @param {{page:number,limit:number}} pagination
   * @returns {Promise<{data:Object[], pagination:Object, summary:Object}>}
   */
  async getRules(filters = {}, pagination = { page: 1, limit: 20 }) {
    try {
      const page = Math.max(1, parseInt(pagination.page, 10) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(pagination.limit, 10) || 20));
      const cacheKey = `rules_${JSON.stringify(filters)}_${page}_${limit}`;

      const cached = await this.safeGetCache(cacheKey);
      if (cached) {
        logger.info('Returning cached rules', { cache_key: cacheKey });
        return cached;
      }

      const where = {};
      if (typeof filters.description === 'string') {
        where.description = { [Op.iLike]: `%${filters.description.trim()}%` };
      }
      if (['wan', 'lan', 'opt1', 'opt2', 'opt3', 'lo0'].includes(filters.interface)) {
        where.interface = filters.interface;
      }
      if (['pass', 'block', 'reject'].includes(filters.action)) {
        where.action = filters.action;
      }
      if (typeof filters.enabled === 'boolean') {
        where.enabled = filters.enabled;
      }
      if (typeof filters.created_by === 'number') {
        where.created_by = filters.created_by;
      }
      if (['tcp', 'udp', 'icmp', 'any'].includes(filters.protocol)) {
        where.protocol = filters.protocol;
      }
      if (filters.priority !== undefined) {
        const p = parseInt(filters.priority, 10);
        if (!isNaN(p) && p >= 0 && p <= 1000) where.priority = p;
      }
      for (const f of ['source', 'destination', 'source_port', 'destination_port']) {
        if (typeof filters[f] === 'string') where[f] = { [Op.iLike]: `%${filters[f].trim()}%` };
      }
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

      const { count, rows } = await Rule.findAndCountAll({
        where,
        limit,
        offset: (page - 1) * limit,
        order: [
          ['interface', 'ASC'],
          ['sequence', 'ASC'],
          ['created_at', 'DESC'],
        ],
        include: [
          { model: User, as: 'createdBy', attributes: ['id', 'username', 'email'], required: false },
          { model: User, as: 'updatedBy', attributes: ['id', 'username', 'email'], required: false },
        ],
      });

      const result = {
        data: rows,
        pagination: {
          total: count,
          page,
          limit,
          total_pages: Math.ceil(count / limit),
        },
        summary: {
          by_interface: {},
          by_action: {},
          enabled_count: 0,
          disabled_count: 0,
        },
      };

      for (const r of rows) {
        result.summary.by_interface[r.interface] = (result.summary.by_interface[r.interface] || 0) + 1;
        result.summary.by_action[r.action] = (result.summary.by_action[r.action] || 0) + 1;
        if (r.enabled) result.summary.enabled_count++;
        else result.summary.disabled_count++;
      }

      await this.safeSetCache(cacheKey, result, this.cacheTimeout);
      logger.info('Rules retrieved and cached', { cache_key: cacheKey, total_count: count, page });

      return result;
    } catch (error) {
      logger.error('Failed to get rules', { error: error.message, filters, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to retrieve firewall rules: ${error.message}`,
        severity: 'medium',
        source: 'rules_service',
        metadata: { filters, error_type: 'retrieval_failure' },
      });
      throw error;
    }
  }

  /**
   * Update a firewall rule.
   * @param {number} ruleId
   * @param {Object} ruleData
   * @returns {Promise<Object>} updated Rule
   */
  async updateRule(ruleId, ruleData) {
    const tx = await sequelize.transaction();
    try {
      if (!ruleId || typeof ruleId !== 'number') throw new Error('Valid rule ID is required');

      const user = await this.validateUserPermissions('update_rules');
      this.validateRuleData(ruleData);

      const rule = await Rule.findByPk(ruleId, { transaction: tx });
      if (!rule) throw new Error('Rule not found');

      // unique description within same interface
      if (ruleData.description && ruleData.description !== rule.description) {
        const dup = await Rule.findOne({
          where: {
            description: ruleData.description,
            interface: ruleData.interface || rule.interface,
            id: { [Op.ne]: ruleId },
          },
          transaction: tx,
        });
        if (dup) {
          throw new Error(
            `Rule with description '${ruleData.description}' already exists on interface '${ruleData.interface || rule.interface}'`
          );
        }
      }

      const updated = await rule.update(
        { ...ruleData, updated_by: this.user.id, updated_at: new Date() },
        { transaction: tx }
      );

      // optional remote sync
      if (ruleData.sync_to_opnsense && rule.opnsense_rule_id) {
        try {
          await this.opnsenseService.updateFirewallRule(rule.opnsense_rule_id, {
            description: updated.description,
            enabled: updated.enabled ? 1 : 0,
            interface: updated.interface,
            action: updated.action,
            protocol: updated.protocol || 'any',
            source: updated.source || 'any',
            destination: updated.destination || 'any',
            source_port: updated.source_port || 'any',
            destination_port: updated.destination_port || 'any',
            sequence: updated.sequence,
          });
        } catch (err) {
          logger.warn('Failed to sync updated rule to OPNsense', {
            rule_id: ruleId,
            opnsense_rule_id: rule.opnsense_rule_id,
            error: err.message,
          });
        }
      }

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rule_updated', {
        rule_id: ruleId,
        interface: updated.interface,
        action: updated.action,
        user_id: this.user.id,
      });
      logger.info('Firewall rule updated', {
        rule_id: ruleId,
        user_id: this.user.id,
        username: user.username,
        description: updated.description,
      });

      return updated;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to update rule', { error: error.message, rule_id: ruleId, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to update firewall rule: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { ruleId, ruleData, error_type: 'update_failure' },
      });
      throw error;
    }
  }

  /**
   * Delete a firewall rule (and attempt remote deletion if synced).
   * @param {number} ruleId
   * @returns {Promise<boolean>}
   */
  async deleteRule(ruleId) {
    const tx = await sequelize.transaction();
    try {
      if (!ruleId || typeof ruleId !== 'number') throw new Error('Valid rule ID is required');

      const user = await this.validateUserPermissions('delete_rules');
      const rule = await Rule.findByPk(ruleId, { transaction: tx });
      if (!rule) throw new Error('Rule not found');

      if (rule.opnsense_rule_id) {
        try {
          await this.opnsenseService.deleteFirewallRule(rule.opnsense_rule_id);
        } catch (err) {
          logger.warn('Failed to delete rule from OPNsense', {
            rule_id: ruleId,
            opnsense_rule_id: rule.opnsense_rule_id,
            error: err.message,
          });
        }
      }

      await rule.destroy({ transaction: tx });
      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rule_deleted', {
        rule_id: ruleId,
        interface: rule.interface,
        action: rule.action,
        user_id: this.user.id,
      });
      logger.info('Firewall rule deleted', {
        rule_id: ruleId,
        user_id: this.user.id,
        username: user.username,
        rule_description: rule.description,
      });

      return true;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to delete rule', { error: error.message, rule_id: ruleId, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to delete firewall rule: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { ruleId, error_type: 'deletion_failure' },
      });
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // Synchronization
  // ---------------------------------------------------------------------------

  /**
   * Synchronize all rules that have sync_to_opnsense=true with OPNsense.
   * @returns {Promise<{success:boolean,total_rules:number,synced_count:number,error_count:number,errors:Array,timestamp:Date}>}
   */
  async syncRulesWithOpnsense() {
    const tx = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('sync_rules');

      const rules = await Rule.findAll({
        where: { sync_to_opnsense: true },
        order: [['interface', 'ASC'], ['sequence', 'ASC']],
        transaction: tx,
      });

      let syncCount = 0;
      let errorCount = 0;
      const errors = [];

      for (const rule of rules) {
        try {
          if (rule.opnsense_rule_id) {
            await this.opnsenseService.updateFirewallRule(rule.opnsense_rule_id, {
              description: rule.description,
              enabled: rule.enabled ? 1 : 0,
              interface: rule.interface,
              action: rule.action,
              protocol: rule.protocol || 'any',
              source: rule.source || 'any',
              destination: rule.destination || 'any',
              source_port: rule.source_port || 'any',
              destination_port: rule.destination_port || 'any',
              sequence: rule.sequence,
            });
          } else {
            const created = await this.opnsenseService.createFirewallRule({
              description: rule.description,
              enabled: rule.enabled ? 1 : 0,
              interface: rule.interface,
              action: rule.action,
              protocol: rule.protocol || 'any',
              source: rule.source || 'any',
              destination: rule.destination || 'any',
              source_port: rule.source_port || 'any',
              destination_port: rule.destination_port || 'any',
              sequence: rule.sequence,
            });
            await rule.update({ opnsense_rule_id: created.uuid }, { transaction: tx });
          }
          syncCount++;
        } catch (err) {
          errorCount++;
          const info = { rule_id: rule.id, rule_description: rule.description, error: err.message };
          errors.push(info);
          logger.error('Failed to sync rule with OPNsense', { ...info, user_id: this.user.id });
          await this.alertService.createSystemAlert({
            type: 'system_error',
            message: `Failed to sync rule ${rule.description} with OPNsense: ${err.message}`,
            severity: 'high',
            source: 'rules_service',
            metadata: { ruleId: rule.id, error_type: 'sync_failure' },
          });
        }
      }

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rules_synced', {
        sync_count: syncCount,
        error_count: errorCount,
        user_id: this.user.id,
      });

      const result = {
        success: errorCount === 0,
        total_rules: rules.length,
        synced_count: syncCount,
        error_count: errorCount,
        errors,
        timestamp: new Date(),
      };

      logger.info('Rules synchronization completed', { ...result, user_id: this.user.id, username: user.username });
      return result;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to sync rules with OPNsense', { error: error.message, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to sync rules with OPNsense: ${error.message}`,
        severity: 'critical',
        source: 'rules_service',
        metadata: { error_type: 'sync_operation_failure' },
      });
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // Read helpers / analytics
  // ---------------------------------------------------------------------------

  /**
   * Get a single rule by id with small cache.
   * @param {number} ruleId
   * @returns {Promise<Object>}
   */
  async getRuleById(ruleId) {
    try {
      if (!ruleId || typeof ruleId !== 'number') throw new Error('Valid rule ID is required');

      const key = `rule_${ruleId}`;
      const cached = await this.safeGetCache(key);
      if (cached) {
        logger.info('Returning cached rule', { rule_id: ruleId });
        return cached;
      }

      const rule = await Rule.findByPk(ruleId, {
        include: [
          { model: User, as: 'createdBy', attributes: ['id', 'username', 'email'], required: false },
          { model: User, as: 'updatedBy', attributes: ['id', 'username', 'email'], required: false },
        ],
      });
      if (!rule) throw new Error('Rule not found');

      await this.safeSetCache(key, rule, this.cacheTimeout);
      return rule;
    } catch (error) {
      logger.error('Failed to get rule by ID', { error: error.message, rule_id: ruleId, user_id: this.user?.id });
      throw error;
    }
  }

  /**
   * Clone a rule. By default, the clone is disabled and not synced.
   * @param {number} ruleId
   * @param {Object} overrides - Fields to override on the clone
   * @returns {Promise<Object>} cloned Rule
   */
  async cloneRule(ruleId, overrides = {}) {
    const tx = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('create_rules');

      const original = await Rule.findByPk(ruleId, { transaction: tx });
      if (!original) throw new Error('Rule to clone not found');

      // unique description generation
      let description = overrides.description || `${original.description} (Copy)`;
      let counter = 1;
      // eslint-disable-next-line no-await-in-loop
      while (await Rule.findOne({
        where: { description, interface: overrides.interface || original.interface },
        transaction: tx,
      })) {
        description = overrides.description ? `${overrides.description} (${counter})` : `${original.description} (Copy ${counter})`;
        counter++;
      }

      // sequence
      let sequence = overrides.sequence;
      if (!sequence) {
        const last = await Rule.findOne({
          where: { interface: overrides.interface || original.interface },
          order: [['sequence', 'DESC']],
          transaction: tx,
        });
        sequence = last ? last.sequence + 10 : 100;
      }

      const data = {
        description,
        interface: original.interface,
        action: original.action,
        protocol: original.protocol,
        source: original.source,
        destination: original.destination,
        source_port: original.source_port,
        destination_port: original.destination_port,
        priority: original.priority,
        enabled: overrides.enabled ?? false,                // disabled by default
        sync_to_opnsense: overrides.sync_to_opnsense ?? false, // not synced by default
        sequence,
        ...overrides,
      };

      this.validateRuleData(data);

      const cloned = await Rule.create(
        {
          ...data,
          created_by: this.user.id,
          updated_by: this.user.id,
          created_at: new Date(),
          updated_at: new Date(),
        },
        { transaction: tx }
      );

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rule_cloned', {
        original_rule_id: ruleId,
        cloned_rule_id: cloned.id,
        user_id: this.user.id,
      });
      logger.info('Rule cloned', {
        original_rule_id: ruleId,
        cloned_rule_id: cloned.id,
        user_id: this.user.id,
        username: user.username,
        cloned_description: description,
      });

      return cloned;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to clone rule', { error: error.message, rule_id: ruleId, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to clone rule: ${error.message}`,
        severity: 'medium',
        source: 'rules_service',
        metadata: { ruleId, overrides, error_type: 'clone_failure' },
      });
      throw error;
    }
  }

  /**
   * Bulk update a list of rules (limited to 50).
   * @param {number[]} ruleIds
   * @param {Object} updateData
   * @returns {Promise<{success:boolean,updated_count:number,requested_count:number,updated_fields:string[],timestamp:Date}>}
   */
  async bulkUpdateRules(ruleIds, updateData) {
    const tx = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('update_rules');

      if (!Array.isArray(ruleIds) || ruleIds.length === 0) {
        throw new Error('Rule IDs array is required');
      }
      if (ruleIds.length > 50) {
        throw new Error('Cannot update more than 50 rules at once');
      }

      const allowed = ['enabled', 'priority', 'action', 'protocol'];
      const payload = {};
      for (const k of Object.keys(updateData)) {
        if (!allowed.includes(k)) continue;
        if (k === 'action' && !['pass', 'block', 'reject'].includes(updateData[k])) {
          throw new Error(`Invalid action: ${updateData[k]}`);
        }
        if (k === 'protocol' && !['tcp', 'udp', 'icmp', 'any'].includes(updateData[k])) {
          throw new Error(`Invalid protocol: ${updateData[k]}`);
        }
        if (k === 'priority') {
          const p = parseInt(updateData[k], 10);
          if (isNaN(p) || p < 0 || p > 1000) throw new Error('Priority must be between 0 and 1000');
          payload[k] = p;
        } else {
          payload[k] = updateData[k];
        }
      }
      if (Object.keys(payload).length === 0) throw new Error('No valid fields to update');

      payload.updated_by = this.user.id;
      payload.updated_at = new Date();

      const [count] = await Rule.update(payload, { where: { id: { [Op.in]: ruleIds } }, transaction: tx });

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rules_bulk_updated', {
        rule_count: count,
        updated_fields: Object.keys(payload).filter(k => !['updated_by', 'updated_at'].includes(k)),
        user_id: this.user.id,
      });

      const result = {
        success: true,
        updated_count: count,
        requested_count: ruleIds.length,
        updated_fields: Object.keys(payload).filter(k => !['updated_by', 'updated_at'].includes(k)),
        timestamp: new Date(),
      };

      logger.info('Bulk update rules completed', { ...result, user_id: this.user.id, username: user.username });
      return result;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to bulk update rules', {
        error: error.message,
        rule_ids: ruleIds,
        update_data: updateData,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to bulk update rules: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { ruleIds, updateData, error_type: 'bulk_update_failure' },
      });
      throw error;
    }
  }

  /**
   * Reorder rules within an interface using evenly spaced sequences.
   * @param {string} interfaceName - e.g. 'lan'
   * @param {number[]} ruleOrder - Ordered list of rule IDs
   * @returns {Promise<{success:boolean,interface:string,reordered_count:number,timestamp:Date}>}
   */
  async reorderRules(interfaceName, ruleOrder) {
    const tx = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('update_rules');

      if (!['wan', 'lan', 'opt1', 'opt2', 'opt3', 'lo0'].includes(interfaceName)) {
        throw new Error('Valid interface name is required');
      }
      if (!Array.isArray(ruleOrder) || ruleOrder.length === 0) {
        throw new Error('Rule order array is required');
      }

      const existing = await Rule.findAll({
        where: { interface: interfaceName },
        order: [['sequence', 'ASC']],
        transaction: tx,
      });

      for (const id of ruleOrder) {
        if (!existing.find(r => r.id === id)) {
          throw new Error(`Rule ${id} not found or doesn't belong to interface ${interfaceName}`);
        }
      }

      const base = 100;
      const step = 10;
      let updatedCount = 0;

      for (let i = 0; i < ruleOrder.length; i++) {
        const id = ruleOrder[i];
        const sequence = base + i * step;
        // eslint-disable-next-line no-await-in-loop
        await Rule.update(
          { sequence, updated_by: this.user.id, updated_at: new Date() },
          { where: { id }, transaction: tx }
        );
        updatedCount++;
      }

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rules_reordered', {
        interface: interfaceName,
        rule_count: updatedCount,
        user_id: this.user.id,
      });

      const result = { success: true, interface: interfaceName, reordered_count: updatedCount, timestamp: new Date() };
      logger.info('Rules reordered', { ...result, user_id: this.user.id, username: user.username });
      return result;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to reorder rules', { error: error.message, interface: interfaceName, rule_order: ruleOrder, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to reorder rules: ${error.message}`,
        severity: 'medium',
        source: 'rules_service',
        metadata: { interfaceName, ruleOrder, error_type: 'reorder_failure' },
      });
      throw error;
    }
  }

  /**
   * Compute basic statistics for rules and cache them.
   * @returns {Promise<Object>}
   */
  async getRuleStatistics() {
    try {
      const key = 'rule_statistics';
      const cached = await this.safeGetCache(key);
      if (cached) {
        logger.info('Returning cached rule statistics', { cache_key: key });
        return cached;
      }

      const [total, enabled, byIf, byAction, byProto, synced] = await Promise.all([
        Rule.count(),
        Rule.count({ where: { enabled: true } }),
        Rule.findAll({ attributes: ['interface', [Rule.sequelize.fn('COUNT', '*'), 'count']], group: ['interface'], raw: true }),
        Rule.findAll({ attributes: ['action', [Rule.sequelize.fn('COUNT', '*'), 'count']], group: ['action'], raw: true }),
        Rule.findAll({ attributes: ['protocol', [Rule.sequelize.fn('COUNT', '*'), 'count']], group: ['protocol'], raw: true }),
        Rule.count({ where: { sync_to_opnsense: true } }),
      ]);

      const stats = {
        total,
        enabled,
        disabled: total - enabled,
        synced_to_opnsense: synced,
        by_interface: {},
        by_action: {},
        by_protocol: {},
        security_insights: {
          block_rules: 0,
          allow_all_rules: 0,
          high_priority_rules: 0,
        },
        timestamp: new Date(),
      };

      byIf.forEach(x => { stats.by_interface[x.interface] = parseInt(x.count, 10); });
      byAction.forEach(x => {
        const c = parseInt(x.count, 10);
        stats.by_action[x.action] = c;
        if (x.action === 'block' || x.action === 'reject') stats.security_insights.block_rules += c;
      });
      byProto.forEach(x => { stats.by_protocol[x.protocol] = parseInt(x.count, 10); });

      const [allowAll, highPrio] = await Promise.all([
        Rule.count({ where: { action: 'pass', source: 'any', destination: 'any', enabled: true } }),
        Rule.count({ where: { priority: { [Op.gte]: 800 }, enabled: true } }),
      ]);
      stats.security_insights.allow_all_rules = allowAll;
      stats.security_insights.high_priority_rules = highPrio;

      await this.safeSetCache(key, stats, this.cacheTimeout);
      return stats;
    } catch (error) {
      logger.error('Failed to get rule statistics', { error: error.message, user_id: this.user?.id });
      throw error;
    }
  }

  /**
   * Basic configuration linting for a rule, yielding warnings/suggestions.
   * @param {Object} rule
   * @returns {Promise<{valid:boolean,errors:string[],warnings:string[],suggestions:string[],security_score:number}>}
   */
  async validateRuleConfiguration(rule) {
    try {
      const out = { valid: true, errors: [], warnings: [], suggestions: [], security_score: 100 };

      if (rule.action === 'pass' && rule.source === 'any' && rule.destination === 'any') {
        out.warnings.push('Very permissive rule - allows all traffic');
        out.security_score -= 30;
      }
      if (rule.action === 'block' && !rule.log) {
        out.suggestions.push('Consider enabling logging for block rules for security monitoring');
        out.security_score -= 10;
      }
      if (rule.interface === 'wan' && rule.action === 'pass' && rule.destination_port === 'any') {
        out.warnings.push('WAN rule allowing all ports - potential security risk');
        out.security_score -= 20;
      }
      if (rule.protocol === 'any' && rule.source_port === 'any' && rule.destination_port === 'any') {
        out.suggestions.push('Consider specifying protocol and ports for better performance');
      }
      if (!rule.description || rule.description.length < 10) {
        out.suggestions.push('Add a more detailed description for better documentation');
      }
      if (rule.priority > 900) {
        out.warnings.push('Very high priority - ensure this is intentional');
      }
      const sensitive = ['22', '23', '3389', '5900'];
      if (rule.action === 'pass' && rule.interface === 'wan' &&
          typeof rule.destination_port === 'string' &&
          sensitive.some(p => rule.destination_port.includes(p))) {
        out.warnings.push('Rule allows access to common administrative ports from WAN');
        out.security_score -= 25;
      }

      out.valid = out.errors.length === 0;
      out.security_score = Math.max(0, out.security_score);
      return out;
    } catch (error) {
      logger.error('Failed to validate rule configuration', { error: error.message, rule_id: rule?.id, user_id: this.user?.id });
      throw error;
    }
  }

  /**
   * Export rules to a JSON-friendly structure.
   * @param {number[]|null} ruleIds
   * @returns {Promise<Object>}
   */
  async exportRules(ruleIds = null) {
    try {
      const user = await this.validateUserPermissions('view_rules');
      const where = ruleIds ? { id: { [Op.in]: ruleIds } } : {};

      const rules = await Rule.findAll({
        where,
        include: [{ model: User, as: 'createdBy', attributes: ['username'], required: false }],
        order: [['interface', 'ASC'], ['sequence', 'ASC']],
      });

      const exportData = {
        export_metadata: {
          timestamp: new Date(),
          exported_by: user.username,
          total_rules: rules.length,
          version: '1.0',
          export_type: 'firewall_rules',
        },
        rules: rules.map(r => ({
          description: r.description,
          interface: r.interface,
          action: r.action,
          protocol: r.protocol,
          source: r.source,
          destination: r.destination,
          source_port: r.source_port,
          destination_port: r.destination_port,
          priority: r.priority,
          sequence: r.sequence,
          enabled: r.enabled,
          created_by: r.createdBy?.username,
          created_at: r.created_at,
        })),
      };

      logger.info('Rules exported', { exported_count: rules.length, user_id: this.user.id, username: user.username });
      return exportData;
    } catch (error) {
      logger.error('Failed to export rules', { error: error.message, rule_ids: ruleIds, user_id: this.user?.id });
      throw error;
    }
  }

  /**
   * Import rules from a JSON object. Can update on conflict when overwrite=true.
   * @param {Object} importData - { rules: Array<rule> }
   * @param {{overwrite?:boolean}} options
   * @returns {Promise<{total:number,imported:number,skipped:number,errors:Object[],imported_rules:Object[],timestamp:Date}>}
   */
  async importRules(importData, options = {}) {
    const tx = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('create_rules');

      if (!importData || !Array.isArray(importData.rules)) throw new Error('Invalid import data format');
      if (importData.rules.length > 100) throw new Error('Cannot import more than 100 rules at once');

      const results = { total: importData.rules.length, imported: 0, skipped: 0, errors: [], imported_rules: [], timestamp: new Date() };

      for (const ruleData of importData.rules) {
        try {
          const existing = await Rule.findOne({
            where: { description: ruleData.description, interface: ruleData.interface },
            transaction: tx,
          });

          if (existing && !options.overwrite) {
            results.skipped++;
            continue;
          }

          this.validateRuleData(ruleData);

          // sequence
          let sequence = ruleData.sequence;
          if (!sequence) {
            const last = await Rule.findOne({
              where: { interface: ruleData.interface },
              order: [['sequence', 'DESC']],
              transaction: tx,
            });
            sequence = last ? last.sequence + 10 : 100;
          }

          let rule;
          if (existing && options.overwrite) {
            rule = await existing.update(
              { ...ruleData, sequence, updated_by: this.user.id, updated_at: new Date() },
              { transaction: tx }
            );
          } else {
            rule = await Rule.create(
              {
                ...ruleData,
                sequence,
                created_by: this.user.id,
                updated_by: this.user.id,
                created_at: new Date(),
                updated_at: new Date(),
              },
              { transaction: tx }
            );
          }

          results.imported++;
          results.imported_rules.push({
            id: rule.id,
            description: rule.description,
            interface: rule.interface,
            action: rule.action,
            import_action: existing ? 'updated' : 'created',
          });
        } catch (e) {
          results.errors.push({ rule_description: ruleData.description, interface: ruleData.interface, error: e.message });
        }
      }

      await tx.commit();

      await this.invalidateCachePattern('rules_*');
      metricsHelpers.recordConfigurationChange('rules_imported', {
        imported_count: results.imported,
        skipped_count: results.skipped,
        error_count: results.errors.length,
        user_id: this.user.id,
      });

      logger.info('Rules import completed', { ...results, user_id: this.user.id, username: user.username });
      return results;
    } catch (error) {
      await tx.rollback();
      logger.error('Failed to import rules', { error: error.message, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'system_error',
        message: `Failed to import rules: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { error_type: 'import_failure' },
      });
      throw error;
    }
  }
}

module.exports = RulesService;