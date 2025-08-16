const Rule = require('../models/Rule');
const User = require('../models/User');
const AlertService = require('./AlertService');
const OpnsenseService = require('./OpnsenseService');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');
const { Op } = require('sequelize');

class RulesService {
  constructor(user = null) {
    this.user = user;
    this.alertService = new AlertService(user);
    this.opnsenseService = new OpnsenseService(user);
    this.cacheTimeout = process.env.RULES_CACHE_TIMEOUT || 60;
    this.maxRetries = process.env.MAX_RETRIES || 3;
  }

  /**
   * Validate rule data
   * @param {Object} ruleData - Rule data to validate
   * @private
   */
  validateRuleData(ruleData) {
    const requiredFields = ['description', 'interface', 'action'];
    const validActions = ['pass', 'block', 'reject'];
    const validInterfaces = ['wan', 'lan', 'opt1', 'opt2', 'opt3', 'lo0'];
    const validProtocols = ['tcp', 'udp', 'icmp', 'any'];

    for (const field of requiredFields) {
      if (!ruleData[field]) {
        throw new Error(`${field} is required`);
      }
    }

    if (!validActions.includes(ruleData.action)) {
      throw new Error(`Invalid action. Must be one of: ${validActions.join(', ')}`);
    }

    if (!validInterfaces.includes(ruleData.interface)) {
      throw new Error(`Invalid interface. Must be one of: ${validInterfaces.join(', ')}`);
    }

    if (ruleData.description.length < 3 || ruleData.description.length > 255) {
      throw new Error('Description must be between 3 and 255 characters');
    }

    if (ruleData.protocol && !validProtocols.includes(ruleData.protocol)) {
      throw new Error(`Invalid protocol. Must be one of: ${validProtocols.join(', ')}`);
    }

    if (ruleData.source && ruleData.source !== 'any' && !/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(ruleData.source)) {
      throw new Error('Invalid source IP/CIDR format');
    }

    if (ruleData.destination && ruleData.destination !== 'any' && !/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(ruleData.destination)) {
      throw new Error('Invalid destination IP/CIDR format');
    }

    if (ruleData.source_port && ruleData.source_port !== 'any') {
      if (!/^\d+(-\d+)?$/.test(ruleData.source_port)) {
        throw new Error('Invalid source port format (use single port or range like 80-90)');
      }
      const portRange = ruleData.source_port.split('-');
      const startPort = parseInt(portRange[0]);
      const endPort = portRange[1] ? parseInt(portRange[1]) : startPort;
      
      if (startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 || startPort > endPort) {
        throw new Error('Invalid source port range (must be 1-65535)');
      }
    }

    if (ruleData.destination_port && ruleData.destination_port !== 'any') {
      if (!/^\d+(-\d+)?$/.test(ruleData.destination_port)) {
        throw new Error('Invalid destination port format (use single port or range like 80-90)');
      }
      const portRange = ruleData.destination_port.split('-');
      const startPort = parseInt(portRange[0]);
      const endPort = portRange[1] ? parseInt(portRange[1]) : startPort;
      
      if (startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 || startPort > endPort) {
        throw new Error('Invalid destination port range (must be 1-65535)');
      }
    }

    if (ruleData.priority !== undefined) {
      const priority = parseInt(ruleData.priority);
      if (isNaN(priority) || priority < 0 || priority > 1000) {
        throw new Error('Priority must be a number between 0 and 1000');
      }
    }

    // Validate rule sequence number
    if (ruleData.sequence !== undefined) {
      const sequence = parseInt(ruleData.sequence);
      if (isNaN(sequence) || sequence < 1) {
        throw new Error('Sequence must be a positive integer');
      }
    }
  }

  /**
   * Validate user permissions
   * @param {string} action - Action to validate
   * @private
   */
  async validateUserPermissions(action) {
    if (!this.user) {
      throw new Error('User authentication required');
    }

    const user = await User.findByPk(this.user.id);
    if (!user) {
      throw new Error('User not found');
    }

    if (!user.is_active) {
      throw new Error('User account is disabled');
    }

    if (user.isAccountLocked()) {
      throw new Error('User account is locked');
    }

    if (!user.hasPermission(action)) {
      throw new Error(`User does not have permission to ${action}`);
    }

    return user;
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
   * Create a new firewall rule with transaction support
   * @param {Object} ruleData - Rule data
   * @returns {Object} Created rule
   */
  async createRule(ruleData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_rules');

      // Validate rule data
      this.validateRuleData(ruleData);

      // Check for duplicate rule descriptions on same interface
      const existingRule = await Rule.findOne({
        where: { 
          description: ruleData.description,
          interface: ruleData.interface
        },
        transaction
      });

      if (existingRule) {
        throw new Error(`Rule with description '${ruleData.description}' already exists on interface '${ruleData.interface}'`);
      }

      // Auto-assign sequence number if not provided
      let sequence = ruleData.sequence;
      if (!sequence) {
        const lastRule = await Rule.findOne({
          where: { interface: ruleData.interface },
          order: [['sequence', 'DESC']],
          transaction
        });
        sequence = lastRule ? lastRule.sequence + 10 : 100;
      }

      const rule = await Rule.create({
        ...ruleData,
        sequence: sequence,
        created_by: this.user.id,
        updated_by: this.user.id,
        created_at: new Date(),
        updated_at: new Date(),
        priority: ruleData.priority || 100,
        enabled: ruleData.enabled !== undefined ? ruleData.enabled : true,
        protocol: ruleData.protocol || 'any',
        source: ruleData.source || 'any',
        destination: ruleData.destination || 'any',
        source_port: ruleData.source_port || 'any',
        destination_port: ruleData.destination_port || 'any'
      }, { transaction });

      // Synchronize with OPNsense if applicable
      let opnsenseRuleId = null;
      if (ruleData.sync_to_opnsense) {
        try {
          const opnsenseRule = await this.opnsenseService.createFirewallRule({
            description: ruleData.description,
            enabled: ruleData.enabled ? 1 : 0,
            interface: ruleData.interface,
            action: ruleData.action,
            protocol: ruleData.protocol || 'any',
            source: ruleData.source || 'any',
            destination: ruleData.destination || 'any',
            source_port: ruleData.source_port || 'any',
            destination_port: ruleData.destination_port || 'any',
            sequence: sequence
          });
          
          opnsenseRuleId = opnsenseRule.uuid;
          await rule.update({ opnsense_rule_id: opnsenseRuleId }, { transaction });
        } catch (opnsenseError) {
          logger.warn('Failed to sync rule to OPNsense', {
            rule_id: rule.id,
            error: opnsenseError.message
          });
          // Don't fail the entire operation, just log the warning
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rule_created', {
        interface: ruleData.interface,
        action: ruleData.action,
        protocol: ruleData.protocol || 'any',
        synced_to_opnsense: !!opnsenseRuleId,
        user_id: this.user.id
      });

      logger.info('Firewall rule created successfully', {
        rule_id: rule.id,
        user_id: this.user.id,
        username: user.username,
        description: rule.description,
        interface: rule.interface,
        action: rule.action,
        sequence: rule.sequence,
        synced_to_opnsense: !!opnsenseRuleId
      });

      return rule;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to create rule', {
        error: error.message,
        ruleData,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to create firewall rule: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { 
          ruleData,
          error_type: 'creation_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Get firewall rules with filtering and pagination
   * @param {Object} filters - Filter criteria
   * @param {Object} pagination - Pagination options
   * @returns {Object} Paginated rules
   */
  async getRules(filters = {}, pagination = { page: 1, limit: 20 }) {
    try {
      // Validate and sanitize inputs
      const page = Math.max(1, parseInt(pagination.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(pagination.limit) || 20));

      const cacheKey = `rules_${JSON.stringify(filters)}_${page}_${limit}`;
      const cachedRules = await this.safeGetCache(cacheKey);

      if (cachedRules) {
        logger.info('Returning cached rules', { cache_key: cacheKey });
        return cachedRules;
      }

      const whereClause = {};

      // Apply filters with validation
      if (filters.description && typeof filters.description === 'string') {
        whereClause.description = { [Op.iLike]: `%${filters.description.trim()}%` };
      }
      
      if (filters.interface && ['wan', 'lan', 'opt1', 'opt2', 'opt3', 'lo0'].includes(filters.interface)) {
        whereClause.interface = filters.interface;
      }
      
      if (filters.action && ['pass', 'block', 'reject'].includes(filters.action)) {
        whereClause.action = filters.action;
      }
      
      if (filters.enabled !== undefined && typeof filters.enabled === 'boolean') {
        whereClause.enabled = filters.enabled;
      }
      
      if (filters.created_by && typeof filters.created_by === 'number') {
        whereClause.created_by = filters.created_by;
      }

      if (filters.protocol && ['tcp', 'udp', 'icmp', 'any'].includes(filters.protocol)) {
        whereClause.protocol = filters.protocol;
      }

      if (filters.priority !== undefined) {
        const priority = parseInt(filters.priority);
        if (!isNaN(priority) && priority >= 0 && priority <= 1000) {
          whereClause.priority = priority;
        }
      }

      if (filters.source && typeof filters.source === 'string') {
        whereClause.source = { [Op.iLike]: `%${filters.source.trim()}%` };
      }

      if (filters.destination && typeof filters.destination === 'string') {
        whereClause.destination = { [Op.iLike]: `%${filters.destination.trim()}%` };
      }

      if (filters.source_port && typeof filters.source_port === 'string') {
        whereClause.source_port = { [Op.iLike]: `%${filters.source_port.trim()}%` };
      }

      if (filters.destination_port && typeof filters.destination_port === 'string') {
        whereClause.destination_port = { [Op.iLike]: `%${filters.destination_port.trim()}%` };
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

      const { count, rows } = await Rule.findAndCountAll({
        where: whereClause,
        limit: limit,
        offset: (page - 1) * limit,
        order: [
          ['interface', 'ASC'],
          ['sequence', 'ASC'],
          ['created_at', 'DESC']
        ],
        include: [
          {
            model: User,
            as: 'createdBy',
            attributes: ['id', 'username', 'email', 'first_name', 'last_name'],
            required: false,
          },
          {
            model: User,
            as: 'updatedBy',
            attributes: ['id', 'username', 'email', 'first_name', 'last_name'],
            required: false,
          },
        ],
      });

      const result = {
        data: rows,
        pagination: {
          total: count,
          page: page,
          limit: limit,
          total_pages: Math.ceil(count / limit),
        },
        summary: {
          by_interface: {},
          by_action: {},
          enabled_count: 0,
          disabled_count: 0
        }
      };

      // Generate summary statistics
      rows.forEach(rule => {
        // Count by interface
        result.summary.by_interface[rule.interface] = 
          (result.summary.by_interface[rule.interface] || 0) + 1;
        
        // Count by action
        result.summary.by_action[rule.action] = 
          (result.summary.by_action[rule.action] || 0) + 1;
        
        // Count enabled/disabled
        if (rule.enabled) {
          result.summary.enabled_count++;
        } else {
          result.summary.disabled_count++;
        }
      });

      await this.safeSetCache(cacheKey, result, this.cacheTimeout);

      logger.info('Rules retrieved and cached', {
        cache_key: cacheKey,
        total_count: count,
        page: page
      });

      return result;
    } catch (error) {
      logger.error('Failed to get rules', {
        error: error.message,
        filters,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to retrieve firewall rules: ${error.message}`,
        severity: 'medium',
        source: 'rules_service',
        metadata: {
          filters,
          error_type: 'retrieval_failure'
        }
      });
      throw error;
    }
  }

  /**
   * Update an existing firewall rule with transaction support
   * @param {number} ruleId - Rule ID
   * @param {Object} ruleData - Updated rule data
   * @returns {Object} Updated rule
   */
  async updateRule(ruleId, ruleData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!ruleId || typeof ruleId !== 'number') {
        throw new Error('Valid rule ID is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('update_rules');

      // Validate rule data
      this.validateRuleData(ruleData);

      const rule = await Rule.findByPk(ruleId, { transaction });
      if (!rule) {
        throw new Error('Rule not found');
      }

      // Check for duplicate descriptions (excluding current rule)
      if (ruleData.description && ruleData.description !== rule.description) {
        const existingRule = await Rule.findOne({
          where: { 
            description: ruleData.description,
            interface: ruleData.interface || rule.interface,
            id: { [Op.ne]: ruleId }
          },
          transaction
        });

        if (existingRule) {
          throw new Error(`Rule with description '${ruleData.description}' already exists on interface '${ruleData.interface || rule.interface}'`);
        }
      }

      const updatedRule = await rule.update({
        ...ruleData,
        updated_by: this.user.id,
        updated_at: new Date(),
      }, { transaction });

      // Synchronize with OPNsense if applicable
      if (ruleData.sync_to_opnsense && rule.opnsense_rule_id) {
        try {
          await this.opnsenseService.updateFirewallRule(rule.opnsense_rule_id, {
            description: ruleData.description || rule.description,
            enabled: ruleData.enabled !== undefined ? (ruleData.enabled ? 1 : 0) : (rule.enabled ? 1 : 0),
            interface: ruleData.interface || rule.interface,
            action: ruleData.action || rule.action,
            protocol: ruleData.protocol || rule.protocol || 'any',
            source: ruleData.source || rule.source || 'any',
            destination: ruleData.destination || rule.destination || 'any',
            source_port: ruleData.source_port || rule.source_port || 'any',
            destination_port: ruleData.destination_port || rule.destination_port || 'any',
            sequence: ruleData.sequence || rule.sequence
          });
        } catch (opnsenseError) {
          logger.warn('Failed to sync rule update to OPNsense', {
            rule_id: ruleId,
            opnsense_rule_id: rule.opnsense_rule_id,
            error: opnsenseError.message
          });
          // Don't fail the entire operation, just log the warning
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rule_updated', {
        rule_id: ruleId,
        interface: updatedRule.interface,
        action: updatedRule.action,
        user_id: this.user.id
      });

      logger.info('Firewall rule updated successfully', {
        rule_id: ruleId,
        user_id: this.user.id,
        username: user.username,
        description: updatedRule.description,
      });

      return updatedRule;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to update rule', {
        error: error.message,
        rule_id: ruleId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to update firewall rule: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { 
          ruleId, 
          ruleData,
          error_type: 'update_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Delete a firewall rule with transaction support
   * @param {number} ruleId - Rule ID
   * @returns {boolean} Success status
   */
  async deleteRule(ruleId) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!ruleId || typeof ruleId !== 'number') {
        throw new Error('Valid rule ID is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('delete_rules');

      const rule = await Rule.findByPk(ruleId, { transaction });
      if (!rule) {
        throw new Error('Rule not found');
      }

      // Delete from OPNsense if synchronized
      if (rule.opnsense_rule_id) {
        try {
          await this.opnsenseService.deleteFirewallRule(rule.opnsense_rule_id);
        } catch (opnsenseError) {
          logger.warn('Failed to delete rule from OPNsense', {
            rule_id: ruleId,
            opnsense_rule_id: rule.opnsense_rule_id,
            error: opnsenseError.message
          });
          // Continue with local deletion even if OPNsense deletion fails
        }
      }

      await rule.destroy({ transaction });

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rule_deleted', {
        rule_id: ruleId,
        interface: rule.interface,
        action: rule.action,
        user_id: this.user.id
      });

      logger.info('Firewall rule deleted successfully', {
        rule_id: ruleId,
        user_id: this.user.id,
        username: user.username,
        rule_description: rule.description
      });

      return true;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to delete rule', {
        error: error.message,
        rule_id: ruleId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to delete firewall rule: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { 
          ruleId,
          error_type: 'deletion_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Synchronize all rules with OPNsense with improved error handling
   * @returns {Object} Synchronization result
   */
  async syncRulesWithOpnsense() {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('sync_rules');

      const rules = await Rule.findAll({ 
        where: { sync_to_opnsense: true },
        order: [['interface', 'ASC'], ['sequence', 'ASC']],
        transaction
      });

      let syncCount = 0;
      let errorCount = 0;
      const errors = [];

      for (const rule of rules) {
        try {
          if (rule.opnsense_rule_id) {
            // Update existing rule
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
              sequence: rule.sequence
            });
          } else {
            // Create new rule
            const opnsenseRule = await this.opnsenseService.createFirewallRule({
              description: rule.description,
              enabled: rule.enabled ? 1 : 0,
              interface: rule.interface,
              action: rule.action,
              protocol: rule.protocol || 'any',
              source: rule.source || 'any',
              destination: rule.destination || 'any',
              source_port: rule.source_port || 'any',
              destination_port: rule.destination_port || 'any',
              sequence: rule.sequence
            });
            await rule.update({ opnsense_rule_id: opnsenseRule.uuid }, { transaction });
          }
          syncCount++;
        } catch (error) {
          errorCount++;
          const errorInfo = {
            rule_id: rule.id,
            rule_description: rule.description,
            error: error.message
          };
          errors.push(errorInfo);
          
          logger.error('Failed to sync rule with OPNsense', {
            ...errorInfo,
            user_id: this.user.id,
          });
          
          await this.alertService.createSystemAlert({
            type: 'configuration_error',
            message: `Failed to sync rule ${rule.description} with OPNsense: ${error.message}`,
            severity: 'high',
            source: 'rules_service',
            metadata: { 
              ruleId: rule.id,
              error_type: 'sync_failure'
            },
          });
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rules_synced', { 
        sync_count: syncCount,
        error_count: errorCount,
        user_id: this.user.id
      });

      const result = {
        success: errorCount === 0,
        total_rules: rules.length,
        synced_count: syncCount,
        error_count: errorCount,
        errors: errors,
        timestamp: new Date()
      };

      logger.info('Rules synchronization completed', {
        ...result,
        user_id: this.user.id,
        username: user.username,
      });

      return result;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to sync rules with OPNsense', {
        error: error.message,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to sync rules with OPNsense: ${error.message}`,
        severity: 'critical',
        source: 'rules_service',
        metadata: {
          error_type: 'sync_operation_failure'
        }
      });
      throw error;
    }
  }

  /**
   * Get rule by ID with caching
   * @param {number} ruleId - Rule ID
   * @returns {Object} Rule object
   */
  async getRuleById(ruleId) {
    try {
      // Validate input
      if (!ruleId || typeof ruleId !== 'number') {
        throw new Error('Valid rule ID is required');
      }

      const cacheKey = `rule_${ruleId}`;
      const cachedRule = await this.safeGetCache(cacheKey);

      if (cachedRule) {
        logger.info('Returning cached rule', { rule_id: ruleId });
        return cachedRule;
      }

      const rule = await Rule.findByPk(ruleId, {
        include: [
          {
            model: User,
            as: 'createdBy',
            attributes: ['id', 'username', 'email', 'first_name', 'last_name'],
            required: false,
          },
          {
            model: User,
            as: 'updatedBy',
            attributes: ['id', 'username', 'email', 'first_name', 'last_name'],
            required: false,
          },
        ],
      });

      if (!rule) {
        throw new Error('Rule not found');
      }

      await this.safeSetCache(cacheKey, rule, this.cacheTimeout);

      return rule;
    } catch (error) {
      logger.error('Failed to get rule by ID', {
        error: error.message,
        rule_id: ruleId,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Clone/duplicate an existing rule
   * @param {number} ruleId - Rule ID to clone
   * @param {Object} overrides - Properties to override in the cloned rule
   * @returns {Object} Cloned rule
   */
  async cloneRule(ruleId, overrides = {}) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_rules');

      // Get original rule
      const originalRule = await Rule.findByPk(ruleId, { transaction });
      if (!originalRule) {
        throw new Error('Rule to clone not found');
      }

      // Generate unique description for cloned rule
      let cloneDescription = overrides.description || `${originalRule.description} (Copy)`;
      let counter = 1;
      
      while (await Rule.findOne({ 
        where: { 
          description: cloneDescription,
          interface: overrides.interface || originalRule.interface 
        }, 
        transaction 
      })) {
        cloneDescription = overrides.description ? 
          `${overrides.description} (${counter})` : 
          `${originalRule.description} (Copy ${counter})`;
        counter++;
      }

      // Auto-assign sequence number
      let sequence = overrides.sequence;
      if (!sequence) {
        const lastRule = await Rule.findOne({
          where: { interface: overrides.interface || originalRule.interface },
          order: [['sequence', 'DESC']],
          transaction
        });
        sequence = lastRule ? lastRule.sequence + 10 : 100;
      }

      // Create cloned rule
      const clonedRuleData = {
        description: cloneDescription,
        interface: originalRule.interface,
        action: originalRule.action,
        protocol: originalRule.protocol,
        source: originalRule.source,
        destination: originalRule.destination,
        source_port: originalRule.source_port,
        destination_port: originalRule.destination_port,
        priority: originalRule.priority,
        enabled: overrides.enabled !== undefined ? overrides.enabled : false, // Disable by default
        sync_to_opnsense: overrides.sync_to_opnsense !== undefined ? overrides.sync_to_opnsense : false, // Don't sync by default
        sequence: sequence,
        ...overrides
      };

      // Validate cloned rule data
      this.validateRuleData(clonedRuleData);

      const clonedRule = await Rule.create({
        ...clonedRuleData,
        created_by: this.user.id,
        updated_by: this.user.id,
        created_at: new Date(),
        updated_at: new Date(),
      }, { transaction });

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rule_cloned', {
        original_rule_id: ruleId,
        cloned_rule_id: clonedRule.id,
        user_id: this.user.id
      });

      logger.info('Rule cloned successfully', {
        original_rule_id: ruleId,
        cloned_rule_id: clonedRule.id,
        user_id: this.user.id,
        username: user.username,
        cloned_description: cloneDescription
      });

      return clonedRule;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to clone rule', {
        error: error.message,
        rule_id: ruleId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to clone rule: ${error.message}`,
        severity: 'medium',
        source: 'rules_service',
        metadata: { 
          ruleId,
          overrides,
          error_type: 'clone_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Bulk update rules
   * @param {Array} ruleIds - Array of rule IDs
   * @param {Object} updateData - Data to update
   * @returns {Object} Bulk update result
   */
  async bulkUpdateRules(ruleIds, updateData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('update_rules');

      // Validate inputs
      if (!Array.isArray(ruleIds) || ruleIds.length === 0) {
        throw new Error('Rule IDs array is required');
      }

      if (ruleIds.length > 50) {
        throw new Error('Cannot update more than 50 rules at once');
      }

      // Validate update data
      const allowedFields = ['enabled', 'priority', 'action', 'protocol'];
      const validatedUpdateData = {};

      Object.keys(updateData).forEach(key => {
        if (allowedFields.includes(key)) {
          // Additional validation for specific fields
          if (key === 'action' && !['pass', 'block', 'reject'].includes(updateData[key])) {
            throw new Error(`Invalid action: ${updateData[key]}`);
          }
          if (key === 'protocol' && !['tcp', 'udp', 'icmp', 'any'].includes(updateData[key])) {
            throw new Error(`Invalid protocol: ${updateData[key]}`);
          }
          if (key === 'priority') {
            const priority = parseInt(updateData[key]);
            if (isNaN(priority) || priority < 0 || priority > 1000) {
              throw new Error('Priority must be between 0 and 1000');
            }
            validatedUpdateData[key] = priority;
          } else {
            validatedUpdateData[key] = updateData[key];
          }
        }
      });

      if (Object.keys(validatedUpdateData).length === 0) {
        throw new Error('No valid fields to update');
      }

      // Add updated metadata
      validatedUpdateData.updated_by = this.user.id;
      validatedUpdateData.updated_at = new Date();

      // Perform bulk update
      const [updatedCount] = await Rule.update(validatedUpdateData, {
        where: {
          id: { [Op.in]: ruleIds }
        },
        transaction
      });

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rules_bulk_updated', {
        rule_count: updatedCount,
        updated_fields: Object.keys(validatedUpdateData),
        user_id: this.user.id
      });

      const result = {
        success: true,
        updated_count: updatedCount,
        requested_count: ruleIds.length,
        updated_fields: Object.keys(validatedUpdateData).filter(key => key !== 'updated_by' && key !== 'updated_at'),
        timestamp: new Date()
      };

      logger.info('Bulk update rules completed', {
        ...result,
        user_id: this.user.id,
        username: user.username,
      });

      return result;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to bulk update rules', {
        error: error.message,
        rule_ids: ruleIds,
        update_data: updateData,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to bulk update rules: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { 
          ruleIds,
          updateData,
          error_type: 'bulk_update_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Reorder rules within an interface
   * @param {string} interfaceName - Interface name
   * @param {Array} ruleOrder - Array of rule IDs in desired order
   * @returns {Object} Reorder result
   */
  async reorderRules(interfaceName, ruleOrder) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('update_rules');

      // Validate inputs
      if (!interfaceName || !['wan', 'lan', 'opt1', 'opt2', 'opt3', 'lo0'].includes(interfaceName)) {
        throw new Error('Valid interface name is required');
      }

      if (!Array.isArray(ruleOrder) || ruleOrder.length === 0) {
        throw new Error('Rule order array is required');
      }

      // Get existing rules for the interface
      const existingRules = await Rule.findAll({
        where: { interface: interfaceName },
        order: [['sequence', 'ASC']],
        transaction
      });

      // Validate that all rules in the order exist and belong to the interface
      for (const ruleId of ruleOrder) {
        const rule = existingRules.find(r => r.id === ruleId);
        if (!rule) {
          throw new Error(`Rule ${ruleId} not found or doesn't belong to interface ${interfaceName}`);
        }
      }

      let updatedCount = 0;
      const baseSequence = 100;
      const sequenceIncrement = 10;

      // Update sequences based on new order
      for (let i = 0; i < ruleOrder.length; i++) {
        const ruleId = ruleOrder[i];
        const newSequence = baseSequence + (i * sequenceIncrement);
        
        await Rule.update(
          { 
            sequence: newSequence,
            updated_by: this.user.id,
            updated_at: new Date()
          },
          { 
            where: { id: ruleId },
            transaction
          }
        );
        updatedCount++;
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rules_reordered', {
        interface: interfaceName,
        rule_count: updatedCount,
        user_id: this.user.id
      });

      const result = {
        success: true,
        interface: interfaceName,
        reordered_count: updatedCount,
        timestamp: new Date()
      };

      logger.info('Rules reordered successfully', {
        ...result,
        user_id: this.user.id,
        username: user.username,
      });

      return result;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to reorder rules', {
        error: error.message,
        interface: interfaceName,
        rule_order: ruleOrder,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to reorder rules: ${error.message}`,
        severity: 'medium',
        source: 'rules_service',
        metadata: { 
          interfaceName,
          ruleOrder,
          error_type: 'reorder_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Get rule statistics
   * @returns {Object} Rule statistics
   */
  async getRuleStatistics() {
    try {
      const cacheKey = 'rule_statistics';
      const cachedStats = await this.safeGetCache(cacheKey);

      if (cachedStats) {
        logger.info('Returning cached rule statistics', { cache_key: cacheKey });
        return cachedStats;
      }

      // Get statistics from database
      const [
        totalCount, 
        enabledCount, 
        interfaceStats, 
        actionStats, 
        protocolStats,
        syncedCount
      ] = await Promise.all([
        Rule.count(),
        Rule.count({ where: { enabled: true } }),
        Rule.findAll({
          attributes: [
            'interface',
            [Rule.sequelize.fn('COUNT', '*'), 'count']
          ],
          group: ['interface'],
          raw: true
        }),
        Rule.findAll({
          attributes: [
            'action',
            [Rule.sequelize.fn('COUNT', '*'), 'count']
          ],
          group: ['action'],
          raw: true
        }),
        Rule.findAll({
          attributes: [
            'protocol',
            [Rule.sequelize.fn('COUNT', '*'), 'count']
          ],
          group: ['protocol'],
          raw: true
        }),
        Rule.count({ where: { sync_to_opnsense: true } })
      ]);

      const stats = {
        total: totalCount,
        enabled: enabledCount,
        disabled: totalCount - enabledCount,
        synced_to_opnsense: syncedCount,
        by_interface: {},
        by_action: {},
        by_protocol: {},
        security_insights: {
          block_rules: 0,
          allow_all_rules: 0,
          high_priority_rules: 0
        },
        timestamp: new Date()
      };

      // Format interface statistics
      interfaceStats.forEach(stat => {
        stats.by_interface[stat.interface] = parseInt(stat.count);
      });

      // Format action statistics
      actionStats.forEach(stat => {
        stats.by_action[stat.action] = parseInt(stat.count);
        if (stat.action === 'block' || stat.action === 'reject') {
          stats.security_insights.block_rules += parseInt(stat.count);
        }
      });

      // Format protocol statistics
      protocolStats.forEach(stat => {
        stats.by_protocol[stat.protocol] = parseInt(stat.count);
      });

      // Get additional security insights
      const [allowAllRules, highPriorityRules] = await Promise.all([
        Rule.count({
          where: {
            action: 'pass',
            source: 'any',
            destination: 'any',
            enabled: true
          }
        }),
        Rule.count({
          where: {
            priority: { [Op.gte]: 800 },
            enabled: true
          }
        })
      ]);

      stats.security_insights.allow_all_rules = allowAllRules;
      stats.security_insights.high_priority_rules = highPriorityRules;

      await this.safeSetCache(cacheKey, stats, this.cacheTimeout);

      return stats;
    } catch (error) {
      logger.error('Failed to get rule statistics', {
        error: error.message,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Validate rule configuration
   * @param {Object} rule - Rule object
   * @returns {Object} Validation result
   */
  async validateRuleConfiguration(rule) {
    try {
      const validationResult = {
        valid: true,
        errors: [],
        warnings: [],
        suggestions: [],
        security_score: 100
      };

      // Security validations
      if (rule.action === 'pass' && rule.source === 'any' && rule.destination === 'any') {
        validationResult.warnings.push('Very permissive rule - allows all traffic');
        validationResult.security_score -= 30;
      }

      if (rule.action === 'block' && !rule.log) {
        validationResult.suggestions.push('Consider enabling logging for block rules for security monitoring');
        validationResult.security_score -= 10;
      }

      if (rule.interface === 'wan' && rule.action === 'pass' && rule.destination_port === 'any') {
        validationResult.warnings.push('WAN rule allowing all ports - potential security risk');
        validationResult.security_score -= 20;
      }

      // Performance validations
      if (rule.protocol === 'any' && rule.source_port === 'any' && rule.destination_port === 'any') {
        validationResult.suggestions.push('Consider specifying protocol and ports for better performance');
      }

      // Best practice validations
      if (!rule.description || rule.description.length < 10) {
        validationResult.suggestions.push('Add a more detailed description for better documentation');
      }

      if (rule.priority > 900) {
        validationResult.warnings.push('Very high priority - ensure this is intentional');
      }

      // Check for common security ports
      const securityPorts = ['22', '23', '3389', '5900'];
      if (rule.action === 'pass' && rule.interface === 'wan' && 
          securityPorts.some(port => rule.destination_port.includes(port))) {
        validationResult.warnings.push('Rule allows access to common administrative ports from WAN');
        validationResult.security_score -= 25;
      }

      validationResult.valid = validationResult.errors.length === 0;
      validationResult.security_score = Math.max(0, validationResult.security_score);

      return validationResult;
    } catch (error) {
      logger.error('Failed to validate rule configuration', {
        error: error.message,
        rule_id: rule.id,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Export rules to JSON format
   * @param {Array} ruleIds - Rule IDs to export (optional, exports all if not provided)
   * @returns {Object} Export result
   */
  async exportRules(ruleIds = null) {
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('view_rules');

      const whereClause = ruleIds ? { id: { [Op.in]: ruleIds } } : {};

      const rules = await Rule.findAll({
        where: whereClause,
        include: [
          {
            model: User,
            as: 'createdBy',
            attributes: ['username'],
            required: false,
          },
        ],
        order: [['interface', 'ASC'], ['sequence', 'ASC']]
      });

      const exportData = {
        export_metadata: {
          timestamp: new Date(),
          exported_by: user.username,
          total_rules: rules.length,
          version: '1.0',
          export_type: 'firewall_rules'
        },
        rules: rules.map(rule => ({
          description: rule.description,
          interface: rule.interface,
          action: rule.action,
          protocol: rule.protocol,
          source: rule.source,
          destination: rule.destination,
          source_port: rule.source_port,
          destination_port: rule.destination_port,
          priority: rule.priority,
          sequence: rule.sequence,
          enabled: rule.enabled,
          created_by: rule.createdBy?.username,
          created_at: rule.created_at
        }))
      };

      logger.info('Rules exported successfully', {
        exported_count: rules.length,
        user_id: this.user.id,
        username: user.username,
      });

      return exportData;
    } catch (error) {
      logger.error('Failed to export rules', {
        error: error.message,
        rule_ids: ruleIds,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Import rules from JSON format
   * @param {Object} importData - Import data
   * @param {Object} options - Import options
   * @returns {Object} Import result
   */
  async importRules(importData, options = {}) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_rules');

      // Validate import data
      if (!importData || !importData.rules || !Array.isArray(importData.rules)) {
        throw new Error('Invalid import data format');
      }

      if (importData.rules.length > 100) {
        throw new Error('Cannot import more than 100 rules at once');
      }

      const results = {
        total: importData.rules.length,
        imported: 0,
        skipped: 0,
        errors: [],
        imported_rules: [],
        timestamp: new Date()
      };

      for (const ruleData of importData.rules) {
        try {
          // Skip if rule description already exists on interface (unless overwrite is enabled)
          const existingRule = await Rule.findOne({
            where: { 
              description: ruleData.description,
              interface: ruleData.interface 
            },
            transaction
          });

          if (existingRule && !options.overwrite) {
            results.skipped++;
            continue;
          }

          // Validate imported rule data
          this.validateRuleData(ruleData);

          // Auto-assign sequence if not provided
          let sequence = ruleData.sequence;
          if (!sequence) {
            const lastRule = await Rule.findOne({
              where: { interface: ruleData.interface },
              order: [['sequence', 'DESC']],
              transaction
            });
            sequence = lastRule ? lastRule.sequence + 10 : 100;
          }

          let rule;
          if (existingRule && options.overwrite) {
            // Update existing rule
            rule = await existingRule.update({
              ...ruleData,
              sequence: sequence,
              updated_by: this.user.id,
              updated_at: new Date()
            }, { transaction });
          } else {
            // Create new rule
            rule = await Rule.create({
              ...ruleData,
              sequence: sequence,
              created_by: this.user.id,
              updated_by: this.user.id,
              created_at: new Date(),
              updated_at: new Date(),
            }, { transaction });
          }

          results.imported++;
          results.imported_rules.push({
            id: rule.id,
            description: rule.description,
            interface: rule.interface,
            action: rule.action,
            import_action: existingRule ? 'updated' : 'created'
          });

        } catch (error) {
          results.errors.push({
            rule_description: ruleData.description,
            interface: ruleData.interface,
            error: error.message
          });
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('rules_imported', {
        imported_count: results.imported,
        skipped_count: results.skipped,
        error_count: results.errors.length,
        user_id: this.user.id
      });

      logger.info('Rules import completed', {
        ...results,
        user_id: this.user.id,
        username: user.username,
      });

      return results;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to import rules', {
        error: error.message,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to import rules: ${error.message}`,
        severity: 'high',
        source: 'rules_service',
        metadata: { 
          error_type: 'import_failure'
        },
      });
      throw error;
    }
  }
}

module.exports = RulesService;