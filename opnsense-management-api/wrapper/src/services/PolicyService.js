const Policy = require('../models/Policy');
const User = require('../models/User');
const AlertService = require('./AlertService');
const OpnsenseService = require('./OpnsenseService');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');
const { Op } = require('sequelize');

class PolicyService {
  constructor(user = null) {
    this.user = user;
    this.alertService = new AlertService(user);
    this.opnsenseService = new OpnsenseService(user);
    this.cacheTimeout = process.env.POLICY_CACHE_TIMEOUT || 60;
    this.maxRetries = process.env.MAX_RETRIES || 3;
  }

  /**
   * Validate policy data
   * @param {Object} policyData - Policy data to validate
   * @private
   */
  validatePolicyData(policyData) {
    const requiredFields = ['name', 'type'];
    const validTypes = ['firewall', 'vpn', 'nat', 'routing', 'qos'];

    for (const field of requiredFields) {
      if (!policyData[field]) {
        throw new Error(`${field} is required`);
      }
    }

    if (!validTypes.includes(policyData.type)) {
      throw new Error(`Invalid policy type. Must be one of: ${validTypes.join(', ')}`);
    }

    if (policyData.name.length < 3 || policyData.name.length > 100) {
      throw new Error('Policy name must be between 3 and 100 characters');
    }

    if (policyData.description && policyData.description.length > 500) {
      throw new Error('Description too long (max 500 characters)');
    }

    // Validate policy configuration based on type
    if (policyData.configuration && typeof policyData.configuration !== 'object') {
      throw new Error('Policy configuration must be a valid object');
    }

    if (policyData.priority !== undefined) {
      const priority = parseInt(policyData.priority);
      if (isNaN(priority) || priority < 0 || priority > 1000) {
        throw new Error('Priority must be a number between 0 and 1000');
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
   * Create a new policy with transaction support
   * @param {Object} policyData - Policy data
   * @returns {Object} Created policy
   */
  async createPolicy(policyData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_policies');

      // Validate policy data
      this.validatePolicyData(policyData);

      // Check for duplicate policy names
      const existingPolicy = await Policy.findOne({
        where: { name: policyData.name },
        transaction
      });

      if (existingPolicy) {
        throw new Error(`Policy with name '${policyData.name}' already exists`);
      }

      const policy = await Policy.create({
        ...policyData,
        created_by: this.user.id,
        updated_by: this.user.id,
        created_at: new Date(),
        updated_at: new Date(),
        priority: policyData.priority || 100
      }, { transaction });

      // Synchronize with OPNsense if applicable
      let opnsenseRuleId = null;
      if (policyData.sync_to_opnsense && policyData.type === 'firewall') {
        try {
          const opnsenseRule = await this.opnsenseService.createFirewallRule({
            description: policyData.name,
            enabled: policyData.enabled ? 1 : 0,
            interface: policyData.configuration?.interface || 'lan',
            action: policyData.configuration?.action || 'pass',
            source: policyData.configuration?.source || 'any',
            destination: policyData.configuration?.destination || 'any',
            ...policyData.configuration
          });
          
          opnsenseRuleId = opnsenseRule.uuid;
          await policy.update({ opnsense_rule_id: opnsenseRuleId }, { transaction });
        } catch (opnsenseError) {
          logger.warn('Failed to sync policy to OPNsense', {
            policy_id: policy.id,
            error: opnsenseError.message
          });
          // Don't fail the entire operation, just log the warning
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policy_created', {
        policy_type: policyData.type,
        synced_to_opnsense: !!opnsenseRuleId,
        user_id: this.user.id
      });

      logger.info('Policy created successfully', {
        policy_id: policy.id,
        user_id: this.user.id,
        username: user.username,
        name: policy.name,
        type: policy.type,
        synced_to_opnsense: !!opnsenseRuleId
      });

      return policy;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to create policy', {
        error: error.message,
        policyData,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to create policy: ${error.message}`,
        severity: 'high',
        source: 'policy_service',
        metadata: { 
          policyData,
          error_type: 'creation_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Get policies with filtering and pagination
   * @param {Object} filters - Filter criteria
   * @param {Object} pagination - Pagination options
   * @returns {Object} Paginated policies
   */
  async getPolicies(filters = {}, pagination = { page: 1, limit: 20 }) {
    try {
      // Validate and sanitize inputs
      const page = Math.max(1, parseInt(pagination.page) || 1);
      const limit = Math.min(100, Math.max(1, parseInt(pagination.limit) || 20));

      const cacheKey = `policies_${JSON.stringify(filters)}_${page}_${limit}`;
      const cachedPolicies = await this.safeGetCache(cacheKey);

      if (cachedPolicies) {
        logger.info('Returning cached policies', { cache_key: cacheKey });
        return cachedPolicies;
      }

      const whereClause = {};

      // Apply filters with validation
      if (filters.name && typeof filters.name === 'string') {
        whereClause.name = { [Op.iLike]: `%${filters.name.trim()}%` };
      }
      
      if (filters.type && ['firewall', 'vpn', 'nat', 'routing', 'qos'].includes(filters.type)) {
        whereClause.type = filters.type;
      }
      
      if (filters.enabled !== undefined && typeof filters.enabled === 'boolean') {
        whereClause.enabled = filters.enabled;
      }
      
      if (filters.created_by && typeof filters.created_by === 'number') {
        whereClause.created_by = filters.created_by;
      }

      if (filters.priority !== undefined) {
        const priority = parseInt(filters.priority);
        if (!isNaN(priority) && priority >= 0 && priority <= 1000) {
          whereClause.priority = priority;
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

      const { count, rows } = await Policy.findAndCountAll({
        where: whereClause,
        limit: limit,
        offset: (page - 1) * limit,
        order: [
          ['priority', 'DESC'],
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
      };

      await this.safeSetCache(cacheKey, result, this.cacheTimeout);

      logger.info('Policies retrieved and cached', {
        cache_key: cacheKey,
        total_count: count,
        page: page
      });

      return result;
    } catch (error) {
      logger.error('Failed to get policies', {
        error: error.message,
        filters,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to retrieve policies: ${error.message}`,
        severity: 'medium',
        source: 'policy_service',
        metadata: {
          filters,
          error_type: 'retrieval_failure'
        }
      });
      throw error;
    }
  }

  /**
   * Update an existing policy with transaction support
   * @param {number} policyId - Policy ID
   * @param {Object} policyData - Updated policy data
   * @returns {Object} Updated policy
   */
  async updatePolicy(policyId, policyData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!policyId || typeof policyId !== 'number') {
        throw new Error('Valid policy ID is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('update_policies');

      // Validate policy data
      this.validatePolicyData(policyData);

      const policy = await Policy.findByPk(policyId, { transaction });
      if (!policy) {
        throw new Error('Policy not found');
      }

      // Check for duplicate names (excluding current policy)
      if (policyData.name && policyData.name !== policy.name) {
        const existingPolicy = await Policy.findOne({
          where: { 
            name: policyData.name,
            id: { [Op.ne]: policyId }
          },
          transaction
        });

        if (existingPolicy) {
          throw new Error(`Policy with name '${policyData.name}' already exists`);
        }
      }

      const updatedPolicy = await policy.update({
        ...policyData,
        updated_by: this.user.id,
        updated_at: new Date(),
      }, { transaction });

      // Synchronize with OPNsense if applicable
      if (policyData.sync_to_opnsense && policy.opnsense_rule_id && policyData.type === 'firewall') {
        try {
          await this.opnsenseService.updateFirewallRule(policy.opnsense_rule_id, {
            description: policyData.name || policy.name,
            enabled: policyData.enabled !== undefined ? (policyData.enabled ? 1 : 0) : (policy.enabled ? 1 : 0),
            interface: policyData.configuration?.interface || policy.configuration?.interface || 'lan',
            action: policyData.configuration?.action || policy.configuration?.action || 'pass',
            source: policyData.configuration?.source || policy.configuration?.source || 'any',
            destination: policyData.configuration?.destination || policy.configuration?.destination || 'any',
            ...policyData.configuration
          });
        } catch (opnsenseError) {
          logger.warn('Failed to sync policy update to OPNsense', {
            policy_id: policyId,
            opnsense_rule_id: policy.opnsense_rule_id,
            error: opnsenseError.message
          });
          // Don't fail the entire operation, just log the warning
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policy_updated', {
        policy_id: policyId,
        policy_type: updatedPolicy.type,
        user_id: this.user.id
      });

      logger.info('Policy updated successfully', {
        policy_id: policyId,
        user_id: this.user.id,
        username: user.username,
        name: updatedPolicy.name,
      });

      return updatedPolicy;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to update policy', {
        error: error.message,
        policy_id: policyId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to update policy: ${error.message}`,
        severity: 'high',
        source: 'policy_service',
        metadata: { 
          policyId, 
          policyData,
          error_type: 'update_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Delete a policy with transaction support
   * @param {number} policyId - Policy ID
   * @returns {boolean} Success status
   */
  async deletePolicy(policyId) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!policyId || typeof policyId !== 'number') {
        throw new Error('Valid policy ID is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('delete_policies');

      const policy = await Policy.findByPk(policyId, { transaction });
      if (!policy) {
        throw new Error('Policy not found');
      }

      // Delete from OPNsense if synchronized
      if (policy.opnsense_rule_id) {
        try {
          await this.opnsenseService.deleteFirewallRule(policy.opnsense_rule_id);
        } catch (opnsenseError) {
          logger.warn('Failed to delete policy from OPNsense', {
            policy_id: policyId,
            opnsense_rule_id: policy.opnsense_rule_id,
            error: opnsenseError.message
          });
          // Continue with local deletion even if OPNsense deletion fails
        }
      }

      await policy.destroy({ transaction });

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policy_deleted', {
        policy_id: policyId,
        policy_type: policy.type,
        user_id: this.user.id
      });

      logger.info('Policy deleted successfully', {
        policy_id: policyId,
        user_id: this.user.id,
        username: user.username,
        policy_name: policy.name
      });

      return true;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to delete policy', {
        error: error.message,
        policy_id: policyId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to delete policy: ${error.message}`,
        severity: 'high',
        source: 'policy_service',
        metadata: { 
          policyId,
          error_type: 'deletion_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Synchronize all policies with OPNsense with improved error handling
   * @returns {Object} Synchronization result
   */
  async syncPoliciesWithOpnsense() {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('sync_policies');

      const policies = await Policy.findAll({ 
        where: { 
          sync_to_opnsense: true,
          type: 'firewall' // Only firewall policies can be synced
        },
        transaction
      });

      let syncCount = 0;
      let errorCount = 0;
      const errors = [];

      for (const policy of policies) {
        try {
          if (policy.opnsense_rule_id) {
            // Update existing rule
            await this.opnsenseService.updateFirewallRule(policy.opnsense_rule_id, {
              description: policy.name,
              enabled: policy.enabled ? 1 : 0,
              interface: policy.configuration?.interface || 'lan',
              action: policy.configuration?.action || 'pass',
              source: policy.configuration?.source || 'any',
              destination: policy.configuration?.destination || 'any',
              ...policy.configuration,
            });
          } else {
            // Create new rule
            const opnsenseRule = await this.opnsenseService.createFirewallRule({
              description: policy.name,
              enabled: policy.enabled ? 1 : 0,
              interface: policy.configuration?.interface || 'lan',
              action: policy.configuration?.action || 'pass',
              source: policy.configuration?.source || 'any',
              destination: policy.configuration?.destination || 'any',
              ...policy.configuration,
            });
            await policy.update({ opnsense_rule_id: opnsenseRule.uuid }, { transaction });
          }
          syncCount++;
        } catch (error) {
          errorCount++;
          const errorInfo = {
            policy_id: policy.id,
            policy_name: policy.name,
            error: error.message
          };
          errors.push(errorInfo);
          
          logger.error('Failed to sync policy with OPNsense', {
            ...errorInfo,
            user_id: this.user.id,
          });
          
          await this.alertService.createSystemAlert({
            type: 'configuration_error',
            message: `Failed to sync policy ${policy.name} with OPNsense: ${error.message}`,
            severity: 'high',
            source: 'policy_service',
            metadata: { 
              policyId: policy.id,
              error_type: 'sync_failure'
            },
          });
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policies_synced', { 
        sync_count: syncCount,
        error_count: errorCount,
        user_id: this.user.id
      });

      const result = {
        success: errorCount === 0,
        total_policies: policies.length,
        synced_count: syncCount,
        error_count: errorCount,
        errors: errors,
        timestamp: new Date()
      };

      logger.info('Policies synchronization completed', {
        ...result,
        user_id: this.user.id,
        username: user.username,
      });

      return result;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to sync policies with OPNsense', {
        error: error.message,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to sync policies with OPNsense: ${error.message}`,
        severity: 'critical',
        source: 'policy_service',
        metadata: {
          error_type: 'sync_operation_failure'
        }
      });
      throw error;
    }
  }

  /**
   * Get policy by ID with caching
   * @param {number} policyId - Policy ID
   * @returns {Object} Policy object
   */
  async getPolicyById(policyId) {
    try {
      // Validate input
      if (!policyId || typeof policyId !== 'number') {
        throw new Error('Valid policy ID is required');
      }

      const cacheKey = `policy_${policyId}`;
      const cachedPolicy = await this.safeGetCache(cacheKey);

      if (cachedPolicy) {
        logger.info('Returning cached policy', { policy_id: policyId });
        return cachedPolicy;
      }

      const policy = await Policy.findByPk(policyId, {
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

      if (!policy) {
        throw new Error('Policy not found');
      }

      await this.safeSetCache(cacheKey, policy, this.cacheTimeout);

      return policy;
    } catch (error) {
      logger.error('Failed to get policy by ID', {
        error: error.message,
        policy_id: policyId,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Clone/duplicate an existing policy
   * @param {number} policyId - Policy ID to clone
   * @param {Object} overrides - Properties to override in the cloned policy
   * @returns {Object} Cloned policy
   */
  async clonePolicy(policyId, overrides = {}) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_policies');

      // Get original policy
      const originalPolicy = await Policy.findByPk(policyId, { transaction });
      if (!originalPolicy) {
        throw new Error('Policy to clone not found');
      }

      // Generate unique name for cloned policy
      let cloneName = overrides.name || `${originalPolicy.name} (Copy)`;
      let counter = 1;
      
      while (await Policy.findOne({ where: { name: cloneName }, transaction })) {
        cloneName = overrides.name ? `${overrides.name} (${counter})` : `${originalPolicy.name} (Copy ${counter})`;
        counter++;
      }

      // Create cloned policy
      const clonedPolicyData = {
        name: cloneName,
        type: originalPolicy.type,
        description: overrides.description || `Clone of ${originalPolicy.name}`,
        enabled: overrides.enabled !== undefined ? overrides.enabled : false, // Disable by default
        priority: overrides.priority || originalPolicy.priority,
        configuration: overrides.configuration || originalPolicy.configuration,
        sync_to_opnsense: overrides.sync_to_opnsense !== undefined ? overrides.sync_to_opnsense : false, // Don't sync by default
        ...overrides
      };

      // Validate cloned policy data
      this.validatePolicyData(clonedPolicyData);

      const clonedPolicy = await Policy.create({
        ...clonedPolicyData,
        created_by: this.user.id,
        updated_by: this.user.id,
        created_at: new Date(),
        updated_at: new Date(),
      }, { transaction });

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policy_cloned', {
        original_policy_id: policyId,
        cloned_policy_id: clonedPolicy.id,
        user_id: this.user.id
      });

      logger.info('Policy cloned successfully', {
        original_policy_id: policyId,
        cloned_policy_id: clonedPolicy.id,
        user_id: this.user.id,
        username: user.username,
        cloned_name: cloneName
      });

      return clonedPolicy;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to clone policy', {
        error: error.message,
        policy_id: policyId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to clone policy: ${error.message}`,
        severity: 'medium',
        source: 'policy_service',
        metadata: { 
          policyId,
          overrides,
          error_type: 'clone_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Bulk update policies
   * @param {Array} policyIds - Array of policy IDs
   * @param {Object} updateData - Data to update
   * @returns {Object} Bulk update result
   */
  async bulkUpdatePolicies(policyIds, updateData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('update_policies');

      // Validate inputs
      if (!Array.isArray(policyIds) || policyIds.length === 0) {
        throw new Error('Policy IDs array is required');
      }

      if (policyIds.length > 50) {
        throw new Error('Cannot update more than 50 policies at once');
      }

      // Validate update data
      const allowedFields = ['enabled', 'priority', 'description'];
      const validatedUpdateData = {};

      Object.keys(updateData).forEach(key => {
        if (allowedFields.includes(key)) {
          validatedUpdateData[key] = updateData[key];
        }
      });

      if (Object.keys(validatedUpdateData).length === 0) {
        throw new Error('No valid fields to update');
      }

      // Add updated metadata
      validatedUpdateData.updated_by = this.user.id;
      validatedUpdateData.updated_at = new Date();

      // Perform bulk update
      const [updatedCount] = await Policy.update(validatedUpdateData, {
        where: {
          id: { [Op.in]: policyIds }
        },
        transaction
      });

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policies_bulk_updated', {
        policy_count: updatedCount,
        updated_fields: Object.keys(validatedUpdateData),
        user_id: this.user.id
      });

      const result = {
        success: true,
        updated_count: updatedCount,
        requested_count: policyIds.length,
        updated_fields: Object.keys(validatedUpdateData).filter(key => key !== 'updated_by' && key !== 'updated_at'),
        timestamp: new Date()
      };

      logger.info('Bulk update policies completed', {
        ...result,
        user_id: this.user.id,
        username: user.username,
      });

      return result;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to bulk update policies', {
        error: error.message,
        policy_ids: policyIds,
        update_data: updateData,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to bulk update policies: ${error.message}`,
        severity: 'high',
        source: 'policy_service',
        metadata: { 
          policyIds,
          updateData,
          error_type: 'bulk_update_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Get policy statistics
   * @returns {Object} Policy statistics
   */
  async getPolicyStatistics() {
    try {
      const cacheKey = 'policy_statistics';
      const cachedStats = await this.safeGetCache(cacheKey);

      if (cachedStats) {
        logger.info('Returning cached policy statistics', { cache_key: cacheKey });
        return cachedStats;
      }

      // Get statistics from database
      const [totalCount, enabledCount, typeStats, priorityStats, syncedCount] = await Promise.all([
        Policy.count(),
        Policy.count({ where: { enabled: true } }),
        Policy.findAll({
          attributes: [
            'type',
            [Policy.sequelize.fn('COUNT', '*'), 'count']
          ],
          group: ['type'],
          raw: true
        }),
        Policy.findAll({
          attributes: [
            'priority',
            [Policy.sequelize.fn('COUNT', '*'), 'count']
          ],
          group: ['priority'],
          order: [['priority', 'ASC']],
          raw: true
        }),
        Policy.count({ where: { sync_to_opnsense: true } })
      ]);

      const stats = {
        total: totalCount,
        enabled: enabledCount,
        disabled: totalCount - enabledCount,
        synced_to_opnsense: syncedCount,
        by_type: {},
        by_priority: {},
        timestamp: new Date()
      };

      // Format type statistics
      typeStats.forEach(stat => {
        stats.by_type[stat.type] = parseInt(stat.count);
      });

      // Format priority statistics
      priorityStats.forEach(stat => {
        const priorityRange = this.getPriorityRange(stat.priority);
        stats.by_priority[priorityRange] = (stats.by_priority[priorityRange] || 0) + parseInt(stat.count);
      });

      await this.safeSetCache(cacheKey, stats, this.cacheTimeout);

      return stats;
    } catch (error) {
      logger.error('Failed to get policy statistics', {
        error: error.message,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Get priority range label
   * @param {number} priority - Priority value
   * @returns {string} Priority range label
   * @private
   */
  getPriorityRange(priority) {
    if (priority >= 800) return 'Critical (800-1000)';
    if (priority >= 600) return 'High (600-799)';
    if (priority >= 400) return 'Medium (400-599)';
    if (priority >= 200) return 'Low (200-399)';
    return 'Very Low (0-199)';
  }

  /**
   * Export policies to JSON format
   * @param {Array} policyIds - Policy IDs to export (optional, exports all if not provided)
   * @returns {Object} Export result
   */
  async exportPolicies(policyIds = null) {
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('view_policies');

      const whereClause = policyIds ? { id: { [Op.in]: policyIds } } : {};

      const policies = await Policy.findAll({
        where: whereClause,
        include: [
          {
            model: User,
            as: 'createdBy',
            attributes: ['username'],
            required: false,
          },
        ],
        order: [['created_at', 'ASC']]
      });

      const exportData = {
        export_metadata: {
          timestamp: new Date(),
          exported_by: user.username,
          total_policies: policies.length,
          version: '1.0'
        },
        policies: policies.map(policy => ({
          name: policy.name,
          type: policy.type,
          description: policy.description,
          enabled: policy.enabled,
          priority: policy.priority,
          configuration: policy.configuration,
          created_by: policy.createdBy?.username,
          created_at: policy.created_at
        }))
      };

      logger.info('Policies exported successfully', {
        exported_count: policies.length,
        user_id: this.user.id,
        username: user.username,
      });

      return exportData;
    } catch (error) {
      logger.error('Failed to export policies', {
        error: error.message,
        policy_ids: policyIds,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Import policies from JSON format
   * @param {Object} importData - Import data
   * @param {Object} options - Import options
   * @returns {Object} Import result
   */
  async importPolicies(importData, options = {}) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_policies');

      // Validate import data
      if (!importData || !importData.policies || !Array.isArray(importData.policies)) {
        throw new Error('Invalid import data format');
      }

      if (importData.policies.length > 100) {
        throw new Error('Cannot import more than 100 policies at once');
      }

      const results = {
        total: importData.policies.length,
        imported: 0,
        skipped: 0,
        errors: [],
        imported_policies: [],
        timestamp: new Date()
      };

      for (const policyData of importData.policies) {
        try {
          // Skip if policy name already exists (unless overwrite is enabled)
          const existingPolicy = await Policy.findOne({
            where: { name: policyData.name },
            transaction
          });

          if (existingPolicy && !options.overwrite) {
            results.skipped++;
            continue;
          }

          // Validate imported policy data
          this.validatePolicyData(policyData);

          let policy;
          if (existingPolicy && options.overwrite) {
            // Update existing policy
            policy = await existingPolicy.update({
              ...policyData,
              updated_by: this.user.id,
              updated_at: new Date()
            }, { transaction });
          } else {
            // Create new policy
            policy = await Policy.create({
              ...policyData,
              created_by: this.user.id,
              updated_by: this.user.id,
              created_at: new Date(),
              updated_at: new Date(),
            }, { transaction });
          }

          results.imported++;
          results.imported_policies.push({
            id: policy.id,
            name: policy.name,
            type: policy.type,
            action: existingPolicy ? 'updated' : 'created'
          });

        } catch (error) {
          results.errors.push({
            policy_name: policyData.name,
            error: error.message
          });
        }
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('policies_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('policies_imported', {
        imported_count: results.imported,
        skipped_count: results.skipped,
        error_count: results.errors.length,
        user_id: this.user.id
      });

      logger.info('Policies import completed', {
        ...results,
        user_id: this.user.id,
        username: user.username,
      });

      return results;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to import policies', {
        error: error.message,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to import policies: ${error.message}`,
        severity: 'high',
        source: 'policy_service',
        metadata: { 
          error_type: 'import_failure'
        },
      });
      throw error;
    }
  }

  /**
   * Validate policy configuration based on type
   * @param {Object} policy - Policy object
   * @returns {Object} Validation result
   */
  async validatePolicyConfiguration(policy) {
    try {
      const validationResult = {
        valid: true,
        errors: [],
        warnings: [],
        suggestions: []
      };

      // Type-specific validation
      switch (policy.type) {
        case 'firewall':
          this.validateFirewallConfiguration(policy.configuration, validationResult);
          break;
        case 'vpn':
          this.validateVpnConfiguration(policy.configuration, validationResult);
          break;
        case 'nat':
          this.validateNatConfiguration(policy.configuration, validationResult);
          break;
        case 'qos':
          this.validateQosConfiguration(policy.configuration, validationResult);
          break;
        default:
          validationResult.warnings.push('Unknown policy type, skipping specific validation');
      }

      // General validation
      if (policy.priority > 900) {
        validationResult.warnings.push('High priority policy - ensure this is intentional');
      }

      if (!policy.description || policy.description.length < 10) {
        validationResult.suggestions.push('Consider adding a more detailed description');
      }

      validationResult.valid = validationResult.errors.length === 0;

      return validationResult;
    } catch (error) {
      logger.error('Failed to validate policy configuration', {
        error: error.message,
        policy_id: policy.id,
        user_id: this.user?.id,
      });
      throw error;
    }
  }

  /**
   * Validate firewall configuration
   * @param {Object} config - Firewall configuration
   * @param {Object} result - Validation result object
   * @private
   */
  validateFirewallConfiguration(config, result) {
    if (!config) {
      result.errors.push('Firewall configuration is required');
      return;
    }

    const requiredFields = ['interface', 'action'];
    requiredFields.forEach(field => {
      if (!config[field]) {
        result.errors.push(`${field} is required for firewall policies`);
      }
    });

    if (config.action === 'block' && !config.log) {
      result.suggestions.push('Consider enabling logging for block rules');
    }

    if (config.source === 'any' && config.destination === 'any' && config.action === 'pass') {
      result.warnings.push('Very permissive rule - ensure this is secure');
    }
  }

  /**
   * Validate VPN configuration
   * @param {Object} config - VPN configuration
   * @param {Object} result - Validation result object
   * @private
   */
  validateVpnConfiguration(config, result) {
    if (!config) {
      result.errors.push('VPN configuration is required');
      return;
    }

    if (!config.protocol || !['openvpn', 'ipsec', 'wireguard'].includes(config.protocol)) {
      result.errors.push('Valid VPN protocol is required (openvpn, ipsec, wireguard)');
    }

    if (!config.encryption || config.encryption.length < 6) {
      result.warnings.push('Weak or missing encryption settings');
    }
  }

  /**
   * Validate NAT configuration
   * @param {Object} config - NAT configuration
   * @param {Object} result - Validation result object
   * @private
   */
  validateNatConfiguration(config, result) {
    if (!config) {
      result.errors.push('NAT configuration is required');
      return;
    }

    if (!config.type || !['snat', 'dnat', 'masquerade'].includes(config.type)) {
      result.errors.push('Valid NAT type is required (snat, dnat, masquerade)');
    }

    if (config.type === 'dnat' && !config.target_ip) {
      result.errors.push('Target IP is required for DNAT rules');
    }
  }

  /**
   * Validate QoS configuration
   * @param {Object} config - QoS configuration
   * @param {Object} result - Validation result object
   * @private
   */
  validateQosConfiguration(config, result) {
    if (!config) {
      result.errors.push('QoS configuration is required');
      return;
    }

    if (!config.bandwidth_limit || config.bandwidth_limit <= 0) {
      result.errors.push('Valid bandwidth limit is required');
    }

    if (!config.priority || config.priority < 1 || config.priority > 7) {
      result.errors.push('Priority must be between 1 and 7');
    }
  }

  /**
   * Get policy dependencies
   * @param {number} policyId - Policy ID
   * @returns {Object} Dependencies information
   */
  async getPolicyDependencies(policyId) {
    try {
      // Validate input
      if (!policyId || typeof policyId !== 'number') {
        throw new Error('Valid policy ID is required');
      }

      const policy = await Policy.findByPk(policyId);
      if (!policy) {
        throw new Error('Policy not found');
      }

      const dependencies = {
        policy_id: policyId,
        policy_name: policy.name,
        dependent_policies: [],
        referenced_by: [],
        opnsense_sync: !!policy.opnsense_rule_id,
        can_be_deleted: true,
        warnings: []
      };

      // Find policies that reference this one
      const referencingPolicies = await Policy.findAll({
        where: {
          configuration: {
            [Op.contains]: { reference_policy: policyId }
          }
        }
      });

      dependencies.referenced_by = referencingPolicies.map(p => ({
        id: p.id,
        name: p.name,
        type: p.type
      }));

      // Check if policy can be safely deleted
      if (dependencies.referenced_by.length > 0) {
        dependencies.can_be_deleted = false;
        dependencies.warnings.push('Policy is referenced by other policies');
      }

      if (policy.opnsense_rule_id) {
        dependencies.warnings.push('Policy is synchronized with OPNsense');
      }

      return dependencies;
    } catch (error) {
      logger.error('Failed to get policy dependencies', {
        error: error.message,
        policy_id: policyId,
        user_id: this.user?.id,
      });
      throw error;
    }
  }
}

module.exports = PolicyService;