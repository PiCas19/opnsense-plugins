const axios = require('axios');
const logger = require('../utils/logger');
const { opnsenseConfig } = require('../config/opnsense');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const { sequelize } = require('../config/database');
const AlertService = require('./AlertService');
const User = require('../models/User');

class OpnsenseService {
  constructor(user = null) {
    this.user = user;
    this.baseUrl = opnsenseConfig.apiUrl;
    this.apiKey = opnsenseConfig.apiKey;
    this.apiSecret = opnsenseConfig.apiSecret;
    this.alertService = new AlertService(user);
    this.cacheTimeout = process.env.OPNSENSE_CACHE_TIMEOUT || 60;
    this.maxRetries = process.env.MAX_API_RETRIES || 3;
    this.requestTimeout = process.env.API_REQUEST_TIMEOUT || 10000;
    this.rateLimitMap = new Map();
  }

  /**
   * Rate limiting check
   * @param {string} operation - Operation identifier
   * @param {number} maxRequests - Max requests per minute
   * @returns {boolean} True if allowed
   * @private
   */
  checkRateLimit(operation, maxRequests = 60) {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    
    if (!this.rateLimitMap.has(operation)) {
      this.rateLimitMap.set(operation, []);
    }
    
    const requests = this.rateLimitMap.get(operation);
    const validRequests = requests.filter(timestamp => now - timestamp < windowMs);
    
    if (validRequests.length >= maxRequests) {
      logger.warn('Rate limit exceeded', { operation, requests_count: validRequests.length });
      return false;
    }
    
    validRequests.push(now);
    this.rateLimitMap.set(operation, validRequests);
    return true;
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
   * Initialize HTTP client for OPNsense API with retry logic
   * @private
   */
  getHttpClient() {
    return axios.create({
      baseURL: this.baseUrl,
      auth: {
        username: this.apiKey,
        password: this.apiSecret,
      },
      timeout: this.requestTimeout,
      maxRedirects: 0
    });
  }

  /**
   * Make API request with retry logic and rate limiting
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request data
   * @param {string} operation - Operation name for rate limiting
   * @returns {Object} API response
   * @private
   */
  async makeApiRequest(method, endpoint, data = {}, operation = 'default') {
    // Check rate limit
    if (!this.checkRateLimit(operation)) {
      throw new Error(`Rate limit exceeded for operation: ${operation}`);
    }

    let lastError;
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const client = this.getHttpClient();
        let response;

        switch (method.toLowerCase()) {
          case 'get':
            response = await client.get(endpoint, { params: data });
            break;
          case 'post':
            response = await client.post(endpoint, data);
            break;
          case 'put':
            response = await client.put(endpoint, data);
            break;
          case 'delete':
            response = await client.delete(endpoint);
            break;
          default:
            throw new Error(`Unsupported HTTP method: ${method}`);
        }

        return response.data;
      } catch (error) {
        lastError = error;
        logger.warn('API request failed', {
          method,
          endpoint,
          attempt,
          error: error.message,
          status: error.response?.status
        });

        // Don't retry on client errors (4xx)
        if (error.response?.status >= 400 && error.response?.status < 500) {
          break;
        }

        if (attempt < this.maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    throw lastError;
  }

  /**
   * Validate firewall rule data
   * @param {Object} ruleData - Rule data to validate
   * @private
   */
  validateRuleData(ruleData) {
    const requiredFields = ['interface', 'action', 'description'];
    const validActions = ['pass', 'block', 'reject'];
    const validInterfaces = ['wan', 'lan', 'opt1', 'opt2', 'opt3'];

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

    if (ruleData.description && ruleData.description.length > 255) {
      throw new Error('Description too long (max 255 characters)');
    }

    if (ruleData.source && ruleData.source !== 'any' && !/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(ruleData.source)) {
      throw new Error('Invalid source IP/CIDR format');
    }

    if (ruleData.destination && ruleData.destination !== 'any' && !/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(ruleData.destination)) {
      throw new Error('Invalid destination IP/CIDR format');
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
 * Get all firewall rules with improved caching and pagination
 * @param {Object} filters - Filter criteria (optional)
 * @returns {Array} List of all firewall rules
 */
async getFirewallRules(filters = {}) {
  try {
    // Validate and sanitize filters
    const sanitizedFilters = { show_all: 1, ...filters }; // Aggiungi show_all per default
    if (filters.interface && /^[a-zA-Z0-9]+$/.test(filters.interface)) {
      sanitizedFilters.interface = filters.interface;
    }
    if (filters.action && ['pass', 'block', 'reject'].includes(filters.action)) {
      sanitizedFilters.action = filters.action;
    }
    if (filters.enabled !== undefined && typeof filters.enabled === 'boolean') {
      sanitizedFilters.enabled = filters.enabled;
    }

    // Usa una chiave cache che indica "tutte le regole" se non ci sono filtri restrittivi
    const cacheKey = `firewall_rules_all_${JSON.stringify(sanitizedFilters)}`;
    const cachedRules = await this.safeGetCache(cacheKey);

    if (cachedRules) {
      logger.info('Returning cached firewall rules', { cache_key: cacheKey });
      return cachedRules;
    }

    let allRules = [];
    let page = 1;
    const limit = 100; // Numero massimo di regole per pagina (regolabile)

    while (true) {
      const offset = (page - 1) * limit;
      const data = await this.makeApiRequest('GET', '/firewall/filter/get', {
        ...sanitizedFilters,
        limit,
        offset,
      }, 'get_rules');

      const rules = data?.rules || [];
      const validatedRules = rules.filter(rule => rule && typeof rule === 'object' && rule.uuid);

      allRules = allRules.concat(validatedRules);

      // Esci dal ciclo se non ci sono più regole
      if (validatedRules.length < limit) break;

      page++;
    }

    // Calcola il totale basato sul numero di regole recuperate
    const total = allRules.length;

    await this.safeSetCache(cacheKey, allRules, this.cacheTimeout);

    logger.info('All firewall rules retrieved and cached', {
      cache_key: cacheKey,
      rules_count: allRules.length,
      total,
    });

    return allRules;
  } catch (error) {
    logger.error('Failed to get firewall rules', {
      error: error.message,
      filters,
      user_id: this.user?.id,
    });
    await this.alertService.createSystemAlert({
      type: 'configuration_error',
      message: `Failed to retrieve firewall rules: ${error.message}`,
      severity: 'medium',
      source: 'opnsense',
      metadata: { 
        filters,
        error_type: 'api_failure',
        endpoint: '/firewall/filter/get'
      },
    });
    throw error;
  }
}

  /**
   * Create a new firewall rule with transaction support
   * @param {Object} ruleData - Firewall rule data
   * @returns {Object} Created rule
   */
  async createFirewallRule(ruleData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_rules');

      // Validate rule data
      this.validateRuleData(ruleData);

      // Create rule via API
      const data = await this.makeApiRequest('POST', '/firewall/filter/add', ruleData, 'create_rule');
      const newRule = data?.rule;

      if (!newRule || !newRule.uuid) {
        throw new Error('Invalid response from OPNsense API');
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('firewall_rule_created', {
        interface: ruleData.interface,
        action: ruleData.action,
        user_id: this.user.id
      });

      logger.info('Firewall rule created successfully', {
        rule_id: newRule.uuid,
        user_id: this.user.id,
        username: user.username,
        interface: ruleData.interface,
        action: ruleData.action
      });

      return newRule;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to create firewall rule', {
        error: error.message,
        ruleData,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to create firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { 
          ruleData,
          error_type: 'api_failure',
          endpoint: '/firewall/filter/add'
        },
      });
      throw error;
    }
  }

  /**
   * Update an existing firewall rule with transaction support
   * @param {string} ruleId - Rule UUID
   * @param {Object} ruleData - Updated rule data
   * @returns {Object} Updated rule
   */
  async updateFirewallRule(ruleId, ruleData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!ruleId || typeof ruleId !== 'string') {
        throw new Error('Valid rule ID is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('update_rules');

      // Validate rule data
      this.validateRuleData(ruleData);

      // Update rule via API
      const data = await this.makeApiRequest('POST', `/firewall/filter/set/${ruleId}`, ruleData, 'update_rule');
      const updatedRule = data?.rule;

      if (!updatedRule) {
        throw new Error('Invalid response from OPNsense API');
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('firewall_rule_updated', {
        rule_id: ruleId,
        interface: ruleData.interface,
        action: ruleData.action,
        user_id: this.user.id
      });

      logger.info('Firewall rule updated successfully', {
        rule_id: ruleId,
        user_id: this.user.id,
        username: user.username,
      });

      return updatedRule;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to update firewall rule', {
        error: error.message,
        rule_id: ruleId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to update firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { 
          ruleId, 
          ruleData,
          error_type: 'api_failure',
          endpoint: `/firewall/filter/set/${ruleId}`
        },
      });
      throw error;
    }
  }

  /**
   * Delete a firewall rule with transaction support
   * @param {string} ruleId - Rule UUID
   * @returns {boolean} Success status
   */
  async deleteFirewallRule(ruleId) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!ruleId || typeof ruleId !== 'string') {
        throw new Error('Valid rule ID is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('delete_rules');

      // Delete rule via API
      await this.makeApiRequest('POST', `/firewall/filter/delete/${ruleId}`, {}, 'delete_rule');

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('firewall_rule_deleted', {
        rule_id: ruleId,
        user_id: this.user.id
      });

      logger.info('Firewall rule deleted successfully', {
        rule_id: ruleId,
        user_id: this.user.id,
        username: user.username,
      });

      return true;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to delete firewall rule', {
        error: error.message,
        rule_id: ruleId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to delete firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { 
          ruleId,
          error_type: 'api_failure',
          endpoint: `/firewall/filter/delete/${ruleId}`
        },
      });
      throw error;
    }
  }

  /**
   * Get network interface configurations with validation
   * @returns {Array} List of interface configurations
   */
  async getInterfaceConfigurations() {
    try {
      const cacheKey = 'interface_configurations';
      const cachedConfigs = await this.safeGetCache(cacheKey);

      if (cachedConfigs) {
        logger.info('Returning cached interface configurations', { cache_key: cacheKey });
        return cachedConfigs;
      }

      const data = await this.makeApiRequest('GET', '/interfaces/settings', {}, 'get_interfaces');
      const interfaces = data?.interfaces || [];

      // Validate interface data structure
      const validatedInterfaces = interfaces.filter(intf => {
        return intf && typeof intf === 'object' && intf.name;
      });

      await this.safeSetCache(cacheKey, validatedInterfaces, this.cacheTimeout);

      logger.info('Interface configurations retrieved and cached', {
        cache_key: cacheKey,
        interfaces_count: validatedInterfaces.length
      });

      return validatedInterfaces;
    } catch (error) {
      logger.error('Failed to get interface configurations', {
        error: error.message,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to retrieve interface configurations: ${error.message}`,
        severity: 'medium',
        source: 'opnsense',
        metadata: {
          error_type: 'api_failure',
          endpoint: '/interfaces/settings'
        }
      });
      throw error;
    }
  }

  /**
   * Update network interface configuration with transaction support
   * @param {string} interfaceId - Interface ID
   * @param {Object} configData - Configuration data
   * @returns {Object} Updated interface configuration
   */
  async updateInterfaceConfiguration(interfaceId, configData) {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate inputs
      if (!interfaceId || typeof interfaceId !== 'string') {
        throw new Error('Valid interface ID is required');
      }
      if (!configData || typeof configData !== 'object') {
        throw new Error('Valid configuration data is required');
      }

      // Validate permissions
      const user = await this.validateUserPermissions('update_interface');

      // Update interface via API
      const data = await this.makeApiRequest('POST', `/interfaces/settings/set/${interfaceId}`, configData, 'update_interface');
      const updatedConfig = data?.interface;

      if (!updatedConfig) {
        throw new Error('Invalid response from OPNsense API');
      }

      await transaction.commit();

      // Invalidate cache
      await this.invalidateCachePattern('interface_configurations');

      // Record metrics
      metricsHelpers.recordConfigurationChange('interface_updated', {
        interface_id: interfaceId,
        user_id: this.user.id
      });

      logger.info('Interface configuration updated successfully', {
        interface_id: interfaceId,
        user_id: this.user.id,
        username: user.username,
      });

      return updatedConfig;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to update interface configuration', {
        error: error.message,
        interface_id: interfaceId,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to update interface configuration: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { 
          interfaceId, 
          configData,
          error_type: 'api_failure',
          endpoint: `/interfaces/settings/set/${interfaceId}`
        },
      });
      throw error;
    }
  }

  /**
   * Apply pending configuration changes with validation
   * @returns {boolean} Success status
   */
  async applyConfigurationChanges() {
    const transaction = await sequelize.transaction();
    
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('apply_configuration');

      // Apply configuration changes via API
      const data = await this.makeApiRequest('POST', '/firewall/filter/apply', {}, 'apply_config');

      // Validate response
      if (data?.status !== 'ok' && data?.result !== 'success') {
        throw new Error('Configuration apply failed on OPNsense');
      }

      await transaction.commit();

      // Invalidate all configuration-related cache
      await this.invalidateCachePattern('firewall_rules_*');
      await this.invalidateCachePattern('interface_configurations');

      // Record metrics
      metricsHelpers.recordConfigurationChange('configuration_applied', {
        user_id: this.user.id,
        timestamp: new Date()
      });

      logger.info('Configuration changes applied successfully', {
        user_id: this.user.id,
        username: user.username,
      });

      return true;
    } catch (error) {
      await transaction.rollback();
      logger.error('Failed to apply configuration changes', {
        error: error.message,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to apply configuration changes: ${error.message}`,
        severity: 'critical',
        source: 'opnsense',
        metadata: {
          error_type: 'api_failure',
          endpoint: '/firewall/filter/apply'
        }
      });
      throw error;
    }
  }

  /**
   * Test API connectivity and authentication
   * @returns {Object} Connection test result
   */
  async testConnection() {
    try {
      const startTime = Date.now();
      
      // Test basic API connectivity
      const data = await this.makeApiRequest('GET', '/core/system/status', {}, 'test_connection');
      
      const responseTime = Date.now() - startTime;
      
      const result = {
        success: true,
        response_time_ms: responseTime,
        api_version: data?.api_version || 'unknown',
        system_version: data?.version || 'unknown',
        timestamp: new Date()
      };

      logger.info('OPNsense connection test successful', {
        response_time_ms: responseTime,
        user_id: this.user?.id
      });

      return result;
    } catch (error) {
      const result = {
        success: false,
        error: error.message,
        status_code: error.response?.status,
        timestamp: new Date()
      };

      logger.error('OPNsense connection test failed', {
        error: error.message,
        status_code: error.response?.status,
        user_id: this.user?.id
      });

      return result;
    }
  }

  /**
   * Get service health status
   * @returns {Object} Service health information
   */
  async getServiceHealth() {
    try {
      const cacheKey = 'opnsense_service_health';
      const cachedHealth = await this.safeGetCache(cacheKey);

      if (cachedHealth) {
        logger.info('Returning cached service health', { cache_key: cacheKey });
        return cachedHealth;
      }

      // Test multiple endpoints to determine overall health
      const healthChecks = await Promise.allSettled([
        this.testConnection(),
        this.getFirewallRules({}).catch(() => null)
      ]);

      const connectionTest = healthChecks[0].status === 'fulfilled' ? healthChecks[0].value : null;
      const rulesTest = healthChecks[1].status === 'fulfilled' ? healthChecks[1].value : null;

      const health = {
        overall_status: connectionTest?.success && rulesTest ? 'healthy' : 'unhealthy',
        timestamp: new Date(),
        components: {
          api_connectivity: connectionTest?.success || false,
          firewall_rules_accessible: !!rulesTest,
          api_response_time_ms: connectionTest?.response_time_ms || null
        },
        rate_limit_status: {
          active_operations: this.rateLimitMap.size,
          total_requests_last_minute: Array.from(this.rateLimitMap.values())
            .flat()
            .filter(timestamp => Date.now() - timestamp < 60000)
            .length
        }
      };

      await this.safeSetCache(cacheKey, health, 30); // Cache for 30 seconds

      return health;
    } catch (error) {
      logger.error('Failed to get service health', {
        error: error.message,
        user_id: this.user?.id
      });
      
      return {
        overall_status: 'unhealthy',
        timestamp: new Date(),
        error: error.message
      };
    }
  }
}

module.exports = OpnsenseService;