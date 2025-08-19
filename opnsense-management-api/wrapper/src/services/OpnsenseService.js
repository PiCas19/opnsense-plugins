const axios = require('axios');
const logger = require('../utils/logger');
const { opnsenseConfig } = require('../config/opnsense');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const { sequelize } = require('../config/database');
const AlertService = require('./AlertService');
const User = require('../models/User');
const { parseStringPromise } = require('xml2js');

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
      maxRedirects: 0,
    });
  }

  /**
   * Make API request with retry logic and rate limiting
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request data
   * @param {string} operation - Operation name for rate limiting
   * @returns {Object|string} API response data (string for XML)
   * @private
   */
  async makeApiRequest(method, endpoint, data = {}, operation = 'default') {
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
            response = await client.get(endpoint, { params: data, responseType: 'text' });
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
          status: error.response?.status,
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

  // ---------------------------------------------------------------------------
  // CORE RULES VIA config.xml (LAN/WAN/OPT/Floating)
  // ---------------------------------------------------------------------------

  /**
   * Scarica il config.xml e lo cachea brevemente
   * @private
   */
  async _fetchConfigXmlCached(ttl = Math.min(this.cacheTimeout, 30)) {
    const cacheKey = 'opnsense_config_xml';
    const cached = await this.safeGetCache(cacheKey);
    if (cached) {
      logger.info('Returning cached config.xml');
      return cached;
    }

    const xml = await this.makeApiRequest('GET', '/core/backup/download/this', {}, 'download_config');
    if (typeof xml !== 'string' || !xml.includes('<opnsense')) {
      throw new Error('Unexpected config.xml content');
    }

    await this.safeSetCache(cacheKey, xml, ttl);
    return xml;
  }

  /**
   * Normalizza un nodo <rule> in un JSON piatto
   * @private
   */
  _normalizeCoreRule(rule, idx = 0) {
    const toBool = v => v === '1' || v === 1 || v === true;

    const hasDisabled = Object.prototype.hasOwnProperty.call(rule, 'disabled');
    const isDisabled = hasDisabled && (rule.disabled === '' || toBool(rule.disabled));

    const pickEp = (node = {}) => {
      if (node.any && toBool(node.any)) return { type: 'any', value: 'any', port: null };
      if (node.address) return { type: 'address', value: node.address, port: node.port ?? null };
      if (node.network) return { type: 'network', value: node.network, port: node.port ?? null };
      return { type: null, value: null, port: null };
    };

    const source = pickEp(rule.source);
    const destination = pickEp(rule.destination);

    const uuid = rule?.$?.uuid || rule?.uuid || rule?.tracker || `rule_${idx}`;

    return {
      uuid,
      interface: rule?.interface || null,
      action: rule?.type || rule?.action || null,
      enabled: !isDisabled,
      protocol: rule?.protocol || null,
      ipprotocol: rule?.ipprotocol || null,
      direction: rule?.direction || null,
      quick: toBool(rule?.quick || '0'),
      statetype: rule?.statetype || null,
      log: toBool(rule?.log || '0'),
      description: rule?.descr || rule?.description || '',
      source,
      destination,
      associated_rule_id: rule?.['associated-rule-id'] || null,
      created_at: rule?.created?.time || null,
      updated_at: rule?.updated?.time || null,
    };
  }

  /**
   * Carica e filtra le core rules dal config.xml
   * Filtri: { page, limit, interface, enabled, action, search }
   * @private
   */
  async _loadCoreRulesFromConfig(filters = {}) {
    const xml = await this._fetchConfigXmlCached();
    const obj = await parseStringPromise(xml, { explicitArray: false, attrkey: '$' });

    let rules = obj?.opnsense?.filter?.rule || [];
    if (!Array.isArray(rules)) rules = rules ? [rules] : [];

    let list = rules.map((r, i) => this._normalizeCoreRule(r, i));

    const { interface: iface, enabled, action, search } = filters;

    if (iface) list = list.filter(r => r.interface === iface);
    if (typeof enabled === 'boolean') list = list.filter(r => r.enabled === enabled);
    if (action) list = list.filter(r => r.action === action);
    if (search) {
      const q = String(search).toLowerCase();
      list = list.filter(r =>
        (r.description || '').toLowerCase().includes(q) ||
        (r.interface || '').toLowerCase().includes(q) ||
        (r.source?.value || '').toLowerCase().includes(q) ||
        (r.destination?.value || '').toLowerCase().includes(q)
      );
    }

    const page = Number.isInteger(filters.page) ? filters.page : 1;
    const limit = Number.isInteger(filters.limit) ? filters.limit : list.length || 1000;
    const start = (page - 1) * limit;
    const end = start + limit;

    return {
      total: list.length,
      page,
      limit,
      rows: list.slice(start, end),
    };
  }

  /**
   * Elenco regole core (LAN/WAN/OPT/Floating) leggendo il config.xml.
   * NOTE: niente Automation qui.
   */
  async getFirewallRules(filters = {}) {
    try {
      const cacheKey = `core_rules_${JSON.stringify({
        page: filters.page ?? 1,
        limit: filters.limit ?? 1000,
        interface: filters.interface ?? null,
        enabled: typeof filters.enabled === 'boolean' ? filters.enabled : null,
        action: filters.action ?? null,
        search: filters.search ?? null,
      })}`;

      const cached = await this.safeGetCache(cacheKey);
      if (cached) return cached;

      const { rows } = await this._loadCoreRulesFromConfig(filters);

      await this.safeSetCache(cacheKey, rows, this.cacheTimeout);
      return rows;
    } catch (error) {
      logger.error('Failed to read core firewall rules from config.xml', {
        error: error.message,
        filters,
        user_id: this.user?.id,
      });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to read firewall rules from config.xml: ${error.message}`,
        severity: 'medium',
        source: 'opnsense',
        metadata: { filters, error_type: 'config_parse', endpoint: '/core/backup/download/this' },
      });
      throw error;
    }
  }

  // ---------------------------------------------------------------------------
  // (RESTO: operazioni Automation / management as-is)
  // ---------------------------------------------------------------------------

  /**
   * Create a new firewall rule with transaction support
   * @param {Object} ruleData - Firewall rule data
   * @returns {Object} Created rule
   */
  async createFirewallRule(ruleData) {
    const transaction = await sequelize.transaction();

    try {
      const user = await this.validateUserPermissions('create_rules');

      this.validateRuleData(ruleData);

      const data = await this.makeApiRequest('POST', '/firewall/filter/add', ruleData, 'create_rule');
      const newRule = data?.rule;

      if (!newRule || !newRule.uuid) {
        throw new Error('Invalid response from OPNsense API');
      }

      await transaction.commit();

      await this.invalidateCachePattern('core_rules_');
      await this.invalidateCachePattern('opnsense_config_xml');

      metricsHelpers.recordConfigurationChange('firewall_rule_created', {
        interface: ruleData.interface,
        action: ruleData.action,
        user_id: this.user.id,
      });

      logger.info('Firewall rule created successfully', {
        rule_id: newRule.uuid,
        user_id: this.user.id,
        username: user.username,
        interface: ruleData.interface,
        action: ruleData.action,
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
          endpoint: '/firewall/filter/add',
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
      if (!ruleId || typeof ruleId !== 'string') {
        throw new Error('Valid rule ID is required');
      }

      const user = await this.validateUserPermissions('update_rules');

      this.validateRuleData(ruleData);

      const data = await this.makeApiRequest('POST', `/firewall/filter/set/${ruleId}`, ruleData, 'update_rule');
      const updatedRule = data?.rule;

      if (!updatedRule) {
        throw new Error('Invalid response from OPNsense API');
      }

      await transaction.commit();

      await this.invalidateCachePattern('core_rules_');
      await this.invalidateCachePattern('opnsense_config_xml');

      metricsHelpers.recordConfigurationChange('firewall_rule_updated', {
        rule_id: ruleId,
        interface: ruleData.interface,
        action: ruleData.action,
        user_id: this.user.id,
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
          endpoint: `/firewall/filter/set/${ruleId}`,
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
      if (!ruleId || typeof ruleId !== 'string') {
        throw new Error('Valid rule ID is required');
      }

      const user = await this.validateUserPermissions('delete_rules');

      await this.makeApiRequest('POST', `/firewall/filter/delete/${ruleId}`, {}, 'delete_rule');

      await transaction.commit();

      await this.invalidateCachePattern('core_rules_');
      await this.invalidateCachePattern('opnsense_config_xml');

      metricsHelpers.recordConfigurationChange('firewall_rule_deleted', {
        rule_id: ruleId,
        user_id: this.user.id,
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
          endpoint: `/firewall/filter/delete/${ruleId}`,
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

      const validatedInterfaces = interfaces.filter(intf => {
        return intf && typeof intf === 'object' && intf.name;
      });

      await this.safeSetCache(cacheKey, validatedInterfaces, this.cacheTimeout);

      logger.info('Interface configurations retrieved and cached', {
        cache_key: cacheKey,
        interfaces_count: validatedInterfaces.length,
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
          endpoint: '/interfaces/settings',
        },
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
      if (!interfaceId || typeof interfaceId !== 'string') {
        throw new Error('Valid interface ID is required');
      }
      if (!configData || typeof configData !== 'object') {
        throw new Error('Valid configuration data is required');
      }

      const user = await this.validateUserPermissions('update_interface');

      const data = await this.makeApiRequest(
        'POST',
        `/interfaces/settings/set/${interfaceId}`,
        configData,
        'update_interface'
      );
      const updatedConfig = data?.interface;

      if (!updatedConfig) {
        throw new Error('Invalid response from OPNsense API');
      }

      await transaction.commit();

      await this.invalidateCachePattern('interface_configurations');

      metricsHelpers.recordConfigurationChange('interface_updated', {
        interface_id: interfaceId,
        user_id: this.user.id,
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
          endpoint: `/interfaces/settings/set/${interfaceId}`,
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
      const user = await this.validateUserPermissions('apply_configuration');

      const data = await this.makeApiRequest('POST', '/firewall/filter/apply', {}, 'apply_config');

      if (data?.status !== 'ok' && data?.result !== 'success') {
        throw new Error('Configuration apply failed on OPNsense');
      }

      await transaction.commit();

      await this.invalidateCachePattern('core_rules_');
      await this.invalidateCachePattern('opnsense_config_xml');
      await this.invalidateCachePattern('interface_configurations');

      metricsHelpers.recordConfigurationChange('configuration_applied', {
        user_id: this.user.id,
        timestamp: new Date(),
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
          endpoint: '/firewall/filter/apply',
        },
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

      const data = await this.makeApiRequest('GET', '/core/system/status', {}, 'test_connection');

      const responseTime = Date.now() - startTime;

      const result = {
        success: true,
        response_time_ms: responseTime,
        api_version: data?.api_version || 'unknown',
        system_version: data?.version || 'unknown',
        timestamp: new Date(),
      };

      logger.info('OPNsense connection test successful', {
        response_time_ms: responseTime,
        user_id: this.user?.id,
      });

      return result;
    } catch (error) {
      const result = {
        success: false,
        error: error.message,
        status_code: error.response?.status,
        timestamp: new Date(),
      };

      logger.error('OPNsense connection test failed', {
        error: error.message,
        status_code: error.response?.status,
        user_id: this.user?.id,
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

      const healthChecks = await Promise.allSettled([
        this.testConnection(),
        this.getFirewallRules({}).catch(() => null),
      ]);

      const connectionTest = healthChecks[0].status === 'fulfilled' ? healthChecks[0].value : null;
      const rulesTest = healthChecks[1].status === 'fulfilled' ? healthChecks[1].value : null;

      const health = {
        overall_status: connectionTest?.success && rulesTest ? 'healthy' : 'unhealthy',
        timestamp: new Date(),
        components: {
          api_connectivity: connectionTest?.success || false,
          firewall_rules_accessible: !!rulesTest,
          api_response_time_ms: connectionTest?.response_time_ms || null,
        },
        rate_limit_status: {
          active_operations: this.rateLimitMap.size,
          total_requests_last_minute: Array.from(this.rateLimitMap.values())
            .flat()
            .filter(timestamp => Date.now() - timestamp < 60000).length,
        },
      };

      await this.safeSetCache(cacheKey, health, 30);

      return health;
    } catch (error) {
      logger.error('Failed to get service health', {
        error: error.message,
        user_id: this.user?.id,
      });

      return {
        overall_status: 'unhealthy',
        timestamp: new Date(),
        error: error.message,
      };
    }
  }
}

module.exports = OpnsenseService;