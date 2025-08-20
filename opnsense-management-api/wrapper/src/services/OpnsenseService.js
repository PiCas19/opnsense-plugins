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
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
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
   * =========================================================================
   * METODI CORRETTI PER LE REGOLE FIREWALL REALI DI OPNSENSE
   * =========================================================================
   */

  /**
   * Get all firewall rules using the CORRECT API endpoints
   * OPNsense stores rules in different sections:
   * - /api/firewall/filter/searchRule (main filter rules)
   * - /api/firewall/nat/searchRule (NAT rules)
   * - /api/firewall/alias/searchItem (aliases)
   */
  async getFirewallRules(filters = {}) {
    try {
      const cacheKey = `firewall_rules_real_${JSON.stringify(filters)}`;
      const cached = await this.safeGetCache(cacheKey);
      if (cached) return cached;

      // Method 1: Try the standard filter rules API
      let filterRules = [];
      try {
        const filterData = await this.makeApiRequest('GET', '/api/firewall/filter/searchRule', {
          current: 1,
          rowCount: 1000, // Get many rules at once
          ...filters
        }, 'get_filter_rules');
        
        if (filterData && filterData.rows) {
          filterRules = filterData.rows.map(rule => this.normalizeFilterRule(rule));
        }
      } catch (error) {
        logger.warn('Filter rules API failed, trying alternative', { error: error.message });
      }

      // Method 2: If filter rules fail, try to get via configuration dump
      if (filterRules.length === 0) {
        try {
          const configData = await this.getFirewallConfiguration();
          filterRules = this.extractRulesFromConfig(configData);
        } catch (error) {
          logger.warn('Configuration dump failed', { error: error.message });
        }
      }

      // Method 3: Fallback to automation API (separate rules)
      let automationRules = [];
      try {
        const automationData = await this.makeApiRequest('GET', '/api/firewall/filter_util/find_rule_references', {}, 'get_automation_rules');
        if (automationData && automationData.rows) {
          automationRules = automationData.rows.map(rule => this.normalizeAutomationRule(rule));
        }
      } catch (error) {
        logger.warn('Automation rules API failed', { error: error.message });
      }

      // Combine all rule sources
      const allRules = [
        ...filterRules,
        ...automationRules
      ];

      // Add metadata to distinguish rule types
      const enrichedRules = allRules.map(rule => ({
        ...rule,
        source_type: rule.source_type || 'filter',
        manageable: rule.source_type !== 'system', // System rules can't be modified
        created_via: rule.source_type === 'automation' ? 'API' : 'WebUI'
      }));

      await this.safeSetCache(cacheKey, enrichedRules, this.cacheTimeout);
      
      logger.info('Retrieved firewall rules from multiple sources', {
        filter_rules: filterRules.length,
        automation_rules: automationRules.length,
        total_rules: enrichedRules.length
      });

      return enrichedRules;

    } catch (error) {
      logger.error('Failed to get firewall rules from all sources', { 
        error: error.message, 
        filters, 
        user_id: this.user?.id 
      });
      
      // Return demo rules as fallback for development
      if (process.env.NODE_ENV === 'development') {
        return this.getDemoRules();
      }
      
      throw error;
    }
  }

  /**
   * Get firewall configuration via XML configuration dump
   * This provides access to ALL rules including those not in automation API
   */
  async getFirewallConfiguration() {
    try {
      // OPNsense configuration backup/export
      const configData = await this.makeApiRequest('GET', '/api/core/backup/searchBackup', {}, 'get_config');
      
      if (configData && configData.config) {
        return configData.config;
      }

      // Alternative: try diagnostics config dump
      const diagnosticData = await this.makeApiRequest('GET', '/api/diagnostics/configuration/get', {}, 'get_diagnostic_config');
      
      return diagnosticData;
      
    } catch (error) {
      logger.error('Failed to get firewall configuration', { error: error.message });
      throw error;
    }
  }

  /**
   * Extract firewall rules from configuration XML/JSON
   */
  extractRulesFromConfig(configData) {
    try {
      const rules = [];
      
      // Parse configuration structure (varies by OPNsense version)
      if (configData.filter && configData.filter.rule) {
        const filterRules = Array.isArray(configData.filter.rule) 
          ? configData.filter.rule 
          : [configData.filter.rule];
          
        filterRules.forEach((rule, index) => {
          rules.push({
            uuid: rule.id || `config-rule-${index}`,
            description: rule.descr || `Configuration Rule ${index + 1}`,
            interface: rule.interface || 'wan',
            action: rule.type || 'pass',
            enabled: rule.disabled !== '1',
            source: this.parseAddress(rule.source),
            destination: this.parseAddress(rule.destination),
            protocol: rule.protocol || 'any',
            source_type: 'config',
            manageable: true
          });
        });
      }

      return rules;
    } catch (error) {
      logger.error('Failed to extract rules from config', { error: error.message });
      return [];
    }
  }

  /**
   * Parse address object from OPNsense configuration
   */
  parseAddress(addressObj) {
    if (!addressObj) return 'any';
    
    if (typeof addressObj === 'string') return addressObj;
    
    if (addressObj.any) return 'any';
    if (addressObj.network) return addressObj.network;
    if (addressObj.address) {
      const addr = addressObj.address;
      const mask = addressObj.subnet ? `/${addressObj.subnet}` : '';
      return `${addr}${mask}`;
    }
    
    return 'any';
  }

  /**
   * Normalize filter rule from searchRule API
   */
  normalizeFilterRule(rule) {
    return {
      uuid: rule.uuid || rule.id,
      description: rule.description || rule.descr || 'Unnamed Rule',
      interface: rule.interface || 'wan',
      action: rule.action || 'pass',
      enabled: rule.enabled === '1' || rule.enabled === true,
      source: rule.source || 'any',
      destination: rule.destination || 'any',
      protocol: rule.protocol || 'any',
      source_port: rule.source_port || null,
      destination_port: rule.destination_port || null,
      created: rule.created || new Date().toISOString(),
      source_type: 'filter',
      manageable: true
    };
  }

  /**
   * Normalize automation rule
   */
  normalizeAutomationRule(rule) {
    return {
      uuid: rule.uuid || rule.id,
      description: rule.description || 'Automation Rule',
      interface: rule.interface || 'wan',
      action: rule.action || 'pass',
      enabled: rule.enabled === '1' || rule.enabled === true,
      source: rule.source || 'any',
      destination: rule.destination || 'any',
      protocol: rule.protocol || 'any',
      created: rule.created || new Date().toISOString(),
      source_type: 'automation',
      manageable: true
    };
  }

  /**
   * Toggle firewall rule (enable/disable)
   * Works with REAL OPNsense rules via proper API endpoints
   */
  async toggleFirewallRule(ruleId, enabled) {
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('update_rules');

      // First, get the current rule to determine its type and current state
      const currentRule = await this.getFirewallRuleById(ruleId);
      if (!currentRule) {
        throw new Error(`Rule with ID ${ruleId} not found`);
      }

      if (!currentRule.manageable) {
        throw new Error('This rule cannot be modified (system rule)');
      }

      let result;
      
      // Handle different rule types differently
      if (currentRule.source_type === 'automation') {
        // Use automation API for automation rules
        result = await this.toggleAutomationRule(ruleId, enabled);
      } else {
        // Use filter API for standard rules
        result = await this.toggleFilterRule(ruleId, enabled);
      }

      // Apply configuration changes
      await this.applyConfigurationChanges();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('firewall_rule_toggled', {
        rule_id: ruleId,
        enabled: enabled,
        rule_type: currentRule.source_type,
        user_id: this.user.id
      });

      logger.info('Firewall rule toggled successfully', {
        rule_id: ruleId,
        enabled: enabled,
        rule_type: currentRule.source_type,
        user_id: this.user.id,
        username: user.username
      });

      return {
        success: true,
        rule_id: ruleId,
        enabled: enabled,
        message: `Rule ${enabled ? 'enabled' : 'disabled'} successfully`
      };

    } catch (error) {
      logger.error('Failed to toggle firewall rule', {
        error: error.message,
        rule_id: ruleId,
        enabled: enabled,
        user_id: this.user?.id
      });

      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to toggle firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { 
          ruleId, 
          enabled,
          error_type: 'toggle_failure'
        }
      });

      throw error;
    }
  }

  /**
   * Get specific firewall rule by ID
   */
  async getFirewallRuleById(ruleId) {
    try {
      // Try filter rules first
      try {
        const filterData = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${ruleId}`, {}, 'get_filter_rule');
        if (filterData && filterData.rule) {
          return this.normalizeFilterRule(filterData.rule);
        }
      } catch (error) {
        logger.debug('Rule not found in filter API', { ruleId, error: error.message });
      }

      // Try automation rules
      try {
        const automationData = await this.makeApiRequest('GET', `/api/firewall/filter_util/get/${ruleId}`, {}, 'get_automation_rule');
        if (automationData && automationData.rule) {
          return this.normalizeAutomationRule(automationData.rule);
        }
      } catch (error) {
        logger.debug('Rule not found in automation API', { ruleId, error: error.message });
      }

      // If not found in APIs, search in all rules
      const allRules = await this.getFirewallRules();
      return allRules.find(rule => rule.uuid === ruleId);

    } catch (error) {
      logger.error('Failed to get firewall rule by ID', { 
        error: error.message, 
        ruleId,
        user_id: this.user?.id 
      });
      return null;
    }
  }

  /**
   * Toggle filter rule via filter API
   */
  async toggleFilterRule(ruleId, enabled) {
    try {
      // Get current rule
      const ruleData = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${ruleId}`, {}, 'get_filter_rule');
      
      if (!ruleData || !ruleData.rule) {
        throw new Error(`Filter rule ${ruleId} not found`);
      }

      // Update the enabled state
      const updatedRule = {
        ...ruleData.rule,
        enabled: enabled ? '1' : '0'
      };

      // Save the updated rule
      const result = await this.makeApiRequest('POST', `/api/firewall/filter/setRule/${ruleId}`, {
        rule: updatedRule
      }, 'update_filter_rule');

      return result;

    } catch (error) {
      logger.error('Failed to toggle filter rule', { 
        error: error.message, 
        ruleId, 
        enabled 
      });
      throw error;
    }
  }

  /**
   * Toggle automation rule via automation API
   */
  async toggleAutomationRule(ruleId, enabled) {
    try {
      // Get current automation rule
      const ruleData = await this.makeApiRequest('GET', `/api/firewall/filter_util/get/${ruleId}`, {}, 'get_automation_rule');
      
      if (!ruleData || !ruleData.rule) {
        throw new Error(`Automation rule ${ruleId} not found`);
      }

      // Update the enabled state
      const updatedRule = {
        ...ruleData.rule,
        enabled: enabled ? '1' : '0'
      };

      // Save the updated rule
      const result = await this.makeApiRequest('POST', `/api/firewall/filter_util/set/${ruleId}`, {
        rule: updatedRule
      }, 'update_automation_rule');

      return result;

    } catch (error) {
      logger.error('Failed to toggle automation rule', { 
        error: error.message, 
        ruleId, 
        enabled 
      });
      throw error;
    }
  }

  /**
   * Create new firewall rule using the appropriate API
   * Creates rules that integrate with the main firewall system
   */
  async createFirewallRule(ruleData) {
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('create_rules');

      // Validate rule data
      this.validateRuleData(ruleData);

      // Determine which API to use based on rule type
      const useAutomationAPI = ruleData.api_managed === true || ruleData.source_type === 'automation';

      let result;
      if (useAutomationAPI) {
        // Create via automation API (separate from web UI rules)
        result = await this.createAutomationRule(ruleData);
      } else {
        // Create via filter API (integrates with web UI rules)
        result = await this.createFilterRule(ruleData);
      }

      // Apply configuration
      await this.applyConfigurationChanges();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      // Record metrics
      metricsHelpers.recordConfigurationChange('firewall_rule_created', {
        rule_type: useAutomationAPI ? 'automation' : 'filter',
        interface: ruleData.interface,
        action: ruleData.action,
        user_id: this.user.id
      });

      logger.info('Firewall rule created successfully', {
        rule_id: result.uuid,
        rule_type: useAutomationAPI ? 'automation' : 'filter',
        user_id: this.user.id,
        username: user.username
      });

      return result;

    } catch (error) {
      logger.error('Failed to create firewall rule', {
        error: error.message,
        ruleData,
        user_id: this.user?.id
      });
      throw error;
    }
  }

  /**
   * Create filter rule (integrates with web UI)
   */
  async createFilterRule(ruleData) {
  const formattedRule = {
    enabled: ruleData.enabled ? '1' : '0',
    interface: ruleData.interface || 'wan',
    direction: ruleData.direction || 'in',
    ipprotocol: ruleData.ipprotocol || 'inet',
    protocol: ruleData.protocol || 'any',
    source_net: this.convertToOPNsenseFormat(ruleData.source) || 'any',
    destination_net: this.convertToOPNsenseFormat(ruleData.destination) || 'any',
    action: ruleData.action || 'pass',
    description: ruleData.description || 'API Created Rule',
    log: ruleData.log ? '1' : '0'
  };

  const result = await this.makeApiRequest('POST', '/api/firewall/filter/addRule', {
    rule: formattedRule
  }, 'create_filter_rule');

  return {
    uuid: result.uuid,
    ...formattedRule,
    source_type: 'filter'
  };
}

convertToOPNsenseFormat(addressObj) {
  // Se è già una stringa, restituiscila
  if (typeof addressObj === 'string') {
    return addressObj;
  }
  
  // Se è un oggetto, convertilo
  if (addressObj && typeof addressObj === 'object') {
    if (addressObj.type === 'any') return 'any';
    if (addressObj.type === 'network') return addressObj.network;
    if (addressObj.type === 'single') return addressObj.address;
  }
  
  return 'any';
}

  /**
   * Create automation rule (separate from web UI)
   */
  async createAutomationRule(ruleData) {
    const formattedRule = {
      enabled: ruleData.enabled ? '1' : '0',
      interface: ruleData.interface || 'wan',
      action: ruleData.action || 'pass',
      source: ruleData.source || 'any',
      destination: ruleData.destination || 'any',
      protocol: ruleData.protocol || 'any',
      description: ruleData.description || 'API Automation Rule'
    };

    const result = await this.makeApiRequest('POST', '/api/firewall/filter_util/add', {
      rule: formattedRule
    }, 'create_automation_rule');

    return {
      uuid: result.uuid,
      ...formattedRule,
      source_type: 'automation'
    };
  }

  /**
   * Apply pending configuration changes
   * This is CRITICAL - changes don't take effect until applied
   */
  async applyConfigurationChanges() {
    try {
      // Multiple apply endpoints might be needed
      const applyEndpoints = [
        '/api/firewall/filter/apply',
        '/api/firewall/filter_util/apply'
      ];

      for (const endpoint of applyEndpoints) {
        try {
          const result = await this.makeApiRequest('POST', endpoint, {}, 'apply_config');
          logger.debug('Configuration applied via endpoint', { endpoint, result });
        } catch (error) {
          logger.warn('Apply failed for endpoint', { endpoint, error: error.message });
          // Continue to next endpoint
        }
      }

      // Wait a moment for changes to propagate
      await new Promise(resolve => setTimeout(resolve, 1000));

      logger.info('Configuration changes applied successfully');
      return true;

    } catch (error) {
      logger.error('Failed to apply configuration changes', { error: error.message });
      throw error;
    }
  }

  /**
   * Get demo rules for development/testing
   */
  getDemoRules() {
    return [
      {
        uuid: 'demo-rule-1',
        description: 'Block Malicious IPs',
        interface: 'wan',
        action: 'block',
        enabled: true,
        source: '192.168.100.0/24',
        destination: 'any',
        protocol: 'any',
        source_type: 'demo',
        manageable: true,
        created_via: 'Demo'
      },
      {
        uuid: 'demo-rule-2',
        description: 'Allow Management Access',
        interface: 'lan',
        action: 'pass',
        enabled: true,
        source: '192.168.1.0/24',
        destination: '192.168.216.1',
        protocol: 'tcp',
        source_type: 'demo',
        manageable: true,
        created_via: 'Demo'
      },
      {
        uuid: 'demo-rule-3',
        description: 'Block Suspicious Port Scans',
        interface: 'wan',
        action: 'block',
        enabled: false,
        source: 'any',
        destination: '192.168.216.0/24',
        protocol: 'tcp',
        source_type: 'demo',
        manageable: true,
        created_via: 'Demo'
      }
    ];
  }

  // ... rest of the existing methods (safeGetCache, safeSetCache, etc.)
  // mantenere gli altri metodi esistenti senza modifiche

  async safeGetCache(key) {
    try {
      return await cache.get(key);
    } catch (error) {
      logger.warn('Cache get failed', { key, error: error.message });
      return null;
    }
  }

  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttl);
    } catch (error) {
      logger.warn('Cache set failed', { key, error: error.message });
    }
  }

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
  }

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

    if (!user.hasPermission(action)) {
      throw new Error(`User does not have permission to ${action}`);
    }

    return user;
  }

  async testConnection() {
    try {
      const startTime = Date.now();
      
      const data = await this.makeApiRequest('GET', '/api/core/firmware/status', {}, 'test_connection');
      
      const responseTime = Date.now() - startTime;
      
      return {
        success: true,
        response_time_ms: responseTime,
        api_version: data?.api_version || 'unknown',
        system_version: data?.version || 'unknown',
        timestamp: new Date()
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        status_code: error.response?.status,
        timestamp: new Date()
      };
    }
  }
}

module.exports = OpnsenseService;