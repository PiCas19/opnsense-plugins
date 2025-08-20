const axios = require('axios');
const https = require('https');
const logger = require('../utils/logger');
const { opnsenseConfig } = require('../config/opnsense');
const { cache } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const AlertService = require('./AlertService');
const User = require('../models/User');

class OpnsenseService {
  constructor(user = null) {
    this.user = user;
    // Read configuration from environment variables first, fallback to config file
    this.baseUrl = process.env.OPNSENSE_BASE_URL || opnsenseConfig.baseURL;
    this.apiKey = process.env.OPNSENSE_API_KEY || opnsenseConfig.apiKey;
    this.apiSecret = process.env.OPNSENSE_API_SECRET || opnsenseConfig.apiSecret;
    this.alertService = new AlertService(user);
    this.cacheTimeout = process.env.OPNSENSE_CACHE_TIMEOUT || 60;
    this.maxRetries = process.env.OPNSENSE_RETRIES || 3;
    this.requestTimeout = process.env.OPNSENSE_TIMEOUT || 30000;
    this.rateLimitMap = new Map();

    // SSL verification configuration from environment
    this.sslVerify = process.env.OPNSENSE_SSL_VERIFY === 'true' ? true : false;
    
    logger.info('OPNsense Service Configuration:', {
      baseUrl: this.baseUrl,
      hasApiKey: !!this.apiKey,
      hasApiSecret: !!this.apiSecret,
      sslVerify: this.sslVerify,
      timeout: this.requestTimeout,
      retries: this.maxRetries
    });

    // Configure HTTPS Agent based on environment settings
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: this.sslVerify,
      requestCert: false,
      agent: false,
      timeout: this.requestTimeout,
      secureProtocol: 'TLSv1_2_method',
      checkServerIdentity: this.sslVerify ? undefined : (() => undefined)
    });

    if (!this.sslVerify) {
      logger.warn('SSL certificate verification DISABLED per configuration');
    } else {
      logger.info('SSL certificate verification ENABLED');
    }
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
   * Initialize HTTP client for OPNsense API with proper SSL configuration
   * @private
   */
  getHttpClient() {
    const client = axios.create({
      baseURL: this.baseUrl,
      httpsAgent: this.httpsAgent,
      auth: {
        username: this.apiKey,
        password: this.apiSecret,
      },
      timeout: this.requestTimeout,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'OPNsense-Management-API/1.0'
      },
      validateStatus: function (status) {
        return status < 600; // Accept all status codes below 600
      }
    });

    // Add request interceptor for debugging
    client.interceptors.request.use(
      (config) => {
        logger.debug(`API Request: ${config.method?.toUpperCase()} ${config.url}`, {
          target: `${config.baseURL}${config.url}`,
          sslVerify: this.sslVerify
        });
        return config;
      },
      (error) => {
        logger.error('Request interceptor error:', error.message);
        return Promise.reject(error);
      }
    );

    // Add response interceptor for debugging
    client.interceptors.response.use(
      (response) => {
        logger.debug(`API Response: ${response.status} ${response.statusText}`);
        return response;
      },
      (error) => {
        logger.error('API Response error:', {
          message: error.message,
          code: error.code,
          status: error.response?.status,
          statusText: error.response?.statusText,
          url: error.config?.url
        });

        // Handle SSL specific errors
        if (error.code && error.code.includes('CERT')) {
          logger.error('SSL Certificate Error - Check OPNSENSE_SSL_VERIFY setting in .env');
        }

        return Promise.reject(error);
      }
    );

    return client;
  }

  /**
   * Make API request with retry logic and enhanced error handling
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

        logger.debug(`API Request attempt ${attempt}/${this.maxRetries}:`, {
          method,
          endpoint,
          operation,
          dataKeys: Object.keys(data),
          baseUrl: this.baseUrl
        });

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

        logger.debug('API Request successful:', {
          method,
          endpoint,
          status: response.status,
          operation
        });

        return response.data;

      } catch (error) {
        lastError = error;
        
        // Detailed error logging
        logger.warn('API request failed:', {
          method,
          endpoint,
          attempt,
          error: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText,
          responseData: error.response?.data,
          operation,
          code: error.code
        });

        // Handle SSL specific errors
        if (error.code === 'SELF_SIGNED_CERT_IN_CHAIN' || 
            error.code === 'CERT_HAS_EXPIRED' ||
            error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
            error.code === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
          logger.error('SSL Certificate Error:', {
            code: error.code,
            message: error.message,
            suggestion: 'Set OPNSENSE_SSL_VERIFY=false in .env for development'
          });
        }

        // Don't retry on client errors (4xx) except 429
        if (error.response?.status >= 400 && error.response?.status < 500 && error.response?.status !== 429) {
          break;
        }

        if (attempt < this.maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          logger.debug(`Retrying in ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    // Enhance error with context
    const enhancedError = new Error(
      `API request failed after ${this.maxRetries} attempts: ${lastError.message}`
    );
    enhancedError.originalError = lastError;
    enhancedError.endpoint = endpoint;
    enhancedError.method = method;
    enhancedError.operation = operation;
    enhancedError.statusCode = lastError.response?.status;
    
    throw enhancedError;
  }

  /**
   * Get all firewall rules using multiple API endpoints
   * OPNsense stores rules in different sections
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
          rowCount: 1000,
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
        manageable: rule.source_type !== 'system',
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
        logger.warn('Returning demo rules for development');
        return this.getDemoRules();
      }
      
      throw error;
    }
  }

  /**
   * Get firewall configuration via XML configuration dump
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
      action: rule.action || rule.type || 'pass',
      enabled: rule.enabled === '1' || rule.enabled === true,
      source: rule.source || rule.source_net || 'any',
      destination: rule.destination || rule.destination_net || 'any',
      protocol: rule.protocol || 'any',
      source_port: rule.source_port || null,
      destination_port: rule.destination_port || null,
      created: rule.created || new Date().toISOString(),
      source_type: 'filter',
      manageable: true,
      log: rule.log === '1' || rule.log === true
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
   * Toggle firewall rule (enable/disable)
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
        result = await this.toggleAutomationRule(ruleId, enabled);
      } else {
        result = await this.toggleFilterRule(ruleId, enabled);
      }

      // Apply configuration changes
      await this.applyConfigurationChanges();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      // Record metrics
      if (metricsHelpers) {
        metricsHelpers.recordConfigurationChange('firewall_rule_toggled', {
          rule_id: ruleId,
          enabled: enabled,
          rule_type: currentRule.source_type,
          user_id: this.user?.id
        });
      }

      logger.info('Firewall rule toggled successfully', {
        rule_id: ruleId,
        enabled: enabled,
        rule_type: currentRule.source_type,
        user_id: this.user?.id,
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

      if (this.alertService) {
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
      }

      throw error;
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
      if (metricsHelpers) {
        metricsHelpers.recordConfigurationChange('firewall_rule_created', {
          rule_type: useAutomationAPI ? 'automation' : 'filter',
          interface: ruleData.interface,
          action: ruleData.action,
          user_id: this.user?.id
        });
      }

      logger.info('Firewall rule created successfully', {
        rule_id: result.uuid,
        rule_type: useAutomationAPI ? 'automation' : 'filter',
        user_id: this.user?.id,
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
    // Correct format for OPNsense Filter API
    const formattedRule = {
      enabled: ruleData.enabled ? '1' : '0',
      interface: ruleData.interface || 'wan',
      direction: 'in', // OPNsense requires direction
      ipprotocol: 'inet', // IPv4
      protocol: ruleData.protocol || 'any',
      
      // Correct source/destination format for OPNsense
      source_net: this.formatAddressForOPNsense(ruleData.source),
      source_port: ruleData.source_port || '',
      destination_net: this.formatAddressForOPNsense(ruleData.destination),
      destination_port: ruleData.destination_port || '',
      
      // Correct action mapping
      type: ruleData.action || 'pass', // OPNsense uses 'type' not 'action'
      descr: ruleData.description || 'API Created Rule', // OPNsense uses 'descr'
      log: ruleData.log ? '1' : '0',
      
      // Additional fields required by OPNsense
      quick: '1', // Apply rule immediately
      floating: '0' // Not a floating rule
    };

    logger.info('Creating filter rule with formatted data:', formattedRule);

    try {
      const result = await this.makeApiRequest('POST', '/api/firewall/filter/addRule', {
        rule: formattedRule
      }, 'create_filter_rule');

      if (!result || !result.uuid) {
        throw new Error('OPNsense API did not return a valid rule UUID');
      }

      return {
        uuid: result.uuid,
        description: formattedRule.descr,
        interface: formattedRule.interface,
        action: ruleData.action,
        enabled: ruleData.enabled,
        source: this.formatAddressForOPNsense(ruleData.source),
        destination: this.formatAddressForOPNsense(ruleData.destination),
        protocol: formattedRule.protocol,
        source_type: 'filter',
        manageable: true
      };

    } catch (error) {
      logger.error('Failed to create filter rule:', {
        error: error.message,
        response: error.response?.data,
        status: error.response?.status,
        formattedRule
      });
      throw error;
    }
  }

  /**
   * Format addresses for OPNsense correctly
   */
  formatAddressForOPNsense(addressInput) {
    if (!addressInput || addressInput === 'any') {
      return 'any';
    }

    // If it's already a simple string, return it
    if (typeof addressInput === 'string') {
      return addressInput;
    }

    // If it's an object with type/network/address
    if (typeof addressInput === 'object') {
      switch (addressInput.type) {
        case 'any':
          return 'any';
        case 'network':
          return addressInput.network;
        case 'single':
          return addressInput.address;
        default:
          return 'any';
      }
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
      source: this.formatAddressForOPNsense(ruleData.source),
      destination: this.formatAddressForOPNsense(ruleData.destination),
      protocol: ruleData.protocol || 'any',
      description: ruleData.description || 'API Automation Rule',
      sequence: ruleData.sequence || 1,
      quick: true
    };

    logger.info('Creating automation rule with formatted data:', formattedRule);

    try {
      const result = await this.makeApiRequest('POST', '/api/firewall/filter_util/add', {
        rule: formattedRule
      }, 'create_automation_rule');

      return {
        uuid: result.uuid || `auto-${Date.now()}`,
        ...formattedRule,
        source_type: 'automation'
      };

    } catch (error) {
      logger.error('Failed to create automation rule:', {
        error: error.message,
        response: error.response?.data,
        status: error.response?.status,
        formattedRule
      });
      throw error;
    }
  }

  /**
   * Update existing firewall rule
   */
  async updateFirewallRule(ruleId, updates) {
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('update_rules');

      // Get existing rule
      const existingRule = await this.getFirewallRuleById(ruleId);
      if (!existingRule) {
        throw new Error(`Rule with ID ${ruleId} not found`);
      }

      if (!existingRule.manageable) {
        throw new Error('This rule cannot be modified (system rule)');
      }

      let result;
      if (existingRule.source_type === 'automation') {
        result = await this.updateAutomationRule(ruleId, updates);
      } else {
        result = await this.updateFilterRule(ruleId, updates);
      }

      // Apply configuration
      await this.applyConfigurationChanges();

      // Invalidate cache
      await this.invalidateCachePattern('firewall_rules_*');

      logger.info('Firewall rule updated successfully', {
        rule_id: ruleId,
        user_id: this.user?.id,
        username: user.username
      });

      return result;

    } catch (error) {
      logger.error('Failed to update firewall rule', {
        error: error.message,
        ruleId,
        updates,
        user_id: this.user?.id
      });
      throw error;
    }
  }

  /**
   * Update filter rule
   */
  async updateFilterRule(ruleId, updates) {
    try {
      // Get current rule
      const ruleData = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${ruleId}`, {}, 'get_filter_rule');
      
      if (!ruleData || !ruleData.rule) {
        throw new Error(`Filter rule ${ruleId} not found`);
      }

      // Merge updates with existing rule
      const updatedRule = {
        ...ruleData.rule,
        ...this.formatUpdatesForOPNsense(updates)
      };

      // Save the updated rule
      const result = await this.makeApiRequest('POST', `/api/firewall/filter/setRule/${ruleId}`, {
        rule: updatedRule
      }, 'update_filter_rule');

      return this.normalizeFilterRule(updatedRule);

    } catch (error) {
      logger.error('Failed to update filter rule', { 
        error: error.message, 
        ruleId, 
        updates 
      });
      throw error;
    }
  }

  /**
   * Update automation rule
   */
  async updateAutomationRule(ruleId, updates) {
    try {
      // Get current rule
      const ruleData = await this.makeApiRequest('GET', `/api/firewall/filter_util/get/${ruleId}`, {}, 'get_automation_rule');
      
      if (!ruleData || !ruleData.rule) {
        throw new Error(`Automation rule ${ruleId} not found`);
      }

      // Merge updates
      const updatedRule = {
        ...ruleData.rule,
        ...updates
      };

      // Save the updated rule
      const result = await this.makeApiRequest('POST', `/api/firewall/filter_util/set/${ruleId}`, {
        rule: updatedRule
      }, 'update_automation_rule');

      return this.normalizeAutomationRule(updatedRule);

    } catch (error) {
      logger.error('Failed to update automation rule', { 
        error: error.message, 
        ruleId, 
        updates 
      });
      throw error;
    }
  }

  /**
   * Format updates for OPNsense API
   */
  formatUpdatesForOPNsense(updates) {
    const formatted = {};

    if (updates.description !== undefined) {
      formatted.descr = updates.description;
    }
    if (updates.enabled !== undefined) {
      formatted.enabled = updates.enabled ? '1' : '0';
    }
    if (updates.action !== undefined) {
      formatted.type = updates.action;
    }
    if (updates.interface !== undefined) {
      formatted.interface = updates.interface;
    }
    if (updates.protocol !== undefined) {
      formatted.protocol = updates.protocol;
    }
    if (updates.source !== undefined) {
      formatted.source_net = this.formatAddressForOPNsense(updates.source);
    }
    if (updates.destination !== undefined) {
      formatted.destination_net = this.formatAddressForOPNsense(updates.destination);
    }
    if (updates.source_port !== undefined) {
      formatted.source_port = updates.source_port;
    }
    if (updates.destination_port !== undefined) {
      formatted.destination_port = updates.destination_port;
    }
    if (updates.log !== undefined) {
      formatted.log = updates.log ? '1' : '0';
    }

    return formatted;
  }

  /**
   * Delete firewall rule
   */
  async deleteFirewallRule(ruleId) {
    try {
      // Validate permissions
      const user = await this.validateUserPermissions('delete_rules');

      // Get existing rule to determine type
      const existingRule = await this.getFirewallRuleById(ruleId);
      if (!existingRule) {
        throw new Error(`Rule with ID ${ruleId} not found`);
      }

      if (!existingRule.manageable) {
        throw new Error('This rule cannot be deleted (system rule)');
      }

      let success;
      if (existingRule.source_type === 'automation') {
        success = await this.deleteAutomationRule(ruleId);
      } else {
        success = await this.deleteFilterRule(ruleId);
      }

      if (success) {
        // Apply configuration
        await this.applyConfigurationChanges();

        // Invalidate cache
        await this.invalidateCachePattern('firewall_rules_*');

        logger.info('Firewall rule deleted successfully', {
          rule_id: ruleId,
          user_id: this.user?.id,
          username: user.username
        });
      }

      return success;

    } catch (error) {
      logger.error('Failed to delete firewall rule', {
        error: error.message,
        ruleId,
        user_id: this.user?.id
      });
      throw error;
    }
  }

  /**
   * Delete filter rule
   */
  async deleteFilterRule(ruleId) {
    try {
      const result = await this.makeApiRequest('POST', `/api/firewall/filter/delRule/${ruleId}`, {}, 'delete_filter_rule');
      return result.result === 'deleted' || result.success === true;
    } catch (error) {
      logger.error('Failed to delete filter rule', { 
        error: error.message, 
        ruleId 
      });
      throw error;
    }
  }

  /**
   * Delete automation rule
   */
  async deleteAutomationRule(ruleId) {
    try {
      const result = await this.makeApiRequest('POST', `/api/firewall/filter_util/del/${ruleId}`, {}, 'delete_automation_rule');
      return result.result === 'deleted' || result.success === true;
    } catch (error) {
      logger.error('Failed to delete automation rule', { 
        error: error.message, 
        ruleId 
      });
      throw error;
    }
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

      let appliedSuccessfully = false;

      for (const endpoint of applyEndpoints) {
        try {
          const result = await this.makeApiRequest('POST', endpoint, {}, 'apply_config');
          logger.debug('Configuration applied via endpoint', { endpoint, result });
          appliedSuccessfully = true;
        } catch (error) {
          logger.warn('Apply failed for endpoint', { endpoint, error: error.message });
          // Continue to next endpoint
        }
      }

      if (!appliedSuccessfully) {
        throw new Error('Failed to apply configuration via any endpoint');
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
   * Get service health information
   */
  async getServiceHealth() {
    try {
      const startTime = Date.now();
      
      // Test basic connectivity
      const connectionTest = await this.testConnection();
      const responseTime = Date.now() - startTime;

      // Try to get system status
      let systemStatus = 'unknown';
      let systemInfo = {};
      
      try {
        const statusData = await this.makeApiRequest('GET', '/api/core/system/status', {}, 'get_system_status');
        systemStatus = 'healthy';
        systemInfo = statusData;
      } catch (error) {
        logger.warn('Could not get system status', { error: error.message });
        systemStatus = connectionTest.success ? 'degraded' : 'unhealthy';
      }

      return {
        overall_status: systemStatus,
        components: {
          api_connectivity: connectionTest.success,
          firewall_rules_accessible: await this.testFirewallAccess(),
          api_response_time_ms: responseTime
        },
        system_info: systemInfo,
        rate_limit_status: this.getRateLimitStatus(),
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      logger.error('Failed to get service health', { error: error.message });
      return {
        overall_status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Test firewall API access
   */
  async testFirewallAccess() {
    try {
      await this.makeApiRequest('GET', '/api/firewall/filter/searchRule', { 
        current: 1, 
        rowCount: 1 
      }, 'test_firewall_access');
      return true;
    } catch (error) {
      logger.warn('Firewall access test failed', { error: error.message });
      return false;
    }
  }

  /**
   * Get rate limit status
   */
  getRateLimitStatus() {
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    let totalRequests = 0;
    let activeOperations = 0;

    for (const [operation, requests] of this.rateLimitMap.entries()) {
      const validRequests = requests.filter(timestamp => now - timestamp < windowMs);
      totalRequests += validRequests.length;
      if (validRequests.length > 0) {
        activeOperations++;
      }
    }

    return {
      active_operations: activeOperations,
      total_requests_last_minute: totalRequests,
      operations: Object.fromEntries(
        Array.from(this.rateLimitMap.entries()).map(([op, requests]) => [
          op, 
          requests.filter(timestamp => now - timestamp < windowMs).length
        ])
      )
    };
  }

  /**
   * Test connection to OPNsense
   */
  async testConnection() {
    logger.info('Testing OPNsense connection', {
      baseUrl: this.baseUrl,
      sslVerify: this.sslVerify,
      timeout: this.requestTimeout
    });

    try {
      const startTime = Date.now();
      
      // Try multiple endpoints for better compatibility
      const testEndpoints = [
        '/api/core/firmware/status',
        '/api/core/system/status',
        '/api/diagnostics/interface/getInterfaceConfig'
      ];

      let lastError;
      for (const endpoint of testEndpoints) {
        try {
          const data = await this.makeApiRequest('GET', endpoint, {}, 'test_connection');
          const responseTime = Date.now() - startTime;
          
          return {
            success: true,
            response_time_ms: responseTime,
            api_version: data?.api_version || 'unknown',
            system_version: data?.version || data?.product_version || 'unknown',
            endpoint_used: endpoint,
            timestamp: new Date().toISOString()
          };
        } catch (error) {
          lastError = error;
          logger.debug(`Test endpoint ${endpoint} failed:`, error.message);
          continue;
        }
      }

      throw lastError;

    } catch (error) {
      logger.error('OPNsense connection test failed', {
        error: error.message,
        code: error.code,
        status: error.response?.status
      });

      return {
        success: false,
        error: error.message,
        status_code: error.response?.status,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Enhanced rule data validation
   */
  validateRuleData(ruleData) {
    const requiredFields = ['interface', 'action', 'description'];
    const validActions = ['pass', 'block', 'reject'];
    const validInterfaces = ['wan', 'lan', 'opt1', 'opt2', 'opt3', 'dmz'];
    const validProtocols = ['tcp', 'udp', 'icmp', 'any'];

    // Check required fields
    for (const field of requiredFields) {
      if (!ruleData[field]) {
        throw new Error(`Required field missing: ${field}`);
      }
    }

    // Validate values
    if (!validActions.includes(ruleData.action)) {
      throw new Error(`Invalid action. Must be one of: ${validActions.join(', ')}`);
    }

    if (!validInterfaces.includes(ruleData.interface)) {
      throw new Error(`Invalid interface. Must be one of: ${validInterfaces.join(', ')}`);
    }

    if (ruleData.protocol && !validProtocols.includes(ruleData.protocol)) {
      throw new Error(`Invalid protocol. Must be one of: ${validProtocols.join(', ')}`);
    }

    // Check description length
    if (ruleData.description && ruleData.description.length > 255) {
      throw new Error('Description too long (max 255 characters)');
    }

    // Validate address formats
    if (ruleData.source && typeof ruleData.source === 'object') {
      this.validateAddressObject(ruleData.source, 'source');
    }

    if (ruleData.destination && typeof ruleData.destination === 'object') {
      this.validateAddressObject(ruleData.destination, 'destination');
    }
  }

  /**
   * Validate address objects
   */
  validateAddressObject(addressObj, fieldName) {
    const validTypes = ['any', 'network', 'single'];
    
    if (!addressObj.type || !validTypes.includes(addressObj.type)) {
      throw new Error(`${fieldName} type must be one of: ${validTypes.join(', ')}`);
    }

    if (addressObj.type === 'network' && !addressObj.network) {
      throw new Error(`${fieldName} of type 'network' must specify 'network'`);
    }

    if (addressObj.type === 'single' && !addressObj.address) {
      throw new Error(`${fieldName} of type 'single' must specify 'address'`);
    }

    // Basic IP/CIDR format validation
    if (addressObj.network) {
      if (!this.isValidNetworkFormat(addressObj.network)) {
        throw new Error(`${fieldName} network has invalid format: ${addressObj.network}`);
      }
    }

    if (addressObj.address) {
      if (!this.isValidIPFormat(addressObj.address)) {
        throw new Error(`${fieldName} address has invalid format: ${addressObj.address}`);
      }
    }
  }

  /**
   * Validate CIDR network format
   */
  isValidNetworkFormat(network) {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    return cidrRegex.test(network);
  }

  /**
   * Validate IP format
   */
  isValidIPFormat(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipRegex.test(ip);
  }

  /**
   * Validate user permissions
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

    if (user.hasPermission && !user.hasPermission(action)) {
      throw new Error(`User does not have permission to ${action}`);
    }

    return user;
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
        created_via: 'Demo',
        created: new Date().toISOString(),
        log: true
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
        destination_port: '22',
        source_type: 'demo',
        manageable: true,
        created_via: 'Demo',
        created: new Date().toISOString(),
        log: false
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
        created_via: 'Demo',
        created: new Date().toISOString(),
        log: true
      }
    ];
  }

  /**
   * Cache management methods
   */
  async safeGetCache(key) {
    try {
      if (cache && cache.get) {
        return await cache.get(key);
      }
      return null;
    } catch (error) {
      logger.warn('Cache get failed', { key, error: error.message });
      return null;
    }
  }

  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      if (cache && cache.set) {
        await cache.set(key, value, ttl);
      }
    } catch (error) {
      logger.warn('Cache set failed', { key, error: error.message });
    }
  }

  async invalidateCachePattern(pattern) {
    try {
      if (cache && cache.keys && cache.del) {
        const keys = await cache.keys(pattern);
        if (keys.length > 0) {
          await cache.del(keys);
          logger.info('Cache invalidated', { pattern, keys_count: keys.length });
        }
      }
    } catch (error) {
      logger.warn('Cache invalidation failed', { pattern, error: error.message });
    }
  }
}

module.exports = OpnsenseService;