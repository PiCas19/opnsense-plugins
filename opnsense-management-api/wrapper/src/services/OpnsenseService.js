const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { opnsenseConfig, createSecureHttpsAgent } = require('../config/opnsense');
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

    // SSL verification configuration
    this.sslVerify = process.env.OPNSENSE_SSL_VERIFY === 'true';
    
    logger.info('OPNsense Service Configuration:', {
      baseUrl: this.baseUrl,
      hasApiKey: !!this.apiKey,
      hasApiSecret: !!this.apiSecret,
      sslVerify: this.sslVerify,
      timeout: this.requestTimeout,
      retries: this.maxRetries,
      customCert: !!(process.env.OPNSENSE_CA_CERT_PATH || process.env.NODE_EXTRA_CA_CERTS)
    });

    // Usa l'HTTPS agent sicuro dalla configurazione
    this.httpsAgent = this.createHttpsAgent();
  }

  /**
   * Crea HTTPS agent con configurazione SSL corretta
   * @private
   */
  createHttpsAgent() {
    try {
      // Usa la funzione sicura dal config
      const agent = createSecureHttpsAgent();
      
      // Log della configurazione SSL effettiva
      const agentConfig = {
        rejectUnauthorized: agent.options.rejectUnauthorized,
        hasCustomCA: !!agent.options.ca,
        sslVerifyEnv: process.env.OPNSENSE_SSL_VERIFY,
        customCertPath: process.env.OPNSENSE_CA_CERT_PATH || process.env.NODE_EXTRA_CA_CERTS
      };
      
      logger.info('HTTPS Agent configured:', agentConfig);
      
      return agent;
    } catch (error) {
      logger.error('Failed to create HTTPS agent:', error.message);
      
      // Fallback sicuro
      return new https.Agent({
        rejectUnauthorized: this.sslVerify,
        keepAlive: true,
        keepAliveMsecs: 30000,
        maxSockets: 10
      });
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
          sslVerify: this.sslVerify,
          hasCustomCert: !!this.httpsAgent.options.ca
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
        // Enhanced SSL error handling
        if (error.code && (
          error.code.includes('CERT') ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        )) {
          logger.error('SSL Certificate Error in OpnsenseService:', {
            code: error.code,
            message: error.message,
            url: error.config?.url,
            sslVerify: this.sslVerify,
            customCertPath: process.env.OPNSENSE_CA_CERT_PATH || process.env.NODE_EXTRA_CA_CERTS,
            suggestion: this.sslVerify ? 
              'Check certificate configuration or set OPNSENSE_SSL_VERIFY=false' : 
              'SSL verification is disabled but still getting certificate errors'
          });
        } else {
          logger.error('API Response error:', {
            message: error.message,
            code: error.code,
            status: error.response?.status,
            statusText: error.response?.statusText,
            url: error.config?.url
          });
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

        // Handle SSL specific errors - don't retry on certificate issues
        if (error.code && (
          error.code.includes('CERT') ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        )) {
          logger.error('SSL Certificate Error - stopping retries:', {
            code: error.code,
            message: error.message,
            suggestion: 'Check SSL configuration in environment variables'
          });
          break;
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
   * Test connection to OPNsense
   */
  async testConnection() {
    logger.info('Testing OPNsense connection', {
      baseUrl: this.baseUrl,
      sslVerify: this.sslVerify,
      timeout: this.requestTimeout,
      hasCustomCert: !!this.httpsAgent.options.ca
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
            ssl_config: {
              verify: this.sslVerify,
              custom_cert: !!this.httpsAgent.options.ca,
              cert_path: process.env.OPNSENSE_CA_CERT_PATH || process.env.NODE_EXTRA_CA_CERTS
            },
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
        status: error.response?.status,
        ssl_config: {
          verify: this.sslVerify,
          custom_cert: !!this.httpsAgent.options.ca
        }
      });

      return {
        success: false,
        error: error.message,
        status_code: error.response?.status,
        ssl_config: {
          verify: this.sslVerify,
          custom_cert: !!this.httpsAgent.options.ca,
          cert_path: process.env.OPNSENSE_CA_CERT_PATH || process.env.NODE_EXTRA_CA_CERTS
        },
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