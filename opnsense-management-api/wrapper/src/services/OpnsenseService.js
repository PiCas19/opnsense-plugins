const axios = require('axios');
const https = require('https');
const { parseStringPromise } = require('xml2js');

const logger = require('../utils/logger');
const { opnsenseConfig } = require('../config/opnsense');
const { cache, sequelize } = require('../config/database');
const { metricsHelpers } = require('../config/monitoring');
const AlertService = require('./AlertService');
const User = require('../models/User');

class OpnsenseService {
  constructor(user = null) {
    this.user = user;
    this.baseUrl = opnsenseConfig.apiUrl;
    this.apiKey = opnsenseConfig.apiKey;
    this.apiSecret = opnsenseConfig.apiSecret;
    this.allowSelfSigned = !!opnsenseConfig.allowSelfSigned;
    this.alertService = new AlertService(user);
    this.cacheTimeout = Number(process.env.OPNSENSE_CACHE_TIMEOUT || 60);
    this.maxRetries = Number(process.env.MAX_API_RETRIES || 3);
    this.requestTimeout = Number(process.env.API_REQUEST_TIMEOUT || 10000);
    this.rateLimitMap = new Map();
  }

  // ---------------- infra helpers ----------------

  checkRateLimit(operation, maxRequests = 60) {
    const now = Date.now();
    const windowMs = 60000;
    if (!this.rateLimitMap.has(operation)) this.rateLimitMap.set(operation, []);
    const valid = this.rateLimitMap.get(operation).filter(ts => now - ts < windowMs);
    if (valid.length >= maxRequests) {
      logger.warn('Rate limit exceeded', { operation, requests_count: valid.length });
      return false;
    }
    valid.push(now);
    this.rateLimitMap.set(operation, valid);
    return true;
  }

  async safeGetCache(key) {
    try {
      return await cache.get(key);
    } catch (e) {
      logger.warn('Cache get failed', { key, error: e.message });
      return null;
    }
  }

  async safeSetCache(key, value, ttl = this.cacheTimeout) {
    try {
      await cache.set(key, value, ttl);
    } catch (e) {
      logger.warn('Cache set failed', { key, error: e.message });
    }
  }

  async invalidateCachePattern(pattern) {
    try {
      const keys = await cache.keys(pattern);
      if (keys.length) {
        await cache.del(keys);
        logger.info('Cache invalidated', { pattern, keys_count: keys.length });
      }
    } catch (e) {
      logger.warn('Cache invalidation failed', { pattern, error: e.message });
    }
  }

  getHttpClient() {
    const httpsAgent = new https.Agent({
      rejectUnauthorized: !this.allowSelfSigned,
    });
    return axios.create({
      baseURL: this.baseUrl,
      auth: { username: this.apiKey, password: this.apiSecret },
      timeout: this.requestTimeout,
      maxRedirects: 0,
      httpsAgent,
    });
  }

  async makeApiRequest(method, endpoint, data = {}, operation = 'default') {
    if (!this.checkRateLimit(operation)) {
      throw new Error(`Rate limit exceeded for operation: ${operation}`);
    }

    const wantsText =
      endpoint.includes('/core/backup/download/this') ||
      endpoint.includes('/backup/backup/download');

    let lastError;
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const client = this.getHttpClient();

        if (method.toLowerCase() === 'get') {
          const res = await client.get(endpoint, {
            params: data,
            responseType: wantsText ? 'text' : 'json',
          });
          return res.data;
        }
        if (method.toLowerCase() === 'post') {
          const res = await client.post(endpoint, data);
          return res.data;
        }
        if (method.toLowerCase() === 'put') {
          const res = await client.put(endpoint, data);
          return res.data;
        }
        if (method.toLowerCase() === 'delete') {
          const res = await client.delete(endpoint);
          return res.data;
        }
        throw new Error(`Unsupported HTTP method: ${method}`);
      } catch (error) {
        lastError = error;
        const status = error.response?.status;
        logger.warn('API request failed', {
          method,
          endpoint,
          attempt,
          status,
          error: error.message,
        });

        // 4xx non si ritenta
        if (status >= 400 && status < 500) break;

        if (attempt < this.maxRetries) {
          const delay = Math.min(1000 * 2 ** attempt, 10000);
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }
    throw lastError;
  }

  // ---------------- validation/auth ----------------

  validateRuleData(ruleData) {
    const requiredFields = ['interface', 'action', 'description'];
    const validActions = ['pass', 'block', 'reject'];
    const validInterfaces = ['wan', 'lan', 'opt1', 'opt2', 'opt3'];

    for (const f of requiredFields) if (!ruleData[f]) throw new Error(`${f} is required`);
    if (!validActions.includes(ruleData.action)) {
      throw new Error(`Invalid action. Must be one of: ${validActions.join(', ')}`);
    }
    if (!validInterfaces.includes(ruleData.interface)) {
      throw new Error(`Invalid interface. Must be one of: ${validInterfaces.join(', ')}`);
    }
    if (ruleData.description && ruleData.description.length > 255) {
      throw new Error('Description too long (max 255 characters)');
    }
    const ipRe = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (ruleData.source && ruleData.source !== 'any' && !ipRe.test(ruleData.source)) {
      throw new Error('Invalid source IP/CIDR format');
    }
    if (ruleData.destination && ruleData.destination !== 'any' && !ipRe.test(ruleData.destination)) {
      throw new Error('Invalid destination IP/CIDR format');
    }
  }

  async validateUserPermissions(action) {
    if (!this.user) throw new Error('User authentication required');
    const user = await User.findByPk(this.user.id);
    if (!user) throw new Error('User not found');
    if (!user.is_active) throw new Error('User account is disabled');
    if (user.isAccountLocked()) throw new Error('User account is locked');
    if (!user.hasPermission(action)) throw new Error(`User does not have permission to ${action}`);
    return user;
  }

  // ---------------- CORE RULES via config.xml ----------------

  async _fetchConfigXmlCached(ttl = Math.min(this.cacheTimeout, 30)) {
    const key = 'opnsense_config_xml';
    const cached = await this.safeGetCache(key);
    if (cached) {
      logger.info('Returning cached config.xml');
      return cached;
    }

    let xml;
    try {
      xml = await this.makeApiRequest('GET', '/core/backup/download/this', {}, 'download_config');
    } catch (e) {
      const status = e.response?.status;
      if (status === 403) {
        throw new Error(
          'OPNsense denied access to download config (403). Grant the API user permission to download configuration.'
        );
      }
      throw e;
    }

    if (typeof xml !== 'string' || !xml.includes('<opnsense')) {
      throw new Error('Unexpected config.xml content');
    }

    await this.safeSetCache(key, xml, ttl);
    return xml;
  }

  _normalizeCoreRule(rule, idx = 0) {
    // enabled se il tag <disabled> NON c'è; disabled se <disabled>1</disabled> o <disabled/>
    const toBool = v => v === '1' || v === 1 || v === true;
    const hasDisabled = Object.prototype.hasOwnProperty.call(rule, 'disabled');
    const isDisabled = hasDisabled && (rule.disabled === '' || toBool(rule.disabled));
    const enabled = !isDisabled;

    const pickEp = (node = {}) => {
      if ('any' in node && toBool(node.any)) return { type: 'any', value: 'any', port: null };
      if (node.address) return { type: 'address', value: node.address, port: node.port ?? null };
      if (node.network) return { type: 'network', value: node.network, port: node.port ?? null };
      return { type: null, value: null, port: null };
    };

    const uuid = rule?.$?.uuid || rule?.uuid || rule?.tracker || `rule_${idx}`;

    return {
      uuid,
      interface: rule?.interface || null,
      action: rule?.type || rule?.action || null,
      enabled,
      protocol: rule?.protocol || null,
      ipprotocol: rule?.ipprotocol || null,
      direction: rule?.direction || null,
      quick: toBool(rule?.quick || '0'),
      statetype: rule?.statetype || null,
      log: toBool(rule?.log || '0'),
      description: rule?.descr || rule?.description || '',
      source: (function s() { return pickEp(rule.source); })(),
      destination: (function d() { return pickEp(rule.destination); })(),
      associated_rule_id: rule?.['associated-rule-id'] || null,
      created_at: rule?.created?.time || null,
      updated_at: rule?.updated?.time || null,
    };
  }

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

    // paginazione lato service
    const page = Number.isInteger(filters.page) ? filters.page : 1;
    const limit = Number.isInteger(filters.limit) ? filters.limit : list.length || 1000;
    const start = (page - 1) * limit;
    const end = start + limit;

    return { rows: list.slice(start, end), total: list.length, page, limit };
  }

  async getFirewallRules(filters = {}) {
    try {
      const key = `core_rules_${JSON.stringify({
        page: filters.page ?? 1,
        limit: filters.limit ?? 1000,
        interface: filters.interface ?? null,
        enabled: typeof filters.enabled === 'boolean' ? filters.enabled : null,
        action: filters.action ?? null,
        search: filters.search ?? null,
      })}`;
      const cached = await this.safeGetCache(key);
      if (cached) return cached;

      const result = await this._loadCoreRulesFromConfig(filters);
      await this.safeSetCache(key, result, this.cacheTimeout);
      return result; // { rows, total, page, limit }
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

  async getFirewallRuleById(uuid) {
    const { rows } = await this._loadCoreRulesFromConfig({});
    return rows.find(r => r.uuid === uuid) || null;
  }

  // ------------- le operazioni qui sotto sono lasciate come prima -------------

  async createFirewallRule(ruleData) {
    const transaction = await sequelize.transaction();
    try {
      const user = await this.validateUserPermissions('create_rules');
      this.validateRuleData(ruleData);

      const data = await this.makeApiRequest('POST', '/firewall/filter/add', ruleData, 'create_rule');
      const newRule = data?.rule;
      if (!newRule || !newRule.uuid) throw new Error('Invalid response from OPNsense API');

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
      logger.error('Failed to create firewall rule', { error: error.message, ruleData, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to create firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { ruleData, error_type: 'api_failure', endpoint: '/firewall/filter/add' },
      });
      throw error;
    }
  }

  async updateFirewallRule(ruleId, ruleData) {
    const transaction = await sequelize.transaction();
    try {
      if (!ruleId || typeof ruleId !== 'string') throw new Error('Valid rule ID is required');
      const user = await this.validateUserPermissions('update_rules');
      this.validateRuleData(ruleData);

      const data = await this.makeApiRequest('POST', `/firewall/filter/set/${ruleId}`, ruleData, 'update_rule');
      const updatedRule = data?.rule;
      if (!updatedRule) throw new Error('Invalid response from OPNsense API');

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
      logger.error('Failed to update firewall rule', { error: error.message, rule_id: ruleId, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to update firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { ruleId, ruleData, error_type: 'api_failure', endpoint: `/firewall/filter/set/${ruleId}` },
      });
      throw error;
    }
  }

  async deleteFirewallRule(ruleId) {
    const transaction = await sequelize.transaction();
    try {
      if (!ruleId || typeof ruleId !== 'string') throw new Error('Valid rule ID is required');
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
      logger.error('Failed to delete firewall rule', { error: error.message, rule_id: ruleId, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to delete firewall rule: ${error.message}`,
        severity: 'high',
        source: 'opnsense',
        metadata: { ruleId, error_type: 'api_failure', endpoint: `/firewall/filter/delete/${ruleId}` },
      });
      throw error;
    }
  }

  async getInterfaceConfigurations() {
    try {
      const key = 'interface_configurations';
      const cached = await this.safeGetCache(key);
      if (cached) {
        logger.info('Returning cached interface configurations', { cache_key: key });
        return cached;
      }

      const data = await this.makeApiRequest('GET', '/interfaces/settings', {}, 'get_interfaces');
      const interfaces = data?.interfaces || [];
      const validated = interfaces.filter(intf => intf && typeof intf === 'object' && intf.name);

      await this.safeSetCache(key, validated, this.cacheTimeout);

      logger.info('Interface configurations retrieved and cached', {
        cache_key: key,
        interfaces_count: validated.length,
      });

      return validated;
    } catch (error) {
      logger.error('Failed to get interface configurations', { error: error.message, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to retrieve interface configurations: ${error.message}`,
        severity: 'medium',
        source: 'opnsense',
        metadata: { error_type: 'api_failure', endpoint: '/interfaces/settings' },
      });
      throw error;
    }
  }

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
      logger.error('Failed to apply configuration changes', { error: error.message, user_id: this.user?.id });
      await this.alertService.createSystemAlert({
        type: 'configuration_error',
        message: `Failed to apply configuration changes: ${error.message}`,
        severity: 'critical',
        source: 'opnsense',
        metadata: { error_type: 'api_failure', endpoint: '/firewall/filter/apply' },
      });
      throw error;
    }
  }

  async testConnection() {
    try {
      const t0 = Date.now();
      const data = await this.makeApiRequest('GET', '/core/system/status', {}, 'test_connection');
      const dt = Date.now() - t0;

      const result = {
        success: true,
        response_time_ms: dt,
        api_version: data?.api_version || 'unknown',
        system_version: data?.version || 'unknown',
        timestamp: new Date(),
      };

      logger.info('OPNsense connection test successful', { response_time_ms: dt, user_id: this.user?.id });
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

  async getServiceHealth() {
    try {
      const cacheKey = 'opnsense_service_health';
      const cached = await this.safeGetCache(cacheKey);
      if (cached) {
        logger.info('Returning cached service health', { cache_key: cacheKey });
        return cached;
      }

      const checks = await Promise.allSettled([
        this.testConnection(),
        this.getFirewallRules({}).catch(() => null),
      ]);

      const conn = checks[0].status === 'fulfilled' ? checks[0].value : null;
      const rules = checks[1].status === 'fulfilled' ? checks[1].value : null;

      const health = {
        overall_status: conn?.success && rules ? 'healthy' : 'unhealthy',
        timestamp: new Date(),
        components: {
          api_connectivity: conn?.success || false,
          firewall_rules_accessible: !!rules,
          api_response_time_ms: conn?.response_time_ms || null,
        },
        rate_limit_status: {
          active_operations: this.rateLimitMap.size,
          total_requests_last_minute: Array.from(this.rateLimitMap.values())
            .flat()
            .filter(ts => Date.now() - ts < 60000).length,
        },
      };

      await this.safeSetCache(cacheKey, health, 30);
      return health;
    } catch (error) {
      logger.error('Failed to get service health', { error: error.message, user_id: this.user?.id });
      return { overall_status: 'unhealthy', timestamp: new Date(), error: error.message };
    }
  }
}

module.exports = OpnsenseService;