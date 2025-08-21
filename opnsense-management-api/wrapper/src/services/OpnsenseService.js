// services/opnsense.service.js (o dove lo hai tu)
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const config = require('../config/opnsense');
const logger = require('../utils/logger');

class OpnsenseService {
  constructor() {
    this.baseUrl = config.host;            // es. https://opnsense.localdomain
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.maxRetries = 3;
    this.requestTimeout = config.timeout || 15000;
    this.rateLimitMap = new Map();

    // Modalità TLS
    this.verifySSL = !!config.verifySSL;   // true => verifica certificati; false => disabilita TLS verify
    this.ca = this._readOptionalFile(config.ssl?.ca);
    this.cert = this._readOptionalFile(config.ssl?.cert);
    this.key = this._readOptionalFile(config.ssl?.key);

    // Prepara httpsAgent SOLO se serve davvero
    this.httpsAgent = this._buildHttpsAgent();

    logger.info('OPNsense Service initialized', {
      baseUrl: this.baseUrl,
      hasApiKey: !!this.apiKey,
      hasApiSecret: !!this.apiSecret,
      sslVerify: this.verifySSL,
      caLoaded: !!this.ca,
      clientCertLoaded: !!this.cert && !!this.key,
      timeout: this.requestTimeout
    });
  }

  _readOptionalFile(p) {
    if (!p) return undefined;
    try {
      const abs = path.isAbsolute(p) ? p : path.resolve(process.cwd(), p);
      return fs.readFileSync(abs);
    } catch (e) {
      logger.warn('Unable to read SSL file', { file: p, error: e.message });
      return undefined;
    }
  }

  _buildHttpsAgent() {
    try {
      const url = new URL(this.baseUrl);
      const isHttps = url.protocol === 'https:';

      if (!isHttps) {
        // HTTP puro: nessun agent
        return undefined;
      }

      if (!this.verifySSL) {
        // HTTPS ma senza verifica: niente agent custom; disattivo la verifica globalmente
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        logger.warn('TLS verification DISABLED (NODE_TLS_REJECT_UNAUTHORIZED=0)');
        return undefined; // nessun agent -> usa quello di default di Node con verify off
      }

      // HTTPS con verifica: agent "rigoroso"
      return new https.Agent({
        rejectUnauthorized: true,
        ca: this.ca,           // CA opzionale
        cert: this.cert,       // mTLS opzionale
        key: this.key,         // mTLS opzionale
        keepAlive: true,
        keepAliveMsecs: 30000,
        maxSockets: 10,
        timeout: 5000
      });
    } catch (e) {
      logger.warn('Failed to build HTTPS agent; falling back to default', { error: e.message });
      return undefined;
    }
  }

  /**
   * Rate limiting
   */
  checkRateLimit(operation, maxRequests = 60) {
    const now = Date.now();
    const windowMs = 60000;

    if (!this.rateLimitMap.has(operation)) {
      this.rateLimitMap.set(operation, []);
    }
    const requests = this.rateLimitMap.get(operation);
    const valid = requests.filter(t => now - t < windowMs);

    if (valid.length >= maxRequests) {
      logger.warn('Rate limit exceeded', { operation, requests_count: valid.length });
      return false;
    }
    valid.push(now);
    this.rateLimitMap.set(operation, valid);
    return true;
  }

  /**
   * Client Axios
   */
  getHttpClient() {
    const client = axios.create({
      baseURL: this.baseUrl,
      httpsAgent: this.httpsAgent, // undefined se verifySSL=false o se HTTP
      auth: { username: this.apiKey, password: this.apiSecret },
      timeout: this.requestTimeout,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'OPNsense-Firewall-API/1.0'
      },
      validateStatus: (s) => s < 600
    });

    // Request interceptor
    client.interceptors.request.use(
      (cfg) => {
        const method = (cfg.method || 'get').toUpperCase();
        logger.debug(`API Request: ${method} ${cfg.url}`, {
          target: `${cfg.baseURL}${cfg.url}`,
          sslVerify: this.verifySSL
        });
        return cfg;
      },
      (error) => {
        logger.error('Request interceptor error:', error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    client.interceptors.response.use(
      (response) => {
        logger.debug(`API Response: ${response.status} ${response.statusText}`, {
          url: response.config.url,
          method: response.config.method
        });
        return response;
      },
      (error) => {
        if (error.code && (
          error.code.includes('CERT') ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        )) {
          logger.error('SSL Certificate Error:', {
            code: error.code,
            message: error.message,
            url: error.config?.url,
            suggestion: this.verifySSL
              ? 'Carica la CA corretta o usa NODE_EXTRA_CA_CERTS'
              : 'Hai verifySSL=false: non dovresti vedere errori SSL'
          });
        } else {
          logger.error('API Response error:', {
            message: error.message,
            code: error.code,
            status: error.response?.status,
            statusText: error.response?.statusText,
            url: error.config?.url,
            data: error.response?.data
          });
        }
        return Promise.reject(error);
      }
    );

    return client;
  }

  /**
   * Wrapper richieste con retry
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

        logger.debug(`API Request attempt ${attempt}/${this.maxRetries}`, {
          method, endpoint, operation, dataKeys: Object.keys(data)
        });

        // Alcuni endpoint OPNsense richiedono POST anche per "search"
        const mustPostJson = endpoint === '/api/firewall/filter/searchRule';

        switch (method.toLowerCase()) {
          case 'get':
            response = mustPostJson
              ? await client.post(endpoint, this._normalizeSearchPayload(data))
              : await client.get(endpoint, { params: data });
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

        if (response.status >= 400) {
          // Non alzare qui: lascia alla logica sotto decidere se fare retry
          throw this._httpError(response, `HTTP ${response.status}`);
        }

        logger.debug('API Request successful', {
          method, endpoint, status: response.status, operation
        });

        return response.data;

      } catch (error) {
        lastError = error;

        logger.warn('API request failed', {
          method, endpoint, attempt,
          error: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText,
          operation, code: error.code
        });

        // Stop retry per errori SSL
        if (error.code && (
          error.code.includes('CERT') ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        )) {
          logger.error('SSL Certificate Error - stopping retries');
          break;
        }

        // Stop retry su 4xx (eccetto 429)
        if (error.response?.status >= 400 && error.response?.status < 500 && error.response?.status !== 429) {
          break;
        }

        if (attempt < this.maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          logger.debug(`Retrying in ${delay}ms...`);
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }

    const enhancedError = new Error(
      `API request failed after ${this.maxRetries} attempts: ${lastError?.message || 'unknown error'}`
    );
    enhancedError.originalError = lastError;
    enhancedError.endpoint = endpoint;
    enhancedError.method = method;
    enhancedError.operation = operation;
    enhancedError.statusCode = lastError?.response?.status;

    throw enhancedError;
  }

  _normalizeSearchPayload(data) {
    return {
      current: Number(data.current) || 1,
      rowCount: Number(data.rowCount) || 50,
      sort: data.sort || {},
      searchPhrase: data.searchPhrase || ''
    };
  }

  _httpError(response, message) {
    const err = new Error(message);
    err.response = response;
    return err;
  }

  /** -------------------- Operazioni di servizio -------------------- **/

  async testConnection() {
    logger.info('Testing OPNsense connection', {
      baseUrl: this.baseUrl,
      sslVerify: this.verifySSL,
      timeout: this.requestTimeout
    });

    try {
      const startTime = Date.now();
      const testEndpoints = [
        '/api/core/firmware/status',
        '/api/core/system/status',
        '/api/diagnostics/interface/getInterfaceConfig',
        '/api/firewall/filter/searchRule'
      ];

      let lastError;
      for (const endpoint of testEndpoints) {
        try {
          const method = (endpoint === '/api/firewall/filter/searchRule') ? 'POST' : 'GET';
          const payload = (method === 'POST') ? this._normalizeSearchPayload({ current: 1, rowCount: 1 }) : {};
          const data = await this.makeApiRequest(method, endpoint, payload, 'test_connection');
          const responseTime = Date.now() - startTime;

          return {
            success: true,
            response_time_ms: responseTime,
            api_version: data?.api_version || 'unknown',
            system_version: data?.version || data?.product_version || 'unknown',
            endpoint_used: endpoint,
            timestamp: new Date().toISOString(),
            ssl_config: {
              verify: this.verifySSL,
              ca_loaded: !!this.ca,
              client_cert_loaded: !!this.cert && !!this.key
            }
          };
        } catch (err) {
          lastError = err;
          logger.debug(`Test endpoint ${endpoint} failed: ${err.message}`);
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
        timestamp: new Date().toISOString(),
        ssl_config: {
          verify: this.verifySSL,
          ca_loaded: !!this.ca,
          client_cert_loaded: !!this.cert && !!this.key
        }
      };
    }
  }

  async getRules() {
    try {
      logger.info('Fetching firewall rules from OPNsense...');
      const filterData = await this.makeApiRequest(
        'POST',
        '/api/firewall/filter/searchRule',
        this._normalizeSearchPayload({ current: 1, rowCount: 1000 }),
        'get_filter_rules'
      );

      logger.debug('Filter searchRule API response:', {
        hasData: !!filterData,
        hasRows: !!(filterData && filterData.rows),
        rowCount: filterData?.rows?.length || 0
      });

      if (!filterData || !filterData.rows) {
        logger.warn('No rules found in OPNsense response');
        return { success: true, data: [], total: 0 };
      }

      const rules = filterData.rows.map((r) => this.normalizeRule(r));
      logger.info('Successfully retrieved firewall rules from OPNsense', {
        total_rules: rules.length
      });

      return {
        success: true,
        data: rules,
        total: filterData.rowCount || rules.length
      };
    } catch (error) {
      logger.error('Failed to get firewall rules', { error: error.message });
      throw new Error(`Errore nel recupero regole: ${error.message}`);
    }
  }

  async getRule(uuid) {
    try {
      const response = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${uuid}`, {}, 'get_rule');
      if (!response || !response.rule) throw new Error('Regola non trovata');
      return { success: true, data: this.normalizeRule(response.rule) };
    } catch (error) {
      logger.error('Errore nel recupero regola', { uuid, error: error.message });
      throw new Error(`Errore nel recupero regola: ${error.message}`);
    }
  }

  async createRule(ruleData) {
    try {
      this.validateRuleData(ruleData);
      const formattedRule = this.formatRuleForOPNsense(ruleData);
      logger.info('Creating filter rule with formatted data:', formattedRule);

      const response = await this.makeApiRequest('POST', '/api/firewall/filter/addRule', { rule: formattedRule }, 'create_rule');
      if (!response || !response.uuid) throw new Error('OPNsense API non ha restituito un UUID valido');

      await this.applyConfig();
      return { success: true, uuid: response.uuid, message: 'Regola creata con successo' };
    } catch (error) {
      logger.error('Errore nella creazione regola', { ruleData, error: error.message });
      throw new Error(`Errore nella creazione regola: ${error.message}`);
    }
  }

  async updateRule(uuid, ruleData) {
    try {
      this.validateRuleData(ruleData);
      const existing = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${uuid}`, {}, 'get_rule');
      if (!existing || !existing.rule) throw new Error('Regola non trovata');

      const updatedRule = { ...existing.rule, ...this.formatRuleForOPNsense(ruleData) };
      const response = await this.makeApiRequest('POST', `/api/firewall/filter/setRule/${uuid}`, { rule: updatedRule }, 'update_rule');
      if (!response || response.result !== 'saved') throw new Error('Errore nell\'aggiornamento della regola');

      await this.applyConfig();
      return { success: true, message: 'Regola aggiornata con successo' };
    } catch (error) {
      logger.error('Errore nell\'aggiornamento regola', { uuid, ruleData, error: error.message });
      throw new Error(`Errore nell'aggiornamento regola: ${error.message}`);
    }
  }

  async deleteRule(uuid) {
    try {
      const response = await this.makeApiRequest('POST', `/api/firewall/filter/delRule/${uuid}`, {}, 'delete_rule');
      if (!response || response.result !== 'deleted') throw new Error('Errore nell\'eliminazione della regola');

      await this.applyConfig();
      return { success: true, message: 'Regola eliminata con successo' };
    } catch (error) {
      logger.error('Errore nell\'eliminazione regola', { uuid, error: error.message });
      throw new Error(`Errore nell'eliminazione regola: ${error.message}`);
    }
  }

  async toggleRule(uuid, enabled = true) {
    try {
      const existing = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${uuid}`, {}, 'get_rule');
      if (!existing || !existing.rule) throw new Error('Regola non trovata');

      const updatedRule = { ...existing.rule, enabled: enabled ? '1' : '0' };
      const response = await this.makeApiRequest('POST', `/api/firewall/filter/setRule/${uuid}`, { rule: updatedRule }, 'toggle_rule');
      if (!response || response.result !== 'saved') throw new Error('Errore nel cambio stato regola');

      await this.applyConfig();
      return { success: true, message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} con successo` };
    } catch (error) {
      logger.error('Errore nel toggle regola', { uuid, enabled, error: error.message });
      throw new Error(`Errore nel cambio stato regola: ${error.message}`);
    }
  }

  async applyConfig() {
    try {
      const response = await this.makeApiRequest('POST', '/api/firewall/filter/apply', {}, 'apply_config');
      if (!response || response.status !== 'ok') throw new Error('Errore nell\'applicazione configurazione');
      await new Promise(r => setTimeout(r, 1000));
      logger.info('Configurazione firewall applicata con successo');
      return true;
    } catch (error) {
      logger.error('Errore nell\'applicazione configurazione', { error: error.message });
      throw new Error(`Errore nell'applicazione configurazione: ${error.message}`);
    }
  }

  /* ---------- Helpers regole ---------- */

  normalizeRule(rule) {
    return {
      uuid: rule.uuid || rule.id,
      description: rule.description || rule.descr || 'Unnamed Rule',
      interface: rule.interface || 'wan',
      action: rule.action || rule.type || 'pass',
      enabled: rule.enabled === '1' || rule.enabled === true,
      source: rule.source || rule.source_net || 'any',
      destination: rule.destination || rule.destination_net || 'any',
      protocol: rule.protocol || rule.ipprotocol || 'any',
      source_port: rule.source_port || rule.src_port || null,
      destination_port: rule.destination_port || rule.dst_port || null,
      log: rule.log === '1' || rule.log === true,
      created: rule.created || new Date().toISOString(),
      sequence: rule.sequence || 1000,
      direction: rule.direction || 'in'
    };
  }

  formatRuleForOPNsense(ruleData) {
    return {
      enabled: ruleData.enabled ? '1' : '0',
      interface: ruleData.interface || 'wan',
      direction: ruleData.direction || 'in',
      ipprotocol: 'inet',
      protocol: ruleData.protocol || 'any',
      type: ruleData.action || 'pass',
      description: ruleData.description || 'API Created Rule',
      source_net: this.formatAddress(ruleData.source_config),
      source_port: this.formatPort(ruleData.source_config),
      destination_net: this.formatAddress(ruleData.destination_config),
      destination_port: this.formatPort(ruleData.destination_config),
      log: ruleData.log_enabled ? '1' : '0',
      quick: '1',
      floating: '0',
      sequence: ruleData.sequence || 1000
    };
  }

  formatAddress(addressConfig) {
    if (!addressConfig || addressConfig.type === 'any') return 'any';
    switch (addressConfig.type) {
      case 'single':  return addressConfig.address || 'any';
      case 'network': return addressConfig.network || 'any';
      default:        return 'any';
    }
  }

  formatPort(addressConfig) {
    if (!addressConfig || !addressConfig.port) return '';
    return String(addressConfig.port);
  }

  validateRuleData(ruleData) {
    const required = ['action', 'interface', 'description'];
    const missing = required.filter(f => !ruleData[f]);
    if (missing.length > 0) throw new Error(`Campi obbligatori mancanti: ${missing.join(', ')}`);

    if (!['pass', 'block', 'reject'].includes(ruleData.action)) {
      throw new Error('Azione non valida. Utilizzare: pass, block, reject');
    }

    if (!['wan', 'lan', 'opt1', 'opt2', 'dmz'].includes(ruleData.interface)) {
      throw new Error('Interfaccia non valida');
    }

    if (ruleData.source_config) this.validateAddressConfig(ruleData.source_config, 'source');
    if (ruleData.destination_config) this.validateAddressConfig(ruleData.destination_config, 'destination');
    return true;
  }

  validateAddressConfig(config, type) {
    if (!config.type || !['any', 'single', 'network'].includes(config.type)) {
      throw new Error(`Tipo ${type} non valido`);
    }
    if (config.type === 'single' && !config.address) {
      throw new Error(`Indirizzo ${type} richiesto per tipo 'single'`);
    }
    if (config.type === 'network' && !config.network) {
      throw new Error(`Rete ${type} richiesta per tipo 'network'`);
    }
    if (config.address && !this.isValidIP(config.address)) {
      throw new Error(`Formato IP ${type} non valido: ${config.address}`);
    }
    if (config.network && !this.isValidCIDR(config.network)) {
      throw new Error(`Formato CIDR ${type} non valido: ${config.network}`);
    }
    if (config.port) {
      const port = parseInt(config.port, 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error(`Porta ${type} non valida: ${config.port}`);
      }
    }
  }

  isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    return ip.split('.').every(p => {
      const n = parseInt(p, 10);
      return n >= 0 && n <= 255;
    });
  }

  isValidCIDR(cidr) {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrRegex.test(cidr)) return false;
    const [ip, mask] = cidr.split('/');
    const maskNum = parseInt(mask, 10);
    return this.isValidIP(ip) && maskNum >= 0 && maskNum <= 32;
    }

  /** Stato servizio */
  getServiceHealth() {
    try {
      const now = Date.now();
      const windowMs = 60000;
      let totalRequests = 0;
      let activeOperations = 0;

      for (const [operation, requests] of this.rateLimitMap.entries()) {
        const valid = requests.filter(t => now - t < windowMs);
        totalRequests += valid.length;
        if (valid.length > 0) activeOperations++;
      }

      return {
        overall_status: 'healthy',
        components: {
          api_connectivity: true,
          rate_limiting: {
            active_operations: activeOperations,
            total_requests_last_minute: totalRequests
          }
        },
        ssl_config: {
          verify_ssl: this.verifySSL,
          ca_loaded: !!this.ca,
          client_cert_loaded: !!this.cert && !!this.key
        },
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

  resetRateLimit(operation = null) {
    if (operation) {
      this.rateLimitMap.delete(operation);
      logger.info('Rate limit reset for operation', { operation });
    } else {
      this.rateLimitMap.clear();
      logger.info('All rate limits reset');
    }
  }

  async getConfigBackup() {
    try {
      const data = await this.makeApiRequest('GET', '/api/core/backup/downloadBackup', {}, 'backup_config');
      return { success: true, data, timestamp: new Date().toISOString() };
    } catch (error) {
      logger.error('Failed to get config backup', { error: error.message });
      throw new Error(`Errore nel backup configurazione: ${error.message}`);
    }
  }

  async getInterfaces() {
    try {
      const data = await this.makeApiRequest('GET', '/api/diagnostics/interface/getInterfaceConfig', {}, 'get_interfaces');
      return { success: true, data, timestamp: new Date().toISOString() };
    } catch (error) {
      logger.error('Failed to get interfaces', { error: error.message });
      throw new Error(`Errore nel recupero interfacce: ${error.message}`);
    }
  }

  async getSystemStats() {
    try {
      const data = await this.makeApiRequest('GET', '/api/diagnostics/system/systemHealth', {}, 'system_stats');
      return { success: true, data, timestamp: new Date().toISOString() };
    } catch (error) {
      logger.error('Failed to get system stats', { error: error.message });
      throw new Error(`Errore nel recupero statistiche sistema: ${error.message}`);
    }
  }
}

module.exports = new OpnsenseService();
