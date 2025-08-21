// services/OpnsenseService.js
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const config = require('../config/opnsense');
const logger = require('../utils/logger');

class OpnsenseService {
  constructor() {
    this.baseUrl = config.host;
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.maxRetries = 3;
    this.requestTimeout = config.timeout || 15000;
    this.rateLimitMap = new Map();

    // Configurazione SSL/TLS
    this.verifySSL = !!config.verifySSL;
    this.ca = this._readOptionalFile(config.ssl?.ca);
    this.cert = this._readOptionalFile(config.ssl?.cert);
    this.key = this._readOptionalFile(config.ssl?.key);

    // Configura HTTPS Agent
    this.httpsAgent = this._buildHttpsAgent();

    logger.info('OPNsense Service inizializzato', {
      baseUrl: this.baseUrl,
      hasCredentials: !!(this.apiKey && this.apiSecret),
      sslVerify: this.verifySSL,
      caLoaded: !!this.ca,
      clientCertLoaded: !!(this.cert && this.key),
      timeout: this.requestTimeout
    });
  }

  /**
   * Legge file SSL opzionali
   */
  _readOptionalFile(filePath) {
    if (!filePath) return undefined;
    
    try {
      const absolutePath = path.isAbsolute(filePath) 
        ? filePath 
        : path.resolve(process.cwd(), filePath);
      return fs.readFileSync(absolutePath);
    } catch (error) {
      logger.warn('Impossibile leggere file SSL', { 
        file: filePath, 
        error: error.message 
      });
      return undefined;
    }
  }

  /**
   * Costruisce HTTPS Agent con configurazioni SSL
   */
  _buildHttpsAgent() {
    try {
      const url = new URL(this.baseUrl);
      
      if (url.protocol !== 'https:') {
        return undefined; // HTTP non necessita agent
      }

      if (!this.verifySSL) {
        // Disabilita verifica TLS globalmente
        process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        logger.warn('Verifica TLS DISABILITATA globalmente');
        return undefined;
      }

      // HTTPS con verifica completa
      return new https.Agent({
        rejectUnauthorized: true,
        ca: this.ca,
        cert: this.cert,
        key: this.key,
        keepAlive: true,
        keepAliveMsecs: 30000,
        maxSockets: 10,
        timeout: 5000
      });

    } catch (error) {
      logger.warn('Errore nella costruzione HTTPS agent, uso default', { 
        error: error.message 
      });
      return undefined;
    }
  }

  /**
   * Rate limiting per operazioni
   */
  checkRateLimit(operation, maxRequests = 60) {
    const now = Date.now();
    const windowMs = 60000; // 1 minuto

    if (!this.rateLimitMap.has(operation)) {
      this.rateLimitMap.set(operation, []);
    }

    const requests = this.rateLimitMap.get(operation);
    const validRequests = requests.filter(timestamp => now - timestamp < windowMs);

    if (validRequests.length >= maxRequests) {
      logger.warn('Rate limit superato', { 
        operation, 
        requestCount: validRequests.length 
      });
      return false;
    }

    validRequests.push(now);
    this.rateLimitMap.set(operation, validRequests);
    return true;
  }

  /**
   * Crea client Axios configurato
   */
  getHttpClient() {
    const client = axios.create({
      baseURL: this.baseUrl,
      httpsAgent: this.httpsAgent,
      auth: {
        username: this.apiKey,
        password: this.apiSecret
      },
      timeout: this.requestTimeout,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'OPNsense-Firewall-API/1.0'
      },
      validateStatus: (status) => status < 600
    });

    // Request interceptor
    client.interceptors.request.use(
      (config) => {
        const method = (config.method || 'get').toUpperCase();
        logger.debug(`Richiesta API: ${method} ${config.url}`, {
          target: `${config.baseURL}${config.url}`,
          sslVerify: this.verifySSL
        });
        return config;
      },
      (error) => {
        logger.error('Errore interceptor richiesta:', error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    client.interceptors.response.use(
      (response) => {
        logger.debug(`Risposta API: ${response.status} ${response.statusText}`, {
          url: response.config.url,
          method: response.config.method
        });
        return response;
      },
      (error) => {
        this._handleApiError(error);
        return Promise.reject(error);
      }
    );

    return client;
  }

  /**
   * Gestisce errori specifici delle API
   */
  _handleApiError(error) {
    const errorInfo = {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      statusText: error.response?.statusText,
      url: error.config?.url,
      data: error.response?.data
    };

    if (this._isSSLError(error)) {
      logger.error('Errore certificato SSL:', {
        ...errorInfo,
        suggestion: this.verifySSL
          ? 'Carica la CA corretta o usa NODE_EXTRA_CA_CERTS'
          : 'Hai verifySSL=false: non dovresti vedere errori SSL'
      });
    } else {
      logger.error('Errore risposta API:', errorInfo);
    }
  }

  /**
   * Verifica se è un errore SSL
   */
  _isSSLError(error) {
    const sslErrorCodes = [
      'CERT_UNTRUSTED',
      'CERT_SIGNATURE_FAILURE',
      'CERT_NOT_YET_VALID',
      'CERT_HAS_EXPIRED',
      'SELF_SIGNED_CERT_IN_CHAIN',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'
    ];

    return error.code && sslErrorCodes.some(code => 
      error.code.includes(code)
    );
  }

  /**
   * Wrapper per richieste API con retry
   */
  async makeApiRequest(method, endpoint, data = {}, operation = 'default') {
    if (!this.checkRateLimit(operation)) {
      throw new Error(`Rate limit superato per operazione: ${operation}`);
    }

    let lastError;
    
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      try {
        const client = this.getHttpClient();
        let response;

        logger.debug(`Tentativo API ${attempt}/${this.maxRetries}`, {
          method, endpoint, operation, dataKeys: Object.keys(data)
        });

        // Gestione metodi HTTP
        switch (method.toLowerCase()) {
          case 'get':
            response = endpoint === '/api/firewall/filter/searchRule'
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
            throw new Error(`Metodo HTTP non supportato: ${method}`);
        }

        if (response.status >= 400) {
          throw this._createHttpError(response, `HTTP ${response.status}`);
        }

        logger.debug('Richiesta API completata', {
          method, endpoint, status: response.status, operation
        });

        return response.data;

      } catch (error) {
        lastError = error;

        logger.warn('Richiesta API fallita', {
          method, endpoint, attempt,
          error: error.message,
          status: error.response?.status,
          operation, code: error.code
        });

        // Stop retry per errori SSL o 4xx (eccetto 429)
        if (this._isSSLError(error) || this._shouldNotRetry(error)) {
          break;
        }

        // Delay esponenziale per retry
        if (attempt < this.maxRetries) {
          const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
          logger.debug(`Nuovo tentativo tra ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    // Crea errore finale con dettagli
    const finalError = new Error(
      `Richiesta API fallita dopo ${this.maxRetries} tentativi: ${lastError?.message || 'errore sconosciuto'}`
    );
    
    finalError.originalError = lastError;
    finalError.endpoint = endpoint;
    finalError.method = method;
    finalError.operation = operation;
    finalError.statusCode = lastError?.response?.status;

    throw finalError;
  }

  /**
   * Determina se non fare retry
   */
  _shouldNotRetry(error) {
    const status = error.response?.status;
    return status >= 400 && status < 500 && status !== 429;
  }

  /**
   * Crea errore HTTP
   */
  _createHttpError(response, message) {
    const error = new Error(message);
    error.response = response;
    return error;
  }

  /**
   * Normalizza payload per ricerca
   */
  _normalizeSearchPayload(data) {
    return {
      current: Number(data.current) || 1,
      rowCount: Number(data.rowCount) || 50,
      sort: data.sort || {},
      searchPhrase: data.searchPhrase || ''
    };
  }

  // ===============================
  // OPERAZIONI PRINCIPALI
  // ===============================

  /**
   * Testa connessione OPNsense
   */
  async testConnection() {
    logger.info('Test connessione OPNsense', {
      baseUrl: this.baseUrl,
      sslVerify: this.verifySSL,
      timeout: this.requestTimeout
    });

    const startTime = Date.now();
    const testEndpoints = [
      { endpoint: '/api/core/firmware/status', method: 'GET' },
      { endpoint: '/api/core/system/status', method: 'GET' },
      { endpoint: '/api/diagnostics/interface/getInterfaceConfig', method: 'GET' },
      { endpoint: '/api/firewall/filter/searchRule', method: 'POST' }
    ];

    let lastError;
    
    for (const { endpoint, method } of testEndpoints) {
      try {
        const payload = method === 'POST' 
          ? this._normalizeSearchPayload({ current: 1, rowCount: 1 }) 
          : {};
          
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
            client_cert_loaded: !!(this.cert && this.key)
          }
        };
      } catch (error) {
        lastError = error;
        logger.debug(`Test endpoint ${endpoint} fallito: ${error.message}`);
      }
    }

    logger.error('Test connessione OPNsense fallito', {
      error: lastError.message,
      code: lastError.code,
      status: lastError.response?.status
    });

    return {
      success: false,
      error: lastError.message,
      status_code: lastError.response?.status,
      timestamp: new Date().toISOString(),
      ssl_config: {
        verify: this.verifySSL,
        ca_loaded: !!this.ca,
        client_cert_loaded: !!(this.cert && this.key)
      }
    };
  }

  /**
   * Recupera regole firewall
   */
  async getRules() {
    try {
      logger.info('Recupero regole firewall da OPNsense...');
      
      const filterData = await this.makeApiRequest(
        'POST',
        '/api/firewall/filter/searchRule',
        this._normalizeSearchPayload({ current: 1, rowCount: 1000 }),
        'get_filter_rules'
      );

      logger.debug('Risposta API searchRule:', {
        hasData: !!filterData,
        hasRows: !!(filterData?.rows),
        rowCount: filterData?.rows?.length || 0
      });

      if (!filterData?.rows) {
        logger.warn('Nessuna regola trovata nella risposta OPNsense');
        return { success: true, data: [], total: 0 };
      }

      const rules = filterData.rows.map(rule => this.normalizeRule(rule));
      
      logger.info('Regole firewall recuperate con successo', {
        total_rules: rules.length
      });

      return {
        success: true,
        data: rules,
        total: filterData.rowCount || rules.length
      };

    } catch (error) {
      logger.error('Errore nel recupero regole firewall', { 
        error: error.message 
      });
      throw new Error(`Errore nel recupero regole: ${error.message}`);
    }
  }

  /**
   * Recupera singola regola
   */
  async getRule(uuid) {
    try {
      const response = await this.makeApiRequest(
        'GET', 
        `/api/firewall/filter/getRule/${uuid}`, 
        {}, 
        'get_rule'
      );
      
      if (!response?.rule) {
        throw new Error('Regola non trovata');
      }
      
      return { 
        success: true, 
        data: this.normalizeRule(response.rule) 
      };
    } catch (error) {
      logger.error('Errore nel recupero regola', { 
        uuid, 
        error: error.message 
      });
      throw new Error(`Errore nel recupero regola: ${error.message}`);
    }
  }

  /**
   * Crea nuova regola
   */
  async createRule(ruleData) {
    try {
      this.validateRuleData(ruleData);
      const formattedRule = this.formatRuleForOPNsense(ruleData);
      
      logger.info('Creazione regola con dati formattati:', formattedRule);

      const response = await this.makeApiRequest(
        'POST', 
        '/api/firewall/filter/addRule', 
        { rule: formattedRule }, 
        'create_rule'
      );
      
      if (!response?.uuid) {
        throw new Error('OPNsense API non ha restituito UUID valido');
      }

      await this.applyConfig();
      
      return { 
        success: true, 
        uuid: response.uuid, 
        message: 'Regola creata con successo' 
      };
    } catch (error) {
      logger.error('Errore nella creazione regola', { 
        ruleData, 
        error: error.message 
      });
      throw new Error(`Errore nella creazione regola: ${error.message}`);
    }
  }

  /**
   * Aggiorna regola esistente
   */
  async updateRule(uuid, ruleData) {
    try {
      this.validateRuleData(ruleData);
      
      const existing = await this.makeApiRequest(
        'GET', 
        `/api/firewall/filter/getRule/${uuid}`, 
        {}, 
        'get_rule'
      );
      
      if (!existing?.rule) {
        throw new Error('Regola non trovata');
      }

      const updatedRule = { 
        ...existing.rule, 
        ...this.formatRuleForOPNsense(ruleData) 
      };
      
      const response = await this.makeApiRequest(
        'POST', 
        `/api/firewall/filter/setRule/${uuid}`, 
        { rule: updatedRule }, 
        'update_rule'
      );
      
      if (response?.result !== 'saved') {
        throw new Error('Errore nell\'aggiornamento della regola');
      }

      await this.applyConfig();
      
      return { 
        success: true, 
        message: 'Regola aggiornata con successo' 
      };
    } catch (error) {
      logger.error('Errore nell\'aggiornamento regola', { 
        uuid, 
        ruleData, 
        error: error.message 
      });
      throw new Error(`Errore nell'aggiornamento regola: ${error.message}`);
    }
  }

  /**
   * Elimina regola
   */
  async deleteRule(uuid) {
    try {
      const response = await this.makeApiRequest(
        'POST', 
        `/api/firewall/filter/delRule/${uuid}`, 
        {}, 
        'delete_rule'
      );
      
      if (response?.result !== 'deleted') {
        throw new Error('Errore nell\'eliminazione della regola');
      }

      await this.applyConfig();
      
      return { 
        success: true, 
        message: 'Regola eliminata con successo' 
      };
    } catch (error) {
      logger.error('Errore nell\'eliminazione regola', { 
        uuid, 
        error: error.message 
      });
      throw new Error(`Errore nell'eliminazione regola: ${error.message}`);
    }
  }

  /**
   * Abilita/disabilita regola
   */
  async toggleRule(uuid, enabled = true) {
    try {
      const existing = await this.makeApiRequest(
        'GET', 
        `/api/firewall/filter/getRule/${uuid}`, 
        {}, 
        'get_rule'
      );
      
      if (!existing?.rule) {
        throw new Error('Regola non trovata');
      }

      const updatedRule = { 
        ...existing.rule, 
        enabled: enabled ? '1' : '0' 
      };
      
      const response = await this.makeApiRequest(
        'POST', 
        `/api/firewall/filter/setRule/${uuid}`, 
        { rule: updatedRule }, 
        'toggle_rule'
      );
      
      if (response?.result !== 'saved') {
        throw new Error('Errore nel cambio stato regola');
      }

      await this.applyConfig();
      
      return { 
        success: true, 
        message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} con successo` 
      };
    } catch (error) {
      logger.error('Errore nel toggle regola', { 
        uuid, 
        enabled, 
        error: error.message 
      });
      throw new Error(`Errore nel cambio stato regola: ${error.message}`);
    }
  }

  /**
   * Applica configurazione firewall
   */
  async applyConfig() {
    try {
      const response = await this.makeApiRequest(
        'POST', 
        '/api/firewall/filter/apply', 
        {}, 
        'apply_config'
      );
      
      if (response?.status !== 'ok') {
        throw new Error('Errore nell\'applicazione configurazione');
      }
      
      // Attesa per stabilizzazione
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      logger.info('Configurazione firewall applicata con successo');
      return true;
    } catch (error) {
      logger.error('Errore nell\'applicazione configurazione', { 
        error: error.message 
      });
      throw new Error(`Errore nell'applicazione configurazione: ${error.message}`);
    }
  }

  // ===============================
  // UTILITÀ E HELPERS
  // ===============================

  /**
   * Normalizza regola da OPNsense
   */
  normalizeRule(rule) {
    return {
      uuid: rule.uuid || rule.id,
      description: rule.description || rule.descr || 'Regola senza nome',
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

  /**
   * Formatta regola per OPNsense
   */
  formatRuleForOPNsense(ruleData) {
    return {
      enabled: ruleData.enabled ? '1' : '0',
      interface: ruleData.interface || 'wan',
      direction: ruleData.direction || 'in',
      ipprotocol: 'inet',
      protocol: ruleData.protocol || 'any',
      type: ruleData.action || 'pass',
      description: ruleData.description || 'Regola creata da API',
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

  /**
   * Formatta indirizzo
   */
  formatAddress(addressConfig) {
    if (!addressConfig || addressConfig.type === 'any') {
      return 'any';
    }
    
    switch (addressConfig.type) {
      case 'single':
        return addressConfig.address || 'any';
      case 'network':
        return addressConfig.network || 'any';
      default:
        return 'any';
    }
  }

  /**
   * Formatta porta
   */
  formatPort(addressConfig) {
    if (!addressConfig?.port) {
      return '';
    }
    return String(addressConfig.port);
  }

  /**
   * Valida dati regola
   */
  validateRuleData(ruleData) {
    const required = ['action', 'interface', 'description'];
    const missing = required.filter(field => !ruleData[field]);
    
    if (missing.length > 0) {
      throw new Error(`Campi obbligatori mancanti: ${missing.join(', ')}`);
    }

    const validActions = ['pass', 'block', 'reject'];
    if (!validActions.includes(ruleData.action)) {
      throw new Error(`Azione non valida. Usare: ${validActions.join(', ')}`);
    }

    const validInterfaces = ['wan', 'lan', 'opt1', 'opt2', 'dmz'];
    if (!validInterfaces.includes(ruleData.interface)) {
      throw new Error(`Interfaccia non valida. Usare: ${validInterfaces.join(', ')}`);
    }

    if (ruleData.source_config) {
      this.validateAddressConfig(ruleData.source_config, 'source');
    }
    if (ruleData.destination_config) {
      this.validateAddressConfig(ruleData.destination_config, 'destination');
    }

    return true;
  }

  /**
   * Valida configurazione indirizzo
   */
  validateAddressConfig(config, type) {
    const validTypes = ['any', 'single', 'network'];
    if (!validTypes.includes(config.type)) {
      throw new Error(`Tipo ${type} non valido. Usare: ${validTypes.join(', ')}`);
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

  /**
   * Valida indirizzo IP
   */
  isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    
    return ip.split('.').every(octet => {
      const num = parseInt(octet, 10);
      return num >= 0 && num <= 255;
    });
  }

  /**
   * Valida notazione CIDR
   */
  isValidCIDR(cidr) {
    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrRegex.test(cidr)) return false;
    
    const [ip, mask] = cidr.split('/');
    const maskNum = parseInt(mask, 10);
    
    return this.isValidIP(ip) && maskNum >= 0 && maskNum <= 32;
  }

  // ===============================
  // OPERAZIONI AGGIUNTIVE
  // ===============================

  /**
   * Stato salute servizio
   */
  getServiceHealth() {
    try {
      const now = Date.now();
      const windowMs = 60000;
      let totalRequests = 0;
      let activeOperations = 0;

      for (const [operation, requests] of this.rateLimitMap.entries()) {
        const validRequests = requests.filter(timestamp => now - timestamp < windowMs);
        totalRequests += validRequests.length;
        if (validRequests.length > 0) activeOperations++;
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
          client_cert_loaded: !!(this.cert && this.key)
        },
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Errore nel recupero stato salute servizio', { 
        error: error.message 
      });
      return {
        overall_status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Reset rate limit
   */
  resetRateLimit(operation = null) {
    if (operation) {
      this.rateLimitMap.delete(operation);
      logger.info('Rate limit resettato per operazione', { operation });
    } else {
      this.rateLimitMap.clear();
      logger.info('Tutti i rate limit resettati');
    }
  }

  /**
   * Backup configurazione
   */
  async getConfigBackup() {
    try {
      const data = await this.makeApiRequest(
        'GET', 
        '/api/core/backup/downloadBackup', 
        {}, 
        'backup_config'
      );
      
      return { 
        success: true, 
        data, 
        timestamp: new Date().toISOString() 
      };
    } catch (error) {
      logger.error('Errore nel backup configurazione', { 
        error: error.message 
      });
      throw new Error(`Errore nel backup configurazione: ${error.message}`);
    }
  }

  /**
   * Recupera interfacce
   */
  async getInterfaces() {
    try {
      const data = await this.makeApiRequest(
        'GET', 
        '/api/diagnostics/interface/getInterfaceConfig', 
        {}, 
        'get_interfaces'
      );
      
      return { 
        success: true, 
        data, 
        timestamp: new Date().toISOString() 
      };
    } catch (error) {
      logger.error('Errore nel recupero interfacce', { 
        error: error.message 
      });
      throw new Error(`Errore nel recupero interfacce: ${error.message}`);
    }
  }

  /**
   * Recupera statistiche sistema
   */
  async getSystemStats() {
    try {
      const data = await this.makeApiRequest(
        'GET', 
        '/api/diagnostics/system/systemHealth', 
        {}, 
        'system_stats'
      );
      
      return { 
        success: true, 
        data, 
        timestamp: new Date().toISOString() 
      };
    } catch (error) {
      logger.error('Errore nel recupero statistiche sistema', { 
        error: error.message 
      });
      throw new Error(`Errore nel recupero statistiche sistema: ${error.message}`);
    }
  }
}

// Esporta istanza singleton
module.exports = new OpnsenseService();