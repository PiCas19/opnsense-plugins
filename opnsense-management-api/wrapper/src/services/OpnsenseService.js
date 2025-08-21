const axios = require('axios');
const https = require('https');
const config = require('../config/opnsense');
const logger = require('../utils/logger');

class OpnsenseService {
  constructor() {
    this.baseUrl = config.host;
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.maxRetries = 3;
    this.requestTimeout = config.timeout;
    this.rateLimitMap = new Map();

    // Configura HTTPS agent
    this.httpsAgent = new https.Agent({
      ca: config.ssl.ca,
      cert: config.ssl.cert,
      key: config.ssl.key,
      rejectUnauthorized: config.verifySSL,
      keepAlive: true,
      keepAliveMsecs: 30000,
      maxSockets: 10
    });

    logger.info('OPNsense Service initialized', {
      baseUrl: this.baseUrl,
      hasApiKey: !!this.apiKey,
      hasApiSecret: !!this.apiSecret,
      sslVerify: config.verifySSL,
      timeout: this.requestTimeout
    });
  }

  /**
   * Rate limiting check
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
      logger.warn('Rate limit exceeded', { operation, requests_count: validRequests.length });
      return false;
    }
    
    validRequests.push(now);
    this.rateLimitMap.set(operation, validRequests);
    return true;
  }

  /**
   * Crea client HTTP per API OPNsense
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
        'User-Agent': 'OPNsense-Firewall-API/1.0'
      },
      validateStatus: function (status) {
        return status < 600; // Accetta tutti gli status code sotto 600
      }
    });

    // Request interceptor
    client.interceptors.request.use(
      (config) => {
        logger.debug(`API Request: ${config.method?.toUpperCase()} ${config.url}`, {
          target: `${config.baseURL}${config.url}`,
          sslVerify: this.httpsAgent.options.rejectUnauthorized
        });
        return config;
      },
      (error) => {
        logger.error('Request interceptor error:', error.message);
        return Promise.reject(error);
      }
    );

    // Response interceptor
    client.interceptors.response.use(
      (response) => {
        logger.debug(`API Response: ${response.status} ${response.statusText}`);
        return response;
      },
      (error) => {
        // Gestione errori SSL
        if (error.code && (
          error.code.includes('CERT') ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        )) {
          logger.error('SSL Certificate Error:', {
            code: error.code,
            message: error.message,
            url: error.config?.url,
            suggestion: 'Verificare configurazione certificati SSL'
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
   * Effettua richiesta API con retry logic
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
          dataKeys: Object.keys(data)
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
        
        logger.warn('API request failed:', {
          method,
          endpoint,
          attempt,
          error: error.message,
          status: error.response?.status,
          statusText: error.response?.statusText,
          operation,
          code: error.code
        });

        // Non fare retry su errori SSL
        if (error.code && (
          error.code.includes('CERT') ||
          error.code === 'SELF_SIGNED_CERT_IN_CHAIN' ||
          error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'
        )) {
          logger.error('SSL Certificate Error - stopping retries');
          break;
        }

        // Non fare retry su errori client (4xx) eccetto 429
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
   * Test connessione a OPNsense
   */
  async testConnection() {
    logger.info('Testing OPNsense connection', {
      baseUrl: this.baseUrl,
      sslVerify: config.verifySSL,
      timeout: this.requestTimeout
    });

    try {
      const startTime = Date.now();
      
      // Prova endpoint multipli per migliore compatibilità
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
   * Ottieni tutte le regole firewall
   */
  async getRules() {
    try {
      logger.info('Fetching firewall rules from OPNsense...');

      // Usa l'endpoint searchRule standard
      const filterData = await this.makeApiRequest('GET', '/api/firewall/filter/searchRule', {
        current: 1,
        rowCount: 1000
      }, 'get_filter_rules');
      
      logger.debug('Filter searchRule API response:', {
        hasData: !!filterData,
        hasRows: !!(filterData && filterData.rows),
        rowCount: filterData?.rows?.length || 0
      });
      
      if (!filterData || !filterData.rows) {
        logger.warn('No rules found in OPNsense response');
        return {
          success: true,
          data: [],
          total: 0
        };
      }

      const rules = filterData.rows.map(rule => this.normalizeRule(rule));
      
      logger.info('Successfully retrieved firewall rules from OPNsense', {
        total_rules: rules.length
      });

      return {
        success: true,
        data: rules,
        total: filterData.rowCount || rules.length
      };

    } catch (error) {
      logger.error('Failed to get firewall rules', { 
        error: error.message
      });
      throw new Error(`Errore nel recupero regole: ${error.message}`);
    }
  }

  /**
   * Ottieni regola specifica per UUID
   */
  async getRule(uuid) {
    try {
      const response = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${uuid}`, {}, 'get_rule');
      
      if (!response || !response.rule) {
        throw new Error('Regola non trovata');
      }

      return {
        success: true,
        data: this.normalizeRule(response.rule)
      };
    } catch (error) {
      logger.error('Errore nel recupero regola', { uuid, error: error.message });
      throw new Error(`Errore nel recupero regola: ${error.message}`);
    }
  }

  /**
   * Crea nuova regola
   */
  async createRule(ruleData) {
    try {
      // Valida dati regola
      this.validateRuleData(ruleData);

      // Formatta regola per OPNsense
      const formattedRule = this.formatRuleForOPNsense(ruleData);

      logger.info('Creating filter rule with formatted data:', formattedRule);

      const response = await this.makeApiRequest('POST', '/api/firewall/filter/addRule', {
        rule: formattedRule
      }, 'create_rule');
      
      if (!response || !response.uuid) {
        throw new Error('OPNsense API non ha restituito un UUID valido');
      }

      // Applica modifiche
      await this.applyConfig();

      return {
        success: true,
        uuid: response.uuid,
        message: 'Regola creata con successo'
      };
    } catch (error) {
      logger.error('Errore nella creazione regola', { ruleData, error: error.message });
      throw new Error(`Errore nella creazione regola: ${error.message}`);
    }
  }

  /**
   * Aggiorna regola esistente
   */
  async updateRule(uuid, ruleData) {
    try {
      this.validateRuleData(ruleData);

      // Ottieni regola esistente
      const existingResponse = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${uuid}`, {}, 'get_rule');
      
      if (!existingResponse || !existingResponse.rule) {
        throw new Error('Regola non trovata');
      }

      // Unisci con nuovi dati
      const updatedRule = {
        ...existingResponse.rule,
        ...this.formatRuleForOPNsense(ruleData)
      };

      const response = await this.makeApiRequest('POST', `/api/firewall/filter/setRule/${uuid}`, {
        rule: updatedRule
      }, 'update_rule');
      
      if (!response || response.result !== 'saved') {
        throw new Error('Errore nell\'aggiornamento della regola');
      }

      await this.applyConfig();

      return {
        success: true,
        message: 'Regola aggiornata con successo'
      };
    } catch (error) {
      logger.error('Errore nell\'aggiornamento regola', { uuid, ruleData, error: error.message });
      throw new Error(`Errore nell'aggiornamento regola: ${error.message}`);
    }
  }

  /**
   * Elimina regola
   */
  async deleteRule(uuid) {
    try {
      const response = await this.makeApiRequest('POST', `/api/firewall/filter/delRule/${uuid}`, {}, 'delete_rule');
      
      if (!response || response.result !== 'deleted') {
        throw new Error('Errore nell\'eliminazione della regola');
      }

      await this.applyConfig();

      return {
        success: true,
        message: 'Regola eliminata con successo'
      };
    } catch (error) {
      logger.error('Errore nell\'eliminazione regola', { uuid, error: error.message });
      throw new Error(`Errore nell'eliminazione regola: ${error.message}`);
    }
  }

  /**
   * Abilita/disabilita regola
   */
  async toggleRule(uuid, enabled = true) {
    try {
      // Ottieni regola esistente
      const existingResponse = await this.makeApiRequest('GET', `/api/firewall/filter/getRule/${uuid}`, {}, 'get_rule');
      
      if (!existingResponse || !existingResponse.rule) {
        throw new Error('Regola non trovata');
      }

      // Aggiorna stato enabled
      const updatedRule = {
        ...existingResponse.rule,
        enabled: enabled ? '1' : '0'
      };

      const response = await this.makeApiRequest('POST', `/api/firewall/filter/setRule/${uuid}`, {
        rule: updatedRule
      }, 'toggle_rule');
      
      if (!response || response.result !== 'saved') {
        throw new Error('Errore nel cambio stato regola');
      }

      await this.applyConfig();

      return {
        success: true,
        message: `Regola ${enabled ? 'abilitata' : 'disabilitata'} con successo`
      };
    } catch (error) {
      logger.error('Errore nel toggle regola', { uuid, enabled, error: error.message });
      throw new Error(`Errore nel cambio stato regola: ${error.message}`);
    }
  }

  /**
   * Applica configurazione firewall
   */
  async applyConfig() {
    try {
      const response = await this.makeApiRequest('POST', '/api/firewall/filter/apply', {}, 'apply_config');
      
      if (!response || response.status !== 'ok') {
        throw new Error('Errore nell\'applicazione configurazione');
      }

      // Aspetta che le modifiche si propaghino
      await new Promise(resolve => setTimeout(resolve, 1000));

      logger.info('Configurazione firewall applicata con successo');
      return true;

    } catch (error) {
      logger.error('Errore nell\'applicazione configurazione', { error: error.message });
      throw new Error(`Errore nell'applicazione configurazione: ${error.message}`);
    }
  }

  /**
   * Normalizza regola da OPNsense
   */
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
      created: rule.created || new Date().toISOString()
    };
  }

  /**
   * Formatta regola per OPNsense API
   */
  formatRuleForOPNsense(ruleData) {
    return {
      enabled: ruleData.enabled ? '1' : '0',
      interface: ruleData.interface || 'wan',
      direction: 'in',
      ipprotocol: 'inet',
      protocol: ruleData.protocol || 'any',
      type: ruleData.action || 'pass',
      description: ruleData.description || 'API Created Rule',
      source_net: this.formatAddress(ruleData.source),
      source_port: ruleData.source_port || '',
      destination_net: this.formatAddress(ruleData.destination),
      destination_port: ruleData.destination_port || '',
      log: ruleData.log ? '1' : '0',
      quick: '1',
      floating: '0'
    };
  }

  /**
   * Formatta indirizzo per OPNsense
   */
  formatAddress(addressInput) {
    if (!addressInput || addressInput === 'any') {
      return 'any';
    }

    if (typeof addressInput === 'string') {
      return addressInput;
    }

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
   * Valida dati regola
   */
  validateRuleData(ruleData) {
    const required = ['action', 'interface', 'description'];
    const missing = required.filter(field => !ruleData[field]);
    
    if (missing.length > 0) {
      throw new Error(`Campi obbligatori mancanti: ${missing.join(', ')}`);
    }

    // Valida azione
    if (!['pass', 'block', 'reject'].includes(ruleData.action)) {
      throw new Error('Azione non valida. Utilizzare: pass, block, reject');
    }

    // Valida interfaccia
    if (!['wan', 'lan', 'opt1', 'opt2', 'dmz'].includes(ruleData.interface)) {
      throw new Error('Interfaccia non valida');
    }

    return true;
  }
}

module.exports = new OpnsenseService();