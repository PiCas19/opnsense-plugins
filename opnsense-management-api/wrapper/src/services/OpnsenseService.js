// services/OpnsenseService.js - Versione con debug migliorato
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

class OpnsenseService {
  constructor() {
    // Configurazione base
    this.baseUrl = process.env.OPNSENSE_HOST || 'https://opnsense.localdomain';
    this.apiKey = process.env.OPNSENSE_API_KEY;
    this.apiSecret = process.env.OPNSENSE_API_SECRET;
    this.maxRetries = 3;
    this.requestTimeout = parseInt(process.env.OPNSENSE_TIMEOUT) || 15000;
    this.rateLimitMap = new Map();

    // Configurazione SSL
    this.verifySSL = process.env.OPNSENSE_VERIFY_SSL !== 'false';
    
    // Log configurazione
    logger.info('OPNsense Service configurato', {
      baseUrl: this.baseUrl,
      hasCredentials: !!(this.apiKey && this.apiSecret),
      verifySSL: this.verifySSL,
      timeout: this.requestTimeout
    });

    // Verifica credenziali
    if (!this.apiKey || !this.apiSecret) {
      logger.error('Credenziali OPNsense mancanti', {
        hasApiKey: !!this.apiKey,
        hasApiSecret: !!this.apiSecret
      });
    }
  }

  /**
   * Crea client HTTP configurato
   */
  getHttpClient() {
    const config = {
      baseURL: this.baseUrl,
      timeout: this.requestTimeout,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'OPNsense-Management-API/1.0'
      },
      validateStatus: (status) => status < 600
    };

    // Configurazione autenticazione
    if (this.apiKey && this.apiSecret) {
      config.auth = {
        username: this.apiKey,
        password: this.apiSecret
      };
    }

    // Configurazione HTTPS
    if (this.baseUrl.startsWith('https:')) {
      if (!this.verifySSL) {
        config.httpsAgent = new https.Agent({
          rejectUnauthorized: false
        });
        logger.warn('SSL verification DISABILITATA per OPNsense');
      }
    }

    const client = axios.create(config);

    // Request interceptor
    client.interceptors.request.use(
      (config) => {
        logger.debug(`OPNsense Request: ${config.method?.toUpperCase()} ${config.url}`, {
          baseURL: config.baseURL,
          timeout: config.timeout,
          hasAuth: !!config.auth
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
        logger.debug(`OPNsense Response: ${response.status}`, {
          url: response.config.url,
          method: response.config.method,
          dataSize: JSON.stringify(response.data).length
        });
        return response;
      },
      (error) => {
        this._logDetailedError(error);
        return Promise.reject(error);
      }
    );

    return client;
  }

  /**
   * Log dettagliato degli errori
   */
  _logDetailedError(error) {
    const errorInfo = {
      message: error.message,
      code: error.code,
      url: error.config?.url,
      method: error.config?.method,
      status: error.response?.status,
      statusText: error.response?.statusText,
      responseData: error.response?.data,
      timeout: error.config?.timeout
    };

    if (error.code === 'ECONNREFUSED') {
      logger.error('OPNsense non raggiungibile - Connessione rifiutata', errorInfo);
    } else if (error.code === 'ETIMEDOUT') {
      logger.error('OPNsense timeout', errorInfo);
    } else if (error.response?.status === 401) {
      logger.error('OPNsense autenticazione fallita - Controlla API key/secret', errorInfo);
    } else if (error.response?.status === 403) {
      logger.error('OPNsense accesso negato - Permessi insufficienti', errorInfo);
    } else if (error.response?.status >= 500) {
      logger.error('OPNsense errore interno del server', errorInfo);
    } else {
      logger.error('OPNsense errore generico', errorInfo);
    }
  }

  /**
   * Test connessione con diagnostica completa
   */
  async testConnection() {
    logger.info('Test connessione OPNsense completo', {
      baseUrl: this.baseUrl,
      verifySSL: this.verifySSL
    });

    const results = {
      success: false,
      tests: {},
      timestamp: new Date().toISOString()
    };

    // Test 1: Connessione base
    try {
      const client = this.getHttpClient();
      const startTime = Date.now();
      
      const response = await client.get('/api/core/firmware/status');
      const responseTime = Date.now() - startTime;

      results.tests.connectivity = {
        success: true,
        responseTime,
        status: response.status
      };

      logger.info('Test connettività OPNsense: OK', {
        responseTime,
        status: response.status
      });

    } catch (error) {
      results.tests.connectivity = {
        success: false,
        error: error.message,
        code: error.code,
        status: error.response?.status
      };

      logger.error('Test connettività OPNsense: FALLITO', {
        error: error.message,
        code: error.code
      });
    }

    // Test 2: Autenticazione
    try {
      const client = this.getHttpClient();
      const response = await client.get('/api/diagnostics/interface/getInterfaceConfig');

      results.tests.authentication = {
        success: response.status === 200,
        status: response.status
      };

      logger.info('Test autenticazione OPNsense: OK');

    } catch (error) {
      results.tests.authentication = {
        success: false,
        error: error.message,
        status: error.response?.status
      };

      if (error.response?.status === 401) {
        logger.error('Test autenticazione OPNsense: FALLITO - Credenziali non valide');
      } else {
        logger.error('Test autenticazione OPNsense: FALLITO', {
          error: error.message,
          status: error.response?.status
        });
      }
    }

    // Test 3: API Firewall
    try {
      const client = this.getHttpClient();
      const response = await client.post('/api/firewall/filter/searchRule', {
        current: 1,
        rowCount: 1,
        searchPhrase: ''
      });

      results.tests.firewall_api = {
        success: response.status === 200,
        status: response.status,
        rulesFound: response.data?.rows?.length || 0
      };

      logger.info('Test API Firewall OPNsense: OK', {
        rulesFound: response.data?.rows?.length || 0
      });

    } catch (error) {
      results.tests.firewall_api = {
        success: false,
        error: error.message,
        status: error.response?.status
      };

      logger.error('Test API Firewall OPNsense: FALLITO', {
        error: error.message,
        status: error.response?.status
      });
    }

    // Determina successo complessivo
    results.success = Object.values(results.tests).every(test => test.success);

    logger.info('Test connessione OPNsense completato', {
      success: results.success,
      tests: Object.keys(results.tests).map(key => ({
        test: key,
        success: results.tests[key].success
      }))
    });

    return results;
  }

  /**
   * Applica configurazione con retry e diagnostica
   */
  async applyConfig() {
    logger.info('Tentativo applicazione configurazione OPNsense');

    try {
      const client = this.getHttpClient();
      
      // Prima verifica lo stato del sistema
      try {
        const statusResponse = await client.get('/api/core/system/status');
        logger.debug('Stato sistema OPNsense prima dell\'apply', {
          status: statusResponse.status,
          data: statusResponse.data
        });
      } catch (statusError) {
        logger.warn('Impossibile verificare stato sistema prima dell\'apply', {
          error: statusError.message
        });
      }

      // Applica configurazione
      const response = await client.post('/api/firewall/filter/apply', {});

      logger.debug('Risposta apply configurazione', {
        status: response.status,
        data: response.data
      });

      if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      if (response.data?.status !== 'ok' && response.data?.result !== 'ok') {
        throw new Error(`OPNsense apply failed: ${JSON.stringify(response.data)}`);
      }

      // Attesa per stabilizzazione
      await new Promise(resolve => setTimeout(resolve, 2000));

      logger.info('Configurazione OPNsense applicata con successo');
      return true;

    } catch (error) {
      logger.error('Errore nell\'applicazione configurazione OPNsense', {
        error: error.message,
        code: error.code,
        status: error.response?.status,
        responseData: error.response?.data
      });

      throw new Error(`Errore nell'applicazione configurazione: ${error.message}`);
    }
  }

  /**
   * Crea regola con validazione migliorata
   */
  async createRule(ruleData) {
    logger.info('Creazione regola OPNsense', {
      description: ruleData.description,
      interface: ruleData.interface,
      action: ruleData.action
    });

    try {
      // Valida i dati della regola
      this.validateRuleData(ruleData);
      
      // Formatta per OPNsense
      const formattedRule = this.formatRuleForOPNsense(ruleData);
      
      logger.debug('Regola formattata per OPNsense', formattedRule);

      const client = this.getHttpClient();
      const response = await client.post('/api/firewall/filter/addRule', {
        rule: formattedRule
      });

      logger.debug('Risposta creazione regola OPNsense', {
        status: response.status,
        data: response.data
      });

      if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      if (!response.data?.uuid) {
        throw new Error(`OPNsense non ha restituito UUID: ${JSON.stringify(response.data)}`);
      }

      // NON applicare automaticamente la configurazione qui
      // Lascia che sia l'applicazione a decidere quando applicare
      
      logger.info('Regola OPNsense creata con successo', {
        uuid: response.data.uuid,
        description: ruleData.description
      });

      return {
        success: true,
        uuid: response.data.uuid,
        message: 'Regola creata in OPNsense (configurazione non ancora applicata)'
      };

    } catch (error) {
      logger.error('Errore nella creazione regola OPNsense', {
        error: error.message,
        ruleData,
        status: error.response?.status,
        responseData: error.response?.data
      });

      throw new Error(`Errore nella creazione regola: ${error.message}`);
    }
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
      description: ruleData.description || 'API Created Rule',
      source_net: this.formatAddress(ruleData.source_config),
      source_port: this.formatPort(ruleData.source_config),
      destination_net: this.formatAddress(ruleData.destination_config),
      destination_port: this.formatPort(ruleData.destination_config),
      log: ruleData.log_enabled ? '1' : '0',
      quick: '1',
      floating: '0'
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
   * Validazione dati regola
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

    return true;
  }

  /**
   * Stato del servizio
   */
  getServiceHealth() {
    return {
      service: 'opnsense',
      status: 'healthy',
      configuration: {
        baseUrl: this.baseUrl,
        hasCredentials: !!(this.apiKey && this.apiSecret),
        verifySSL: this.verifySSL,
        timeout: this.requestTimeout
      },
      timestamp: new Date().toISOString()
    };
  }
}

// Esporta istanza singleton
module.exports = new OpnsenseService();