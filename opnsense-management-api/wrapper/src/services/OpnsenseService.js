// services/OpnsenseService.js - Versione semplificata senza gestione certificati SSL
const axios = require('axios');
const https = require('https');
const config = require('../config/opnsense');
const logger = require('../utils/logger');

class OpnsenseService {
  constructor() {
    // Configurazione base dal file config
    this.baseUrl = config.host;
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.verifySSL = config.verifySSL;
    this.requestTimeout = config.timeout;
    this.maxRetries = 3;
    this.rateLimitMap = new Map();

    // FORZA disabilitazione SSL se configurato
    if (!this.verifySSL) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }

    logger.info('OPNsense Service inizializzato', {
      baseUrl: this.baseUrl,
      hasCredentials: !!(this.apiKey && this.apiSecret),
      verifySSL: this.verifySSL,
      timeout: this.requestTimeout,
      tlsRejectUnauthorized: process.env.NODE_TLS_REJECT_UNAUTHORIZED
    });

    // Verifica credenziali
    if (!this.apiKey || !this.apiSecret) {
      logger.error('❌ Credenziali OPNsense mancanti!', {
        hasApiKey: !!this.apiKey,
        hasApiSecret: !!this.apiSecret
      });
      throw new Error('Credenziali OPNsense mancanti');
    }
  }

  /**
   * Crea client HTTP configurato
   */
  getHttpClient() {
    const clientConfig = {
      baseURL: this.baseUrl,
      timeout: this.requestTimeout,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'OPNsense-Management-API/1.0'
      },
      auth: {
        username: this.apiKey,
        password: this.apiSecret
      },
      validateStatus: (status) => status < 600
    };

    // Configurazione HTTPS semplificata
    if (this.baseUrl.startsWith('https:')) {
      if (!this.verifySSL) {
        // Disabilita COMPLETAMENTE SSL verification
        clientConfig.httpsAgent = new https.Agent({
          rejectUnauthorized: false,
          checkServerIdentity: () => undefined
        });
        logger.debug('HTTPS Agent configurato per ignorare certificati SSL');
      } else {
        // SSL verification abilitata
        clientConfig.httpsAgent = new https.Agent({
          rejectUnauthorized: true
        });
        logger.debug('HTTPS Agent configurato con SSL verification abilitata');
      }
    }

    const client = axios.create(clientConfig);

    // Request interceptor
    client.interceptors.request.use(
      (config) => {
        logger.debug(`OPNsense Request: ${config.method?.toUpperCase()} ${config.url}`);
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
        logger.debug(`OPNsense Response: ${response.status} ${response.statusText}`);
        return response;
      },
      (error) => {
        this._logError(error);
        return Promise.reject(error);
      }
    );

    return client;
  }

  /**
   * Log semplificato degli errori
   */
  _logError(error) {
    const errorDetails = {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      url: error.config?.url
    };

    if (error.code === 'ECONNREFUSED') {
      logger.error('❌ OPNsense non raggiungibile (ECONNREFUSED)', errorDetails);
    } else if (error.code === 'ETIMEDOUT') {
      logger.error('❌ Timeout connessione OPNsense', errorDetails);
    } else if (error.response?.status === 401) {
      logger.error('❌ Autenticazione OPNsense fallita - Credenziali errate', errorDetails);
    } else if (error.response?.status === 403) {
      logger.error('❌ Accesso negato OPNsense - Permessi insufficienti', errorDetails);
    } else if (error.code && error.code.includes('CERT')) {
      logger.error('❌ Errore certificato SSL OPNsense', {
        ...errorDetails,
        suggestion: 'Imposta OPNSENSE_VERIFY_SSL=false nel .env per certificati auto-firmati'
      });
    } else {
      logger.error('❌ Errore generico OPNsense', errorDetails);
    }
  }

  /**
   * Test connessione semplificato
   */
  async testConnection() {
    logger.info('🔍 Test connessione OPNsense...');

    try {
      const client = this.getHttpClient();
      const startTime = Date.now();
      
      // Test base connectivity
      const response = await client.get('/api/core/firmware/status');
      const responseTime = Date.now() - startTime;

      logger.info('✅ Connessione OPNsense riuscita', {
        responseTime: `${responseTime}ms`,
        status: response.status
      });

      return {
        success: true,
        responseTime,
        status: response.status,
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      logger.error('❌ Test connessione OPNsense fallito', {
        error: error.message,
        code: error.code,
        status: error.response?.status
      });

      return {
        success: false,
        error: error.message,
        code: error.code,
        status: error.response?.status,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Crea regola firewall
   */
  async createRule(ruleData) {
    logger.info('📝 Creazione regola OPNsense', {
      description: ruleData.description,
      interface: ruleData.interface,
      action: ruleData.action
    });

    try {
      // Valida dati
      this.validateRuleData(ruleData);
      
      // Formatta per OPNsense
      const formattedRule = this.formatRuleForOPNsense(ruleData);
      
      const client = this.getHttpClient();
      const response = await client.post('/api/firewall/filter/addRule', {
        rule: formattedRule
      });

      if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      if (!response.data?.uuid) {
        throw new Error(`OPNsense non ha restituito UUID valido: ${JSON.stringify(response.data)}`);
      }

      logger.info('✅ Regola OPNsense creata', {
        uuid: response.data.uuid,
        description: ruleData.description
      });

      return {
        success: true,
        uuid: response.data.uuid,
        message: 'Regola creata in OPNsense'
      };

    } catch (error) {
      logger.error('❌ Errore creazione regola OPNsense', {
        error: error.message,
        ruleData: {
          description: ruleData.description,
          interface: ruleData.interface,
          action: ruleData.action
        }
      });

      throw new Error(`Errore nella creazione regola: ${error.message}`);
    }
  }


  // Nel file OpnsenseService.js
  async toggleRule(ruleUuid, enabled) {
    try {
      // Prima recupera la regola esistente
      const existingRule = await this.getRule(ruleUuid);
      if (!existingRule) {
        throw new Error(`Regola con UUID ${ruleUuid} non trovata su OPNsense`);
      }

      // Aggiorna solo il campo enabled
      const updateData = {
        ...existingRule,
        enabled: enabled
      };

      // Chiamata API per aggiornare la regola
      const response = await this.apiCall('POST', `/api/firewall/filter/setRule/${ruleUuid}`, updateData);
      
      if (response.result !== 'saved') {
        throw new Error('Errore nell\'aggiornamento della regola su OPNsense');
      }

      return {
        success: true,
        uuid: ruleUuid,
        enabled: enabled
      };

    } catch (error) {
      logger.error('Errore nel toggle regola OPNsense', {
        uuid: ruleUuid,
        enabled: enabled,
        error: error.message
      });
      throw error;
    }
  }

  /**
   * Applica configurazione firewall
   */
  async applyConfig() {
    logger.info('🔄 Applicazione configurazione OPNsense...');

    try {
      const client = this.getHttpClient();
      const response = await client.post('/api/firewall/filter/apply', {});

      if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      // Attesa stabilizzazione
      await new Promise(resolve => setTimeout(resolve, 2000));

      logger.info('✅ Configurazione OPNsense applicata con successo');
      return true;

    } catch (error) {
      logger.error('❌ Errore applicazione configurazione OPNsense', {
        error: error.message,
        status: error.response?.status
      });

      throw new Error(`Errore nell'applicazione configurazione: ${error.message}`);
    }
  }

  /**
   * Formatta regola per OPNsense
   */
  formatRuleForOPNsense(ruleData) {
    return {
      enabled: ruleData.enabled !== false ? '1' : '0',
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
    return addressConfig?.port ? String(addressConfig.port) : '';
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
      status: 'ready',
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