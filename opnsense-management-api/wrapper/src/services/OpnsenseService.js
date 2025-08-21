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


  // Aggiungi questo metodo al tuo OpnsenseService.js

/**
 * Abilita/disabilita una regola su OPNsense
 * @param {string} ruleUuid - UUID della regola su OPNsense
 * @param {boolean} enabled - true per abilitare, false per disabilitare
 * @returns {Promise<Object>} Risultato dell'operazione
 */
async toggleRule(ruleUuid, enabled) {
  try {
    logger.info('Tentativo toggle regola OPNsense', {
      uuid: ruleUuid,
      enabled: enabled
    });

    // Prima recupera la regola esistente per avere tutti i dati
    const existingRule = await this.getRule(ruleUuid);
    if (!existingRule) {
      throw new Error(`Regola con UUID ${ruleUuid} non trovata su OPNsense`);
    }

    // Prepara i dati per l'aggiornamento - mantieni tutti i campi esistenti
    const updateData = {
      ...existingRule,
      enabled: enabled ? '1' : '0'  // OPNsense usa stringhe '1'/'0' per boolean
    };

    // Chiama l'API di OPNsense per aggiornare la regola
    const updateResponse = await this.apiCall('POST', `/api/firewall/filter/setRule/${ruleUuid}`, {
      rule: updateData
    });

    if (updateResponse.result !== 'saved') {
      throw new Error(`Errore nell'aggiornamento regola: ${JSON.stringify(updateResponse)}`);
    }

    logger.info('Regola toggleata con successo su OPNsense', {
      uuid: ruleUuid,
      enabled: enabled,
      response: updateResponse
    });

    return {
      success: true,
      uuid: ruleUuid,
      enabled: enabled,
      opnsense_response: updateResponse
    };

  } catch (error) {
    logger.error('Errore nel toggle regola OPNsense', {
      uuid: ruleUuid,
      enabled: enabled,
      error: error.message,
      stack: error.stack
    });
    throw new Error(`Impossibile modificare stato regola: ${error.message}`);
  }
}

/**
 * Recupera una singola regola da OPNsense
 * @param {string} ruleUuid - UUID della regola
 * @returns {Promise<Object|null>} Dati della regola o null se non trovata
 */
async getRule(ruleUuid) {
  try {
    const response = await this.apiCall('GET', `/api/firewall/filter/getRule/${ruleUuid}`);
    
    if (response && response.rule) {
      return response.rule;
    }
    
    return null;
  } catch (error) {
    logger.error('Errore nel recupero regola OPNsense', {
      uuid: ruleUuid,
      error: error.message
    });
    throw error;
  }
}

/**
 * Recupera tutte le regole da OPNsense
 * @returns {Promise<Array>} Array delle regole
 */
async getRules() {
  try {
    const response = await this.apiCall('GET', '/api/firewall/filter/get');
    
    if (response && response.filter && response.filter.rules) {
      // Converte l'oggetto delle regole in array
      return Object.values(response.filter.rules);
    }
    
    return [];
  } catch (error) {
    logger.error('Errore nel recupero regole OPNsense', {
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

  formatRuleForOPNsense(ruleData) {
    return {
      enabled: ruleData.enabled !== false ? '1' : '0',
      interface: ruleData.interface || 'wan',
      direction: ruleData.direction || 'in',
      ipprotocol: 'inet',
      protocol: ruleData.protocol || 'any',
      action: ruleData.action || 'pass',    // <- QUI prima era "type"
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

  async apiCall(method, url, data = undefined) {
  try {
    const client = this.getHttpClient();
    const resp = await client.request({
      method,
      url,
      data
    });

    // L'API OPNsense di solito torna 200 con payload {result: "..."} anche su errori logici
    if (resp.status >= 400) {
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }
    return resp.data;
  } catch (err) {
    this._logError(err);
    throw err;
  }
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