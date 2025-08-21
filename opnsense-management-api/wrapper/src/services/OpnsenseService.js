const axios = require('axios');
const https = require('https');
const config = require('../config/opnsense');
const logger = require('../utils/logger');

class OpnsenseService {
  constructor() {
    this.baseUrl = config.host;
    this.apiKey = config.apiKey;
    this.apiSecret = config.apiSecret;
    this.verifySSL = config.verifySSL;
    this.requestTimeout = config.timeout;
    this.maxRetries = 3;
    this.rateLimitMap = new Map();

    if (!this.verifySSL) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    }

    logger.info('OPNsense Service inizializzato', {
      baseUrl: this.baseUrl,
      hasCredentials: !!(this.apiKey && this.apiSecret),
      verifySSL: this.verifySSL,
      timeout: this.requestTimeout
    });

    if (!this.apiKey || !this.apiSecret) {
      logger.error('Credenziali OPNsense mancanti');
      throw new Error('Credenziali OPNsense mancanti');
    }
  }

  // Crea client HTTP configurato
  getHttpClient() {
    const clientConfig = {
      baseURL: this.baseUrl,
      timeout: this.requestTimeout,
      maxRedirects: 0,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      auth: {
        username: this.apiKey,
        password: this.apiSecret
      },
      validateStatus: (status) => status < 600
    };

    if (this.baseUrl.startsWith('https:')) {
      if (!this.verifySSL) {
        clientConfig.httpsAgent = new https.Agent({
          rejectUnauthorized: false,
          checkServerIdentity: () => undefined
        });
      } else {
        clientConfig.httpsAgent = new https.Agent({ rejectUnauthorized: true });
      }
    }

    const client = axios.create(clientConfig);

    client.interceptors.request.use(
      (cfg) => {
        logger.debug(`OPNsense Request: ${cfg.method?.toUpperCase()} ${cfg.url}`);
        return cfg;
      },
      (error) => {
        logger.error('Errore interceptor richiesta', { error: error.message });
        return Promise.reject(error);
      }
    );

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

  // Log errori in modo uniforme
  _logError(error) {
    const info = {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      url: error.config?.url
    };

    if (error.code === 'ECONNREFUSED') {
      logger.error('OPNsense non raggiungibile (ECONNREFUSED)', info);
    } else if (error.code === 'ETIMEDOUT') {
      logger.error('Timeout connessione OPNsense', info);
    } else if (error.response?.status === 401) {
      logger.error('Autenticazione OPNsense fallita', info);
    } else if (error.response?.status === 403) {
      logger.error('Accesso negato OPNsense', info);
    } else if (error.code && String(error.code).includes('CERT')) {
      logger.error('Errore certificato SSL OPNsense', {
        ...info,
        suggerimento: 'Impostare OPNSENSE_VERIFY_SSL=false nel file di configurazione per certificati auto-firmati'
      });
    } else {
      logger.error('Errore generico OPNsense', info);
    }
  }

  // Test connessione
  async testConnection() {
    logger.info('Test connessione OPNsense');
    try {
      const client = this.getHttpClient();
      const start = Date.now();
      const response = await client.get('/api/core/firmware/status');
      const responseTime = Date.now() - start;

      logger.info('Connessione OPNsense riuscita', { responseTime: `${responseTime}ms`, status: response.status });

      return {
        success: true,
        responseTime,
        status: response.status,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Test connessione OPNsense fallito', {
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

  // Recupera tutte le regole
  async getRule(ruleUuid) {
  try {
    const uuid = this.encodeId(ruleUuid);
    logger.debug('Chiamata getRule con UUID:', { uuid });
    const res = await this.apiCall('GET', `/api/firewall/filter/getRule/${uuid}`);
    logger.debug('Risposta raw da getRule:', { response: res });

    if (!res || typeof res !== 'object') {
      logger.warn('Risposta inattesa da getRule, oggetto non valido', { response: res });
      return null;
    }

    if (!res.rule) {
      logger.warn('Nessun campo "rule" nella risposta', { response: res });
      return null;
    }

    const normalizedRule = this.normalizeOpnRule(res.rule);
    logger.debug('Regola normalizzata:', { rule: normalizedRule });
    return normalizedRule;
  } catch (error) {
    logger.error('Errore getRule OPNsense', { uuid: ruleUuid, error: error.message, status: error.response?.status });
    throw error;
  }
}

  // Recupera una regola da OPNsense
  async getRule(ruleUuid) {
    try {
      const uuid = this.encodeId(ruleUuid);
      const res = await this.apiCall('GET', `/api/firewall/filter/getRule/${uuid}`);
      return res?.rule ? this.normalizeOpnRule(res.rule) : null;
    } catch (error) {
      logger.error('Errore getRule OPNsense', { uuid: ruleUuid, error: error.message });
      throw error;
    }
  }

  // Creazione regola
  async createRule(ruleData) {
    logger.info('Creazione regola su OPNsense', {
      description: ruleData.description,
      interface: ruleData.interface,
      action: ruleData.action
    });

    try {
      this.validateRuleData(ruleData);
      const formattedRule = this.formatRuleForOPNsense(ruleData);

      const client = this.getHttpClient();
      const response = await client.post('/api/firewall/filter/addRule', { rule: formattedRule });

      if (response.status !== 200) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      if (!response.data?.uuid) {
        throw new Error('Risposta OPNsense priva di UUID');
      }

      logger.info('Regola OPNsense creata', { uuid: response.data.uuid, description: ruleData.description });

      return { success: true, uuid: response.data.uuid, message: 'Regola creata in OPNsense' };
    } catch (error) {
      logger.error('Errore creazione regola OPNsense', {
        error: error.message,
        ruleData: { description: ruleData.description, interface: ruleData.interface, action: ruleData.action }
      });
      throw new Error(`Errore nella creazione regola: ${error.message}`);
    }
  }

  // Abilita/disabilita regola (con opzione revert come in Python)
  async toggleRule(ruleUuid, enabled = null, useRevert = false) {
    try {
      const uuid = this.encodeId(ruleUuid);
      let revision = null;

      if (useRevert) {
        const spRes = await this.apiCall('POST', '/api/firewall/filter/savepoint', undefined);
        revision = spRes.revision;
      }

      const suffix = (enabled === null || enabled === undefined) ? '' : `/${enabled ? '1' : '0'}`;
      const url = `/api/firewall/filter/toggleRule/${uuid}${suffix}`;
      const res = await this.apiCall('POST', url, undefined);

      const ok = res?.result === 'ok' || res?.result === 'saved' || res?.status === 'ok';
      if (!ok) throw new Error(`Risposta inattesa: ${JSON.stringify(res)}`);

      if (useRevert && revision) {
        await this.applyConfig(revision);
        logger.info(`Toggle applicato con revert a ${revision} in 60 secondi`);
      }

      return { success: true, uuid: ruleUuid, enabled: enabled ?? null, opnsense_response: res, revision };
    } catch (error) {
      logger.error('Errore toggleRule OPNsense', { uuid: ruleUuid, enabled, error: error.message });
      throw new Error(`Impossibile eseguire toggleRule: ${error.message}`);
    }
  }

  // Aggiorna regola su OPNsense (con opzione revert come in Python)
  async updateRule(ruleUuid, ruleData, useRevert = false) {
    try {
      logger.info('Aggiornamento regola OPNsense', { uuid: ruleUuid });
      this.validateRuleData({
        ...ruleData,
        description: ruleData.description || 'Rule',
        interface: ruleData.interface || 'wan',
        action: ruleData.action || 'pass'
      });

      const uuid = this.encodeId(ruleUuid);
      const formattedRule = this.formatRuleForOPNsense(ruleData);

      let revision = null;
      if (useRevert) {
        const spRes = await this.apiCall('POST', '/api/firewall/filter/savepoint', undefined);
        revision = spRes.revision;
      }

      const res = await this.apiCall('POST', `/api/firewall/filter/setRule/${uuid}`, { rule: formattedRule });
      const ok = res?.result === 'ok' || res?.result === 'saved' || res?.status === 'ok';
      if (!ok) throw new Error(`Risposta inattesa: ${JSON.stringify(res)}`);

      if (useRevert && revision) {
        await this.applyConfig(revision);
        logger.info(`Update applicato con revert a ${revision} in 60 secondi`);
      }

      return res;
    } catch (error) {
      logger.error('Errore setRule OPNsense', { uuid: ruleUuid, error: error.message });
      throw new Error(`Errore aggiornamento regola: ${error.message}`);
    }
  }

  // Elimina regola su OPNsense
  async deleteRule(ruleUuid) {
    try {
      const uuid = this.encodeId(ruleUuid);
      const res = await this.apiCall('POST', `/api/firewall/filter/delRule/${uuid}`, undefined);
      const ok = res?.result === 'ok' || res?.result === 'deleted' || res?.status === 'ok';
      if (!ok) throw new Error(`Risposta inattesa: ${JSON.stringify(res)}`);
      return true;
    } catch (error) {
      logger.error('Errore delRule OPNsense', { uuid: ruleUuid, error: error.message });
      throw new Error(`Errore eliminazione regola: ${error.message}`);
    }
  }

  // Applica configurazione su OPNsense (opzionale con revision per revert)
  async applyConfig(revision = null) {
    logger.info('Applicazione configurazione OPNsense');
    try {
      const url = revision ? `/api/firewall/filter/apply/${revision}` : '/api/firewall/filter/apply';
      const response = await this.apiCall('POST', url, undefined);
      if (response.status !== 200) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      return true;
    } catch (error) {
      logger.error('Errore applicazione configurazione OPNsense', { error: error.message, status: error.response?.status });
      throw new Error(`Errore nell'applicazione configurazione: ${error.message}`);
    }
  }

  encodeId(v) {
    if (v === undefined || v === null) throw new Error('UUID mancante');
    return encodeURIComponent(String(v).trim());
  }

normalizeOpnRule(opn) {
  // Estrai lo statetype selezionato
  let statetype = 'keep state'; // Default
  if (opn.statetype) {
    for (const [key, value] of Object.entries(opn.statetype)) {
      if (value.selected === 1) {
        statetype = value.value || key; // Usa value.value se presente, altrimenti key
        break;
      }
    }
  }

  // Estrai lo state-policy selezionato
  let statePolicy = 'default'; // Default
  if (opn['state-policy']) {
    for (const [key, value] of Object.entries(opn['state-policy'])) {
      if (value.selected === 1) {
        statePolicy = value.value || key; // Usa value.value se presente, altrimenti key
        break;
      }
    }
  }

  return {
    uuid: opn.uuid || null,
    description: opn.description ?? '',
    interface: opn.interface ?? '',
    action: opn.action ?? '',
    protocol: opn.protocol ?? 'any',
    direction: opn.direction ?? 'in',
    enabled: opn.enabled === '1' || opn.enabled === 1 || opn.enabled === true,
    source: opn.source ?? 'any',
    source_port: opn.source_port ?? '',
    destination: opn.destination ?? 'any',
    destination_port: opn.destination_port ?? '',
    log: opn.log === '1' || opn.log === 1 || opn.log === true,
    statetype: statetype,
    state_policy: statePolicy,
  };
}

  // Conversione dati regola per OPNsense
  formatRuleForOPNsense(ruleData) {
    return {
      enabled: ruleData.enabled !== false ? '1' : '0',
      interface: ruleData.interface || 'wan',
      direction: ruleData.direction || 'in',
      ipprotocol: 'inet',
      protocol: ruleData.protocol || 'any',
      action: ruleData.action || 'pass',
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

  // Formattazione indirizzo
  formatAddress(addressConfig) {
    if (!addressConfig || addressConfig.type === 'any') return 'any';
    switch (addressConfig.type) {
      case 'single':
        return addressConfig.address || 'any';
      case 'network':
        return addressConfig.network || 'any';
      default:
        return 'any';
    }
  }

  // Formattazione porta
  formatPort(addressConfig) {
    return addressConfig?.port ? String(addressConfig.port) : '';
  }

  // Validazione minima dati regola
  validateRuleData(ruleData) {
    const required = ['action', 'interface', 'description'];
    const missing = required.filter(f => !ruleData[f]);
    if (missing.length > 0) throw new Error(`Campi obbligatori mancanti: ${missing.join(', ')}`);

    const validActions = ['pass', 'block', 'reject'];
    if (!validActions.includes(ruleData.action)) {
      throw new Error(`Azione non valida. Valori ammessi: ${validActions.join(', ')}`);
    }
    return true;
  }

  // Chiamata generica API OPNsense
  async apiCall(method, url, data = undefined) {
    try {
      const client = this.getHttpClient();
      const resp = await client.request({ method, url, data });
      logger.debug('OPNsense response', { url, status: resp.status, data: resp.data });

      if (resp.status === 401) throw new Error(`HTTP 401 Unauthorized - ${JSON.stringify(resp.data)}`);
      if (resp.status === 403) throw new Error(`HTTP 403 Forbidden - ${JSON.stringify(resp.data)}`);
      if (resp.status === 404) throw new Error(`HTTP 404 Not Found - ${JSON.stringify(resp.data)}`);
      if (resp.status >= 500) throw new Error(`HTTP ${resp.status} Server Error - ${JSON.stringify(resp.data)}`);
      if (resp.status >= 400) throw new Error(`HTTP ${resp.status} - ${JSON.stringify(resp.data)}`);

      return resp.data;
    } catch (err) {
      this._logError(err);
      throw err;
    }
  }

  // Stato del servizio
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

module.exports = new OpnsenseService();