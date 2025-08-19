// src/config/opnsense.js
const fs = require('fs');
const path = require('path');
const axios = require('axios');

// axios-retry@4 in CJS espone la funzione in .default
const axiosRetryImport = require('axios-retry');
const axiosRetry = axiosRetryImport.default || axiosRetryImport;
const { isNetworkOrIdempotentRequestError } = axiosRetryImport;

const https = require('https');
const logger = require('../utils/logger');

/* ===========================
 * OPNsense API & SSH config
 * =========================== */
const opnsenseConfig = {
  baseURL: process.env.OPNSENSE_BASE_URL || 'https://192.168.216.1',
  apiKey: process.env.OPNSENSE_API_KEY,
  apiSecret: process.env.OPNSENSE_API_SECRET,
  timeout: parseInt(process.env.OPNSENSE_TIMEOUT, 10) || 30000,
  // se vuoi accettare certificati self-signed metti OPNSENSE_SSL_VERIFY=false
  sslVerify: process.env.OPNSENSE_SSL_VERIFY === 'true',
  retries: parseInt(process.env.OPNSENSE_RETRIES, 10) || 3,
  retryDelay: parseInt(process.env.OPNSENSE_RETRY_DELAY, 10) || 1000,

  // ---- SSH (usato dal Service per leggere /conf/config.xml) ----
  ssh: {
    host: process.env.OPNSENSE_SSH_HOST || '192.168.216.1',
    port: parseInt(process.env.OPNSENSE_SSH_PORT || '22', 10),
    username: process.env.OPNSENSE_SSH_USER || 'root',
    password: process.env.OPNSENSE_SSH_PASSWORD || undefined,
    // privateKey può arrivare inline (PEM o base64) o da file path
    privateKey:
      (() => {
        try {
          const inline = process.env.OPNSENSE_SSH_PRIVATE_KEY || '';
          if (inline.trim()) {
            const pem = inline.includes('BEGIN') ? inline : Buffer.from(inline, 'base64').toString('utf8');
            return pem;
          }
          const p = process.env.OPNSENSE_SSH_PRIVATE_KEY_PATH;
          if (p && fs.existsSync(p)) return fs.readFileSync(p, 'utf8');
          return undefined;
        } catch (e) {
          logger.warn('SSH private key load failed', { error: e.message });
          return undefined;
        }
      })(),
    useSudo: process.env.OPNSENSE_SSH_USE_SUDO === 'true',        // true se utente non-root
    readyTimeout: parseInt(process.env.OPNSENSE_SSH_READY_TIMEOUT || '10000', 10),
    // opzionale: pin della host key (hex lowercase). La verifica viene eseguita nel service.
    hostFingerprint: (process.env.OPNSENSE_SSH_HOST_FINGERPRINT || '').toLowerCase(),
  },
};

/* ==========================================
 * Validazione credenziali API (per CRUD/apply)
 * ========================================== */
if (!opnsenseConfig.apiKey || !opnsenseConfig.apiSecret) {
  logger.error('OPNsense API credentials not configured');
  throw new Error('OPNSENSE_API_KEY and OPNSENSE_API_SECRET must be set');
}

/* ==============================
 * HTTPS agent per chiamate API
 * ============================== */
const httpsAgent = new https.Agent({
  rejectUnauthorized: opnsenseConfig.sslVerify,
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 10,
});

/* ==============================
 * Axios instance + retry/logging
 * ============================== */
const opnsenseApi = axios.create({
  baseURL: opnsenseConfig.baseURL,
  timeout: opnsenseConfig.timeout,
  httpsAgent,
  auth: { username: opnsenseConfig.apiKey, password: opnsenseConfig.apiSecret },
  headers: {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    'User-Agent': 'OPNsense-Management-API/1.0.0',
  },
});

axiosRetry(opnsenseApi, {
  retries: opnsenseConfig.retries,
  retryDelay: (retryCount) => retryCount * opnsenseConfig.retryDelay,
  retryCondition: (error) =>
    isNetworkOrIdempotentRequestError(error) ||
    error.response?.status >= 500 ||
    error.code === 'ECONNABORTED',
  onRetry: (retryCount, error, requestConfig) => {
    logger.warn(
      `OPNsense API retry ${retryCount}/${opnsenseConfig.retries} for ${requestConfig?.url}`,
      { error: error.message, status: error.response?.status }
    );
  },
});

opnsenseApi.interceptors.request.use(
  (config) => {
    config.metadata = { startTime: Date.now() };
    logger.debug('OPNsense API Request', {
      method: config.method?.toUpperCase(),
      url: config.url,
      baseURL: config.baseURL,
    });
    return config;
  },
  (error) => {
    logger.error('OPNsense API Request Error', error);
    return Promise.reject(error);
  }
);

opnsenseApi.interceptors.response.use(
  (response) => {
    const duration = Date.now() - (response.config.metadata?.startTime || Date.now());
    logger.debug('OPNsense API Response', {
      method: response.config.method?.toUpperCase(),
      url: response.config.url,
      status: response.status,
      duration: `${duration}ms`,
    });
    try {
      const { metricsHelpers } = require('./monitoring');
      metricsHelpers?.recordOpnsenseApiCall?.(
        response.config.url,
        response.config.method?.toUpperCase(),
        'success',
        duration
      );
    } catch (_) {}
    return response;
  },
  (error) => {
    const duration = error.config?.metadata ? Date.now() - error.config.metadata.startTime : 0;
    logger.error('OPNsense API Response Error', {
      method: error.config?.method?.toUpperCase(),
      url: error.config?.url,
      status: error.response?.status,
      message: error.message,
      duration: `${duration}ms`,
    });
    try {
      const { metricsHelpers } = require('./monitoring');
      metricsHelpers?.recordOpnsenseApiCall?.(
        error.config?.url || 'unknown',
        error.config?.method?.toUpperCase() || 'unknown',
        'error',
        duration
      );
    } catch (_) {}
    return Promise.reject(error);
  }
);

/* ======================
 * Endpoints di comodo
 * ====================== */
const endpoints = {
  system: {
    status: '/api/core/system/status',
    reboot: '/api/core/system/reboot',
    halt: '/api/core/system/halt',
    info: '/api/core/system/getSystemInformation',
  },
  firewall: {
    filter: {
      get: '/api/firewall/filter/get',
      set: '/api/firewall/filter/set',
      searchRule: '/api/firewall/filter/searchRule',
      getRule: '/api/firewall/filter/getRule',
      addRule: '/api/firewall/filter/addRule',
      delRule: '/api/firewall/filter/delRule',
      setRule: '/api/firewall/filter/setRule',
      toggleRule: '/api/firewall/filter/toggleRule',
      apply: '/api/firewall/filter/apply',
    },
    alias: {
      get: '/api/firewall/alias/get',
      searchItem: '/api/firewall/alias/searchItem',
      getItem: '/api/firewall/alias/getItem',
      addItem: '/api/firewall/alias/addItem',
      delItem: '/api/firewall/alias/delItem',
      setItem: '/api/firewall/alias/setItem',
      reconfigure: '/api/firewall/alias/reconfigure',
    },
  },
  interfaces: {
    get: '/api/interfaces/overview/get',
    getInterface: '/api/interfaces/overview/getInterface',
    status: '/api/interfaces/overview/getInterfaceStatus',
  },
  diagnostics: {
    logs: '/api/diagnostics/log/get',
    activity: '/api/diagnostics/activity/getActivity',
    interface: '/api/diagnostics/interface/getInterfaceStatistics',
  },
  services: {
    status: '/api/core/service/search',
    start: '/api/core/service/start',
    stop: '/api/core/service/stop',
    restart: '/api/core/service/restart',
  },
  firmware: {
    status: '/api/core/firmware/status',
    check: '/api/core/firmware/check',
    update: '/api/core/firmware/update',
    upgrade: '/api/core/firmware/upgrade',
  },
};

/* =========================
 * Rate limiting di comodo
 * ========================= */
const rateLimits = {
  default: { requests: 100, window: 60000 },
  critical: { requests: 10, window: 60000 },
  readonly: { requests: 200, window: 60000 },
};

const endpointCategories = {
  critical: [
    endpoints.firewall.filter.apply,
    endpoints.system.reboot,
    endpoints.system.halt,
    endpoints.firmware.update,
    endpoints.firmware.upgrade,
  ],
  readonly: [
    endpoints.system.status,
    endpoints.system.info,
    endpoints.firewall.filter.get,
    endpoints.firewall.filter.searchRule,
    endpoints.interfaces.get,
    endpoints.diagnostics.logs,
  ],
};

const categorizeEndpoint = (endpoint) => {
  if (endpointCategories.critical.includes(endpoint)) return 'critical';
  if (endpointCategories.readonly.includes(endpoint)) return 'readonly';
  return 'default';
};

/* ======================
 * Helpers API generici
 * ====================== */
const handleApiError = (error, context = '') => {
  const info = {
    message: error.message,
    status: error.response?.status,
    statusText: error.response?.statusText,
    url: error.config?.url,
    method: error.config?.method,
    context,
  };

  if (error.response?.status === 401) {
    logger.error('OPNsense API authentication failed', info);
    throw new Error('Invalid OPNsense API credentials');
  }
  if (error.response?.status === 403) {
    logger.error('OPNsense API access forbidden', info);
    throw new Error('Insufficient permissions for OPNsense API');
  }
  if (error.response?.status === 404) {
    logger.error('OPNsense API endpoint not found', info);
    throw new Error('OPNsense API endpoint not available');
  }
  if (error.code === 'ECONNREFUSED') {
    logger.error('OPNsense API connection refused', info);
    throw new Error('Unable to connect to OPNsense API');
  }
  if (error.code === 'ECONNABORTED') {
    logger.error('OPNsense API request timeout', info);
    throw new Error('OPNsense API request timeout');
  }

  logger.error('OPNsense API error', info);
  throw error;
};

const testConnection = async () => {
  try {
    const response = await opnsenseApi.get(endpoints.system.status);
    logger.info('OPNsense API connection test successful', {
      status: response.status,
      version: response.data?.version || 'unknown',
    });
    return true;
  } catch (error) {
    logger.error('OPNsense API connection test failed', {
      message: error.message,
      status: error.response?.status,
      url: error.config?.url,
    });
    return false;
  }
};

const getSystemInfo = async () => {
  try {
    const response = await opnsenseApi.get(endpoints.system.info);
    return { success: true, data: response.data };
  } catch (error) {
    logger.error('Failed to get system information', error);
    return { success: false, error: error.message };
  }
};

module.exports = {
  opnsenseApi,
  opnsenseConfig,    // <-- contiene anche opnsenseConfig.ssh
  endpoints,
  rateLimits,
  testConnection,
  getSystemInfo,
  categorizeEndpoint,
  handleApiError,
  httpsAgent,
};