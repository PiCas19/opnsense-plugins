const axios = require('axios');
const axiosRetry = require('axios-retry');
const https = require('https');
const logger = require('../utils/logger');

// OPNsense API Configuration
const opnsenseConfig = {
  baseURL: process.env.OPNSENSE_BASE_URL || 'https://192.168.216.1',
  apiKey: process.env.OPNSENSE_API_KEY,
  apiSecret: process.env.OPNSENSE_API_SECRET,
  timeout: parseInt(process.env.OPNSENSE_TIMEOUT) || 30000,
  sslVerify: process.env.OPNSENSE_SSL_VERIFY === 'true',
  retries: parseInt(process.env.OPNSENSE_RETRIES) || 3,
  retryDelay: parseInt(process.env.OPNSENSE_RETRY_DELAY) || 1000,
};

// Validate required configuration
if (!opnsenseConfig.apiKey || !opnsenseConfig.apiSecret) {
  logger.error('OPNsense API credentials not configured');
  throw new Error('OPNSENSE_API_KEY and OPNSENSE_API_SECRET must be set');
}

// Create HTTPS agent for OPNsense API calls
const httpsAgent = new https.Agent({
  rejectUnauthorized: opnsenseConfig.sslVerify,
  keepAlive: true,
  keepAliveMsecs: 30000,
  maxSockets: 10,
});

// Create axios instance for OPNsense API
const opnsenseApi = axios.create({
  baseURL: opnsenseConfig.baseURL,
  timeout: opnsenseConfig.timeout,
  httpsAgent: httpsAgent,
  auth: {
    username: opnsenseConfig.apiKey,
    password: opnsenseConfig.apiSecret,
  },
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'User-Agent': 'OPNsense-Management-API/1.0.0',
  },
});

// Configure axios retry
axiosRetry(opnsenseApi, {
  retries: opnsenseConfig.retries,
  retryDelay: (retryCount) => {
    return retryCount * opnsenseConfig.retryDelay;
  },
  retryCondition: (error) => {
    return axiosRetry.isNetworkOrIdempotentRequestError(error) ||
           error.response?.status >= 500 ||
           error.code === 'ECONNABORTED';
  },
  onRetry: (retryCount, error, requestConfig) => {
    logger.warn(`OPNsense API retry ${retryCount}/${opnsenseConfig.retries} for ${requestConfig.url}`, {
      error: error.message,
      status: error.response?.status,
    });
  },
});

// Request interceptor for logging and metrics
opnsenseApi.interceptors.request.use(
  (config) => {
    const startTime = Date.now();
    config.metadata = { startTime };
    
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

// Response interceptor for logging and metrics
opnsenseApi.interceptors.response.use(
  (response) => {
    const duration = Date.now() - response.config.metadata.startTime;
    
    logger.debug('OPNsense API Response', {
      method: response.config.method?.toUpperCase(),
      url: response.config.url,
      status: response.status,
      duration: `${duration}ms`,
    });

    // Record metrics if monitoring is available
    try {
      const { metricsHelpers } = require('./monitoring');
      metricsHelpers.recordOpnsenseApiCall(
        response.config.url,
        response.config.method?.toUpperCase(),
        'success',
        duration
      );
    } catch (error) {
      // Monitoring not available, continue silently
    }

    return response;
  },
  (error) => {
    const duration = error.config?.metadata ? 
      Date.now() - error.config.metadata.startTime : 0;

    logger.error('OPNsense API Response Error', {
      method: error.config?.method?.toUpperCase(),
      url: error.config?.url,
      status: error.response?.status,
      message: error.message,
      duration: `${duration}ms`,
    });

    // Record error metrics if monitoring is available
    try {
      const { metricsHelpers } = require('./monitoring');
      metricsHelpers.recordOpnsenseApiCall(
        error.config?.url || 'unknown',
        error.config?.method?.toUpperCase() || 'unknown',
        'error',
        duration
      );
    } catch (metricsError) {
      // Monitoring not available, continue silently
    }

    return Promise.reject(error);
  }
);

// OPNsense API Endpoints Configuration
const endpoints = {
  // Core System
  system: {
    status: '/api/core/system/status',
    reboot: '/api/core/system/reboot',
    halt: '/api/core/system/halt',
    info: '/api/core/system/getSystemInformation',
  },

  // Firewall Filter Rules
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

  // Interface Management
  interfaces: {
    get: '/api/interfaces/overview/get',
    getInterface: '/api/interfaces/overview/getInterface',
    status: '/api/interfaces/overview/getInterfaceStatus',
  },

  // Diagnostics
  diagnostics: {
    logs: '/api/diagnostics/log/get',
    activity: '/api/diagnostics/activity/getActivity',
    interface: '/api/diagnostics/interface/getInterfaceStatistics',
  },

  // Services
  services: {
    status: '/api/core/service/search',
    start: '/api/core/service/start',
    stop: '/api/core/service/stop',
    restart: '/api/core/service/restart',
  },

  // Updates
  firmware: {
    status: '/api/core/firmware/status',
    check: '/api/core/firmware/check',
    update: '/api/core/firmware/update',
    upgrade: '/api/core/firmware/upgrade',
  },
};

// Test connection to OPNsense
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

// Get system information
const getSystemInfo = async () => {
  try {
    const response = await opnsenseApi.get(endpoints.system.info);
    return {
      success: true,
      data: response.data,
    };
  } catch (error) {
    logger.error('Failed to get system information', error);
    return {
      success: false,
      error: error.message,
    };
  }
};

// Rate limiting configuration for OPNsense API
const rateLimits = {
  default: {
    requests: 100,
    window: 60000, // 1 minute
  },
  critical: {
    requests: 10,
    window: 60000, // 1 minute for critical operations
  },
  readonly: {
    requests: 200,
    window: 60000, // 1 minute for read operations
  },
};

// Endpoint categories for rate limiting
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

// Helper function to categorize endpoint
const categorizeEndpoint = (endpoint) => {
  if (endpointCategories.critical.includes(endpoint)) {
    return 'critical';
  }
  if (endpointCategories.readonly.includes(endpoint)) {
    return 'readonly';
  }
  return 'default';
};

// Error handling helper
const handleApiError = (error, context = '') => {
  const errorInfo = {
    message: error.message,
    status: error.response?.status,
    statusText: error.response?.statusText,
    url: error.config?.url,
    method: error.config?.method,
    context,
  };

  if (error.response?.status === 401) {
    logger.error('OPNsense API authentication failed', errorInfo);
    throw new Error('Invalid OPNsense API credentials');
  }

  if (error.response?.status === 403) {
    logger.error('OPNsense API access forbidden', errorInfo);
    throw new Error('Insufficient permissions for OPNsense API');
  }

  if (error.response?.status === 404) {
    logger.error('OPNsense API endpoint not found', errorInfo);
    throw new Error('OPNsense API endpoint not available');
  }

  if (error.code === 'ECONNREFUSED') {
    logger.error('OPNsense API connection refused', errorInfo);
    throw new Error('Unable to connect to OPNsense API');
  }

  if (error.code === 'ECONNABORTED') {
    logger.error('OPNsense API request timeout', errorInfo);
    throw new Error('OPNsense API request timeout');
  }

  logger.error('OPNsense API error', errorInfo);
  throw error;
};

module.exports = {
  opnsenseApi,
  opnsenseConfig,
  endpoints,
  rateLimits,
  testConnection,
  getSystemInfo,
  categorizeEndpoint,
  handleApiError,
  httpsAgent,
};