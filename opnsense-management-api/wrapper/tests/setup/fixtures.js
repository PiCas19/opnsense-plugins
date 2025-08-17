// tests/setup/fixtures.js
const path = require('path');
const fs = require('fs');

// Carica i JSON dei fixtures con gestione errori
let mockResponses, testData;

try {
  const mockResponsesPath = path.join(__dirname, '..', 'fixtures', 'mock-responses.json');
  const testDataPath = path.join(__dirname, '..', 'fixtures', 'test-data.json');
  
  mockResponses = require(mockResponsesPath);
  testData = require(testDataPath);
} catch (error) {
  console.error('Errore nel caricamento dei fixtures:', error.message);
  // Fallback con oggetti vuoti
  mockResponses = {};
  testData = {};
}

// Utility: deep clone semplice
const deepClone = obj => {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime());
  if (obj instanceof Array) return obj.map(item => deepClone(item));
  if (typeof obj === 'object') {
    const cloned = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        cloned[key] = deepClone(obj[key]);
      }
    }
    return cloned;
  }
  return obj;
};

// Ritorna un valore navigando con "a.b.c" su un oggetto
function getByDotPath(root, dotPath, rootNameForError = 'Data') {
  if (!root || typeof root !== 'object') {
    throw new Error(`${rootNameForError}: root object is null or not an object`);
  }
  
  if (!dotPath || typeof dotPath !== 'string') {
    throw new Error(`${rootNameForError}: invalid dot path`);
  }
  
  const parts = dotPath.split('.');
  let current = root;
  
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (current[part] === undefined || current[part] === null) {
      throw new Error(`${rootNameForError} not found for path: ${dotPath} (missing at: ${part})`);
    }
    current = current[part];
  }
  
  return deepClone(current);
}

/**
 * Ottiene una mock response per un endpoint specifico
 * @param {string} endpoint - Path dell'endpoint (es: "firewall.getRule.success")
 * @param {object} overrides - Valori da sovrascrivere
 * @returns {object} Mock response
 */
function getMockResponse(endpoint, overrides = {}) {
  try {
    const base = getByDotPath(mockResponses, endpoint, 'Mock response');
    return { ...base, ...overrides };
  } catch (error) {
    console.warn(`Mock response not found for endpoint: ${endpoint}`);
    return { ...overrides };
  }
}

/**
 * Ottiene test data per una categoria specifica
 * @param {string} category - Categoria dei test data (es: "users.admin")
 * @returns {object} Test data
 */
function getTestData(category) {
  return getByDotPath(testData, category, 'Test data');
}

/**
 * Crea un utente di test
 * @param {string} role - Ruolo dell'utente (admin, operator, viewer)
 * @param {object} overrides - Valori da sovrascrivere
 * @returns {object} User object
 */
function createTestUser(role = 'admin', overrides = {}) {
  try {
    const baseUser = getTestData(`users.${role}`);
    return { ...baseUser, ...overrides };
  } catch (error) {
    console.warn(`User role not found: ${role}, using default admin`);
    const defaultUser = {
      id: 1,
      username: 'admin',
      email: 'admin@test.local',
      role: 'admin',
      active: true,
      permissions: ['firewall:read', 'firewall:write', 'system:read', 'system:write']
    };
    return { ...defaultUser, ...overrides };
  }
}

/**
 * Crea una regola firewall di test
 * @param {boolean} valid - Se la regola deve essere valida
 * @param {number} index - Indice della regola da usare
 * @param {object} overrides - Valori da sovrascrivere
 * @returns {object} Firewall rule object
 */
function createTestFirewallRule(valid = true, index = 0, overrides = {}) {
  try {
    const bucket = valid ? 'valid_rules' : 'invalid_rules';
    const rules = getTestData(`firewall_rules.${bucket}`);
    
    if (!Array.isArray(rules) || index >= rules.length) {
      throw new Error(`Rule index ${index} out of bounds for ${bucket}`);
    }
    
    const baseRule = rules[index];
    return {
      uuid: `test-rule-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      enabled: '1',
      sequence: index + 1,
      ...baseRule,
      ...overrides
    };
  } catch (error) {
    console.warn(`Error creating test rule: ${error.message}`);
    // Fallback con regola di default
    const defaultRule = {
      uuid: `fallback-rule-${Date.now()}`,
      enabled: '1',
      sequence: 1,
      action: 'pass',
      interface: 'wan',
      direction: 'in',
      protocol: 'tcp',
      source_net: 'any',
      destination_net: '192.168.1.10',
      destination_port: '80',
      description: 'Test rule'
    };
    return { ...defaultRule, ...overrides };
  }
}

/**
 * Crea multiple regole firewall di test
 * @param {number} count - Numero di regole da creare
 * @param {boolean} valid - Se le regole devono essere valide
 * @returns {Array} Array di firewall rules
 */
function createMultipleFirewallRules(count = 5, valid = true) {
  const rules = [];
  
  for (let i = 0; i < count; i++) {
    try {
      const rule = createTestFirewallRule(valid, i % 5, {
        uuid: `test-rule-${i + 1}`,
        sequence: i + 1,
        description: `Test rule ${i + 1}`
      });
      rules.push(rule);
    } catch (error) {
      console.warn(`Error creating rule ${i + 1}: ${error.message}`);
    }
  }
  
  return rules;
}

/**
 * Crea un alert di test
 * @param {string} type - Tipo di alert (security, performance, configuration)
 * @param {string} severity - Livello di severità (low, medium, high)
 * @param {object} overrides - Valori da sovrascrivere
 * @returns {object} Alert object
 */
function createTestAlert(type = 'security', severity = 'medium', overrides = {}) {
  try {
    const alerts = getTestData('alerts.sample_alerts');
    const base = alerts.find(a => a.type === type && a.severity === severity) || alerts[0];
    
    return {
      ...base,
      id: `test-alert-${Date.now()}`,
      timestamp: new Date().toISOString(),
      ...overrides
    };
  } catch (error) {
    console.warn(`Error creating test alert: ${error.message}`);
    return {
      id: `fallback-alert-${Date.now()}`,
      type,
      severity,
      title: 'Test Alert',
      description: 'Test alert description',
      timestamp: new Date().toISOString(),
      status: 'active',
      acknowledged: false,
      ...overrides
    };
  }
}

/**
 * Crea un audit log di test
 * @param {string} action - Azione del log
 * @param {number} userId - ID dell'utente
 * @param {object} overrides - Valori da sovrascrivere
 * @returns {object} Audit log object
 */
function createTestAuditLog(action = 'firewall.rule.create', userId = 1, overrides = {}) {
  try {
    const logs = getTestData('audit_logs.sample_logs');
    const base = logs.find(l => l.action === action) || logs[0];
    
    return {
      ...base,
      id: `test-log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: userId,
      ...overrides
    };
  } catch (error) {
    console.warn(`Error creating test audit log: ${error.message}`);
    return {
      id: `fallback-log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: userId,
      action,
      resource: 'test_resource',
      success: true,
      ...overrides
    };
  }
}

/**
 * Crea un JWT token di test
 * @param {object} payload - Payload del token
 * @param {number} expiresIn - Durata in secondi
 * @returns {string} JWT token
 */
function createTestJWTToken(payload = {}, expiresIn = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const defaultPayload = {
    sub: '1',
    username: 'admin',
    role: 'admin',
    iat: now,
    exp: now + expiresIn
  };
  
  const finalPayload = { ...defaultPayload, ...payload };
  
  // Simula la struttura di un JWT (header.payload.signature)
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payloadStr = Buffer.from(JSON.stringify(finalPayload)).toString('base64url');
  const signature = 'fake_signature_for_testing';
  
  return `${header}.${payloadStr}.${signature}`;
}

/**
 * Crea un errore di rete di test
 * @param {string} type - Tipo di errore (timeout, connection_refused, ssl_error)
 * @returns {Error} Network error
 */
function createNetworkError(type = 'timeout') {
  try {
    const errorData = getMockResponse(`errors.${type}`);
    const error = new Error(errorData.message);
    error.code = errorData.code;
    if (errorData.status) error.status = errorData.status;
    return error;
  } catch (err) {
    const error = new Error('Network error');
    error.code = 'NETWORK_ERROR';
    return error;
  }
}

/**
 * Crea un errore HTTP di test
 * @param {number} status - Status code HTTP
 * @param {string} message - Messaggio di errore
 * @returns {Error} HTTP error
 */
function createHTTPError(status = 500, message = null) {
  const statusMap = {
    400: 'bad_request',
    401: 'unauthorized', 
    403: 'forbidden',
    404: 'not_found',
    429: 'rate_limit',
    500: 'server_error'
  };
  
  const errorKey = statusMap[status] || 'server_error';
  
  try {
    const base = getMockResponse(`errors.${errorKey}`);
    const error = new Error(message || base.message);
    
    // Simula la struttura di un errore HTTP (come Axios)
    error.response = {
      status,
      statusText: getStatusText(status),
      data: {
        ...base,
        message: message || base.message
      }
    };
    
    return error;
  } catch (err) {
    const error = new Error(message || 'HTTP Error');
    error.response = {
      status,
      statusText: getStatusText(status),
      data: { message: message || 'HTTP Error' }
    };
    return error;
  }
}

function getStatusText(status) {
  const statusTexts = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden', 
    404: 'Not Found',
    429: 'Too Many Requests',
    500: 'Internal Server Error'
  };
  return statusTexts[status] || 'Unknown';
}

/**
 * Crea configurazione per rate limiting
 * @param {object} config - Configurazione personalizzata
 * @returns {object} Rate limit config
 */
function createRateLimitConfig(config = {}) {
  try {
    const defaultConfig = getTestData('test_scenarios.rate_limiting');
    return { ...defaultConfig, ...config };
  } catch (error) {
    return {
      api_endpoint: '/api/v1/test',
      max_requests_per_minute: 60,
      burst_size: 20,
      test_requests: 100,
      ...config
    };
  }
}

/**
 * Crea dati per test di performance
 * @param {number} size - Numero di elementi da creare
 * @returns {Array} Array di test data
 */
function createPerformanceTestData(size = 1000) {
  const results = [];
  
  for (let i = 0; i < size; i++) {
    const item = createTestFirewallRule(true, 0, {
      uuid: `perf-test-rule-${i}`,
      sequence: i + 1,
      description: `Performance test rule ${i + 1}`
    });
    results.push(item);
  }
  
  return results;
}

/**
 * Valida un oggetto contro un fixture
 * @param {object} obj - Oggetto da validare
 * @param {string} fixtureType - Tipo di fixture per la validazione
 * @returns {boolean} True se valido
 */
function validateAgainstFixture(obj, fixtureType) {
  try {
    const expected = getTestData(fixtureType);
    
    if (!obj || typeof obj !== 'object') return false;
    if (!expected || typeof expected !== 'object') return false;
    
    const expectedKeys = Object.keys(expected);
    const objKeys = Object.keys(obj);
    
    return expectedKeys.every(key => objKeys.includes(key));
  } catch (error) {
    console.warn(`Validation error for fixture type ${fixtureType}: ${error.message}`);
    return false;
  }
}

/**
 * Reset dello stato dei fixtures (se necessario)
 */
function reset() {
  // Per ora non c'è stato da resettare dato che cloniamo sempre i dati
  // Questa funzione può essere estesa in futuro se necessario
}

/**
 * Verifica se i fixtures sono stati caricati correttamente
 * @returns {boolean} True se i fixtures sono disponibili
 */
function isReady() {
  return mockResponses && testData && 
         Object.keys(mockResponses).length > 0 && 
         Object.keys(testData).length > 0;
}

/**
 * Ottiene informazioni di debug sui fixtures
 * @returns {object} Debug info
 */
function getDebugInfo() {
  return {
    mockResponsesLoaded: !!mockResponses && Object.keys(mockResponses).length > 0,
    testDataLoaded: !!testData && Object.keys(testData).length > 0,
    mockResponsesKeys: mockResponses ? Object.keys(mockResponses) : [],
    testDataKeys: testData ? Object.keys(testData) : []
  };
}

module.exports = {
  // Funzioni principali
  getMockResponse,
  getTestData,
  
  // Factory functions
  createTestUser,
  createTestFirewallRule,
  createMultipleFirewallRules,
  createTestAlert,
  createTestAuditLog,
  createTestJWTToken,
  
  // Error factories
  createNetworkError,
  createHTTPError,
  
  // Config factories
  createRateLimitConfig,
  createPerformanceTestData,
  
  // Utility functions
  validateAgainstFixture,
  reset,
  isReady,
  getDebugInfo,
  
  // Internal utilities (per debugging)
  _deepClone: deepClone,
  _getByDotPath: getByDotPath
};