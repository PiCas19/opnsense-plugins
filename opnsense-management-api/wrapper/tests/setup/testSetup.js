const mockResponses = require('../fixtures/mock-responses.json');
const testData = require('../fixtures/test-data.json');

/**
 * Helper utility per gestire i fixtures nei test
 */
class FixturesHelper {
  
  /**
   * Ottiene un mock response per un endpoint specifico
   * @param {string} endpoint - Path dell'endpoint (es: 'firewall.getRule.success')
   * @param {object} overrides - Valori da sovrascrivere nel mock
   * @returns {object} Mock response
   */
  static getMockResponse(endpoint, overrides = {}) {
    const pathParts = endpoint.split('.');
    let response = mockResponses;
    
    for (const part of pathParts) {
      if (response[part] === undefined) {
        throw new Error(`Mock response not found for endpoint: ${endpoint}`);
      }
      response = response[part];
    }
    
    // Clona profondamente per evitare modifiche ai fixtures originali
    const clonedResponse = JSON.parse(JSON.stringify(response));
    
    // Applica override se forniti
    return { ...clonedResponse, ...overrides };
  }
  
  /**
   * Ottiene test data per una categoria specifica
   * @param {string} category - Categoria dei dati (es: 'users.admin')
   * @returns {object} Test data
   */
  static getTestData(category) {
    const pathParts = category.split('.');
    let data = testData;
    
    for (const part of pathParts) {
      if (data[part] === undefined) {
        throw new Error(`Test data not found for category: ${category}`);
      }
      data = data[part];
    }
    
    // Clona profondamente
    return JSON.parse(JSON.stringify(data));
  }
  
  /**
   * Genera un utente di test con permessi specifici
   * @param {string} role - Ruolo dell'utente (admin, operator, viewer)
   * @param {object} overrides - Valori da sovrascrivere
   * @returns {object} User object
   */
  static createTestUser(role = 'admin', overrides = {}) {
    const baseUser = this.getTestData(`users.${role}`);
    return { ...baseUser, ...overrides };
  }
  
  /**
   * Genera una regola firewall di test
   * @param {boolean} valid - Se true, genera una regola valida, altrimenti invalida
   * @param {number} index - Indice della regola da utilizzare
   * @param {object} overrides - Valori da sovrascrivere
   * @returns {object} Firewall rule object
   */
  static createTestFirewallRule(valid = true, index = 0, overrides = {}) {
    const category = valid ? 'valid_rules' : 'invalid_rules';
    const rules = this.getTestData(`firewall_rules.${category}`);
    
    if (index >= rules.length) {
      throw new Error(`Rule index ${index} out of bounds for ${category}`);
    }
    
    return { ...rules[index], ...overrides };
  }
  
  /**
   * Genera più regole firewall di test
   * @param {number} count - Numero di regole da generare
   * @param {boolean} valid - Se generare regole valide o invalide
   * @returns {Array} Array di regole firewall
   */
  static createMultipleFirewallRules(count = 5, valid = true) {
    const category = valid ? 'valid_rules' : 'invalid_rules';
    const rules = this.getTestData(`firewall_rules.${category}`);
    
    const result = [];
    for (let i = 0; i < count; i++) {
      const ruleIndex = i % rules.length;
      result.push({ 
        ...rules[ruleIndex], 
        uuid: `test-rule-${i + 1}`,
        sequence: i + 1
      });
    }
    
    return result;
  }
  
  /**
   * Genera un alert di test
   * @param {string} type - Tipo di alert (security, performance, configuration)
   * @param {string} severity - Severità (high, medium, low)
   * @param {object} overrides - Valori da sovrascrivere
   * @returns {object} Alert object
   */
  static createTestAlert(type = 'security', severity = 'medium', overrides = {}) {
    const alerts = this.getTestData('alerts.sample_alerts');
    const baseAlert = alerts.find(alert => alert.type === type && alert.severity === severity) || alerts[0];
    
    return {
      ...baseAlert,
      id: `test-alert-${Date.now()}`,
      timestamp: new Date().toISOString(),
      ...overrides
    };
  }
  
  /**
   * Genera un audit log di test
   * @param {string} action - Azione eseguita
   * @param {number} userId - ID dell'utente
   * @param {object} overrides - Valori da sovrascrivere
   * @returns {object} Audit log object
   */
  static createTestAuditLog(action = 'firewall.rule.create', userId = 1, overrides = {}) {
    const logs = this.getTestData('audit_logs.sample_logs');
    const baseLog = logs.find(log => log.action === action) || logs[0];
    
    return {
      ...baseLog,
      id: `test-log-${Date.now()}`,
      timestamp: new Date().toISOString(),
      user_id: userId,
      ...overrides
    };
  }
  
  /**
   * Genera token JWT di test
   * @param {object} payload - Payload del token
   * @param {number} expiresIn - Scadenza in secondi
   * @returns {string} JWT token
   */
  static createTestJWTToken(payload = {}, expiresIn = 3600) {
    const defaultPayload = {
      sub: '1',
      username: 'admin',
      role: 'admin',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + expiresIn
    };
    
    const finalPayload = { ...defaultPayload, ...payload };
    
    // Questo è un token di esempio, non valido crittograficamente
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
    const payloadStr = Buffer.from(JSON.stringify(finalPayload)).toString('base64');
    const signature = 'fake_signature_for_testing';
    
    return `${header}.${payloadStr}.${signature}`;
  }
  
  /**
   * Simula errore di rete
   * @param {string} type - Tipo di errore (timeout, connection_refused, ssl_error)
   * @returns {Error} Error object
   */
  static createNetworkError(type = 'timeout') {
    const errorData = this.getMockResponse(`errors.${type}`);
    const error = new Error(errorData.message);
    error.code = errorData.code;
    return error;
  }
  
  /**
   * Simula errore HTTP
   * @param {number} status - Status code HTTP
   * @param {string} message - Messaggio di errore
   * @returns {object} HTTP error object
   */
  static createHTTPError(status = 500, message = null) {
    const errorMap = {
      400: 'bad_request',
      401: 'unauthorized',
      403: 'forbidden',
      404: 'not_found',
      429: 'rate_limit',
      500: 'server_error'
    };
    
    const errorType = errorMap[status] || 'server_error';
    const errorData = this.getMockResponse(`errors.${errorType}`);
    
    return {
      response: {
        status: status,
        data: {
          ...errorData,
          message: message || errorData.message
        }
      }
    };
  }
  
  /**
   * Crea configurazione di test per rate limiting
   * @param {object} config - Configurazione personalizzata
   * @returns {object} Rate limiting config
   */
  static createRateLimitConfig(config = {}) {
    const defaultConfig = this.getTestData('test_scenarios.rate_limiting');
    return { ...defaultConfig, ...config };
  }
  
  /**
   * Crea dataset per test di performance
   * @param {number} size - Dimensione del dataset
   * @returns {Array} Array di oggetti per test di carico
   */
  static createPerformanceTestData(size = 1000) {
    const baseRule = this.createTestFirewallRule(true, 0);
    const data = [];
    
    for (let i = 0; i < size; i++) {
      data.push({
        ...baseRule,
        uuid: `perf-test-rule-${i}`,
        sequence: i + 1,
        description: `Performance test rule ${i + 1}`
      });
    }
    
    return data;
  }
  
  /**
   * Valida che un oggetto corrisponda alla struttura dei fixtures
   * @param {object} obj - Oggetto da validare
   * @param {string} fixtureType - Tipo di fixture da utilizzare per la validazione
   * @returns {boolean} true se valido
   */
  static validateAgainstFixture(obj, fixtureType) {
    try {
      const expectedStructure = this.getTestData(fixtureType);
      
      // Validazione semplice delle chiavi principali
      const expectedKeys = Object.keys(expectedStructure);
      const objKeys = Object.keys(obj);
      
      return expectedKeys.every(key => objKeys.includes(key));
    } catch (error) {
      return false;
    }
  }
  
  /**
   * Reset dei fixtures tra i test (se necessario)
   */
  static reset() {
    // Implementa logic di reset se i fixtures vengono modificati durante i test
    // Per ora, dato che cloniamo sempre, non è necessario
  }
}

module.exports = FixturesHelper;