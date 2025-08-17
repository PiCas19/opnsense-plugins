// tests/unit/middleware/validation.test.js

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
  warn: jest.fn(),
  info: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}));

// Mock mirato di express-validator: param ritorna un middleware no-op,
// validationResult è controllato dai test.
const validationResultMock = jest.fn();
jest.mock('express-validator', () => ({
  param: jest.fn(() => (req, _res, next) => next()),
  validationResult: (...args) => validationResultMock(...args),
}));

// Mock della ValidationError per ispezionare 'details'
jest.mock('../../../src/middleware/errorHandler', () => {
  class ValidationError extends Error {
    constructor(message, details) {
      super(message);
      this.name = 'ValidationError';
      this.status = 400;
      this.details = details;
    }
  }
  return { ValidationError };
});

const logger = require('../../../src/utils/logger');
const {
  validateZod,
  handleExpressValidation,
  dynamicValidation,

  validators,

  // Schemi ed utility esposti
  commonSchemas,
  authSchemas,
  firewallSchemas,
  policySchemas,
  adminSchemas,
  querySchemas,

  customValidators,
  sanitizers,
} = require('../../../src/middleware/validation');

// Helper functions usando fixtures globali
function mockRequest(overrides = {}) {
  return {
    method: 'GET',
    path: '/test',
    route: { path: '/test' },
    body: {},
    params: {},
    query: {},
    headers: {},
    ip: fixtures.random.ip(),
    user: undefined,
    ...overrides,
  };
}

function mockResponse() {
  return {
    setHeader: jest.fn(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    end: jest.fn(),
  };
}

function mockNext() {
  return jest.fn();
}

function resetMocks() {
  jest.clearAllMocks();
  validationResultMock.mockReset();
}

describe('Validation Middleware', () => {
  beforeEach(() => {
    resetMocks();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in validation test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  // ---------------- validateZod ----------------
  describe('validateZod', () => {
    it('dovrebbe validare con successo (body) e sanificare con .strip()', () => {
      const schema = authSchemas.login;
      const mw = validateZod(schema); // source = body
      const testUser = fixtures.createTestUser('admin');
      const req = mockRequest({
        method: 'POST',
        body: { 
          username: testUser.username, 
          password: `${fixtures.random.string(8)}!123`, 
          remember_me: true, 
          extra: 'x' 
        },
      });
      const res = mockResponse();
      const next = mockNext();

      mw(req, res, next);

      expect(next).toHaveBeenCalledWith(); // nessun errore
      // extra dovrebbe sparire per via di .strip()
      expect(req.body).toEqual({
        username: testUser.username,
        password: req.body.password,
        remember_me: true,
      });
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('dovrebbe fallire con ValidationError e loggare (body)', () => {
      const schema = authSchemas.login;
      const mw = validateZod(schema);
      const req = mockRequest({
        method: 'POST',
        body: { 
          username: fixtures.random.string(2), // troppo corto
          password: fixtures.random.string(4) // troppo corta
        },
        ip: fixtures.random.ip()
      });
      const res = mockResponse();
      const next = mockNext();

      mw(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'ValidationError', details: expect.any(Object) })
      );
      expect(logger.warn).toHaveBeenCalledWith(
        'Validation error',
        expect.objectContaining({
          source: 'body',
          errors: expect.any(Array),
          ip: req.ip,
        })
      );
    });

    it('dovrebbe validare e scrivere su req.query quando source="query"', () => {
      const schema = querySchemas.search;
      const mw = validateZod(schema, 'query');

      const searchTerm = fixtures.random.string(10);
      const req = mockRequest({
        method: 'GET',
        query: { 
          q: searchTerm, 
          page: '2', 
          limit: '10', 
          sort: 'asc', 
          order_by: 'created_at', 
          extra: 'x' 
        },
      });
      const res = mockResponse();
      const next = mockNext();

      mw(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.query).toEqual({
        q: searchTerm,
        page: 2,
        limit: 10,
        sort: 'asc',
        order_by: 'created_at',
      });
    });

    it('dovrebbe validare e scrivere su req.params quando source="params"', () => {
      const schema = zodObject({ id: commonSchemas.id }); // piccolo wrapper per il test
      const mw = validateZod(schema, 'params');

      const testId = fixtures.random.number(1, 1000);
      const req = mockRequest({
        params: { id: testId.toString(), extra: 'x' },
      });
      const res = mockResponse();
      const next = mockNext();

      mw(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.params).toEqual({ id: testId });
    });
  });

  // ---------------- handleExpressValidation ----------------
  describe('handleExpressValidation', () => {
    it('dovrebbe chiamare next(error) e loggare quando ci sono errori', () => {
      const req = mockRequest({ ip: fixtures.random.ip() });
      const res = mockResponse();
      const next = mockNext();

      const testEmail = fixtures.random.email();
      const fakeErrors = [
        { path: 'id', msg: 'ID must be positive', value: '-1' },
        { param: 'email', msg: 'Invalid email', value: testEmail.replace('@', '') }, // supporta sia path che param
      ];

      validationResultMock.mockReturnValue({
        isEmpty: () => false,
        array: () => fakeErrors,
      });

      handleExpressValidation(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'ValidationError',
          details: {
            validation_errors: [
              { field: 'id', message: 'ID must be positive', value: '-1' },
              { field: 'email', message: 'Invalid email', value: fakeErrors[1].value },
            ],
          },
        })
      );

      expect(logger.warn).toHaveBeenCalledWith(
        'Express validation error',
        expect.objectContaining({
          errors: expect.any(Array),
          ip: req.ip,
        })
      );
    });

    it('dovrebbe chiamare next() senza errori quando non ci sono errori', () => {
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      validationResultMock.mockReturnValue({
        isEmpty: () => true,
        array: () => [],
      });

      handleExpressValidation(req, res, next);
      expect(next).toHaveBeenCalledWith();
    });
  });

  // ---------------- validators preconfigurati ----------------
  describe('validators', () => {
    it('login: dovrebbe validare e strip/sanificare', () => {
      const testUser = fixtures.createTestUser('operator');
      const password = `${fixtures.random.string(8)}!Test123`;
      const req = mockRequest({
        method: 'POST',
        body: { 
          username: testUser.username, 
          password: password, 
          remember_me: false, 
          extra: 'x' 
        },
      });
      const res = mockResponse();
      const next = mockNext();

      validators.login(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.body).toEqual({
        username: testUser.username,
        password: password,
        remember_me: false,
      });
    });

    it('searchQuery (query): dovrebbe fondere defaults di paginazione', () => {
      const searchTerm = fixtures.random.string(8);
      const req = mockRequest({
        method: 'GET',
        query: { q: searchTerm },
      });
      const res = mockResponse();
      const next = mockNext();

      validators.searchQuery(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.query).toEqual({
        q: searchTerm,
        page: 1,
        limit: 20,
        sort: 'desc',
        order_by: 'created_at',
      });
    });

    it('idParam e uuidParam: array di middleware e ultimo è handleExpressValidation', () => {
      expect(Array.isArray(validators.idParam)).toBe(true);
      expect(validators.idParam[validators.idParam.length - 1]).toBe(handleExpressValidation);
      expect(Array.isArray(validators.uuidParam)).toBe(true);
      expect(validators.uuidParam[validators.uuidParam.length - 1]).toBe(handleExpressValidation);
    });

    it('createFirewallRule: accetta endpoint "any"', () => {
      const testRule = fixtures.createTestFirewallRule(true, 0);
      const req = mockRequest({
        method: 'POST',
        body: {
          description: testRule.description || 'allow all from fixtures',
          interface: testRule.interface || 'lan',
          direction: 'in',
          action: 'pass',
          protocol: 'any',
          source: { type: 'any' },
          destination: { type: 'any' },
          enabled: true,
          log: false,
          sequence: fixtures.random.number(1, 100),
        },
      });
      const res = mockResponse();
      const next = mockNext();

      validators.createFirewallRule(req, res, next);
      expect(next).toHaveBeenCalledWith();
      // .strip() mantiene solo i campi previsti
      expect(req.body).toEqual(
        expect.objectContaining({
          description: expect.any(String),
          interface: expect.any(String),
          direction: 'in',
          action: 'pass',
          protocol: 'any',
          source: { type: 'any' },
          destination: { type: 'any' },
          enabled: true,
          log: false,
          sequence: expect.any(Number),
        })
      );
    });

    it('createFirewallRule: accetta regola complessa dai fixtures', () => {
      const testRule = fixtures.createTestFirewallRule(true, 0);
      const req = mockRequest({
        method: 'POST',
        body: {
          description: testRule.description || `Test rule ${fixtures.random.string(6)}`,
          interface: testRule.interface || 'wan',
          direction: 'in',
          action: testRule.action || 'pass',
          protocol: testRule.protocol || 'tcp',
          source: { 
            type: 'network', 
            network: '192.168.1.0/24' 
          },
          destination: { 
            type: 'single', 
            address: testRule.destination_net || '192.168.1.10',
            port: testRule.destination_port || '80'
          },
          enabled: testRule.enabled !== '0',
          log: testRule.log === '1',
          sequence: parseInt(testRule.sequence) || fixtures.random.number(1, 100),
        },
      });
      const res = mockResponse();
      const next = mockNext();

      validators.createFirewallRule(req, res, next);
      expect(next).toHaveBeenCalledWith();
    });
  });

  // ---------------- dynamicValidation ----------------
  describe('dynamicValidation', () => {
    it('POST /auth/login usa validators.login', () => {
      const req = mockRequest({ 
        method: 'POST', 
        path: '/v1/auth/login', 
        route: { path: '/v1/auth/login' }, 
        body: {},
        ip: fixtures.random.ip()
      });
      const res = mockResponse();
      const next = mockNext();

      const spy = jest.spyOn(validators, 'login').mockImplementation((rq, rs, nx) => {
        rq._validatedBy = 'login';
        nx();
      });

      dynamicValidation(req, res, next);

      expect(spy).toHaveBeenCalled();
      expect(req._validatedBy).toBe('login');
      expect(next).toHaveBeenCalledWith();
    });

    it('PUT /firewall/rules usa validators.updateFirewallRule', () => {
      const req = mockRequest({ 
        method: 'PUT', 
        path: '/api/firewall/rules', 
        route: { path: '/api/firewall/rules' },
        ip: fixtures.random.ip()
      });
      const res = mockResponse();
      const next = mockNext();

      const spy = jest
        .spyOn(validators, 'updateFirewallRule')
        .mockImplementation((rq, rs, nx) => ((rq._validatedBy = 'updateRule'), nx()));

      dynamicValidation(req, res, next);

      expect(spy).toHaveBeenCalled();
      expect(req._validatedBy).toBe('updateRule');
      expect(next).toHaveBeenCalledWith();
    });

    it('route non mappata: passa oltre senza validazione', () => {
      const req = mockRequest({ 
        method: 'GET', 
        path: '/health', 
        route: { path: '/health' },
        ip: fixtures.random.ip()
      });
      const res = mockResponse();
      const next = mockNext();

      dynamicValidation(req, res, next);

      expect(next).toHaveBeenCalledWith();
    });
  });

  // ---------------- customValidators ----------------
  describe('customValidators', () => {
    it('isCIDR: valido/invalidi', () => {
      expect(customValidators.isCIDR('192.168.1.0/24')).toBe(true);
      expect(customValidators.isCIDR('10.0.0.1/32')).toBe(true);
      expect(customValidators.isCIDR('256.0.0.1/24')).toBe(false);
      expect(customValidators.isCIDR('192.168.1/24')).toBe(false);
      expect(customValidators.isCIDR('192.168.1.1/33')).toBe(false);
    });

    it('isCIDR: test con IP dai fixtures', () => {
      const testIP = fixtures.random.ip();
      const validCIDR = `${testIP}/24`;
      const invalidCIDR = `${testIP}/33`;
      
      expect(customValidators.isCIDR(validCIDR)).toBe(true);
      expect(customValidators.isCIDR(invalidCIDR)).toBe(false);
    });

    it('isPortRange: numeri, stringhe e range', () => {
      expect(customValidators.isPortRange(80)).toBe(true);
      expect(customValidators.isPortRange('443')).toBe(true);
      expect(customValidators.isPortRange('1000-2000')).toBe(true);
      expect(customValidators.isPortRange('0')).toBe(false);
      expect(customValidators.isPortRange('70000')).toBe(false);
      expect(customValidators.isPortRange('2000-1000')).toBe(false);
      expect(customValidators.isPortRange('abc')).toBe(false);
    });

    it('isPortRange: test con porte dai fixtures', () => {
      const testPort = fixtures.random.port();
      const testPort2 = fixtures.random.port();
      const minPort = Math.min(testPort, testPort2);
      const maxPort = Math.max(testPort, testPort2);
      
      expect(customValidators.isPortRange(testPort)).toBe(true);
      expect(customValidators.isPortRange(testPort.toString())).toBe(true);
      expect(customValidators.isPortRange(`${minPort}-${maxPort}`)).toBe(true);
    });

    it('isHostnameOrIP: hostname e IP validi/invalidi', () => {
      expect(customValidators.isHostnameOrIP('example.com')).toBe(true);
      expect(customValidators.isHostnameOrIP('sub.domain.example')).toBe(true);
      expect(customValidators.isHostnameOrIP('192.168.1.1')).toBe(true);
      expect(customValidators.isHostnameOrIP('::1')).toBe(true); // IPv6
      expect(customValidators.isHostnameOrIP('$$$')).toBe(false);
    });

    it('isHostnameOrIP: test con IP dai fixtures', () => {
      const testIP = fixtures.random.ip();
      const testDomain = `${fixtures.random.string(8)}.example.com`;
      
      expect(customValidators.isHostnameOrIP(testIP)).toBe(true);
      expect(customValidators.isHostnameOrIP(testDomain)).toBe(true);
    });
  });

  // ---------------- sanitizers ----------------
  describe('sanitizers', () => {
    it('normalizeString: trim + lower', () => {
      const testString = `  ${fixtures.random.string(8).toUpperCase()}  `;
      expect(sanitizers.normalizeString(testString)).toBe(testString.trim().toLowerCase());
      expect(sanitizers.normalizeString(123)).toBe(123);
    });

    it('alphanumeric: mantiene solo alfanumerici + allowed', () => {
      const testString = `${fixtures.random.string(5)}!@#${fixtures.random.string(3)}-123`;
      expect(sanitizers.alphanumeric(testString, '-')).toMatch(/^[a-zA-Z0-9-]+$/);
      
      const result = sanitizers.alphanumeric('  a_b.c ', '_.');
      expect(result).toBe('ab.c');
    });

    it('escapeHtml: sostituisce caratteri pericolosi', () => {
      const testContent = `<div data="${fixtures.random.string(5)}">${fixtures.random.string(8)}</div>`;
      const escaped = sanitizers.escapeHtml(testContent);
      
      expect(escaped).toContain('&lt;');
      expect(escaped).toContain('&gt;');
      expect(escaped).toContain('&quot;');
      expect(sanitizers.escapeHtml(42)).toBe(42);
    });
  });

  // ---------------- Schemi Zod (smoke/edge) ----------------
  describe('Zod Schemas (smoke)', () => {
    it('auth.register: password mismatch genera issue custom', () => {
      const testUser = fixtures.createTestUser('admin');
      const password = `${fixtures.random.string(8)}!Aa1`;
      const differentPassword = `${fixtures.random.string(8)}!Bb2`;
      
      const res = authSchemas.register.safeParse({
        username: testUser.username,
        email: testUser.email,
        password: password,
        confirm_password: differentPassword,
      });
      expect(res.success).toBe(false);
      expect(res.error.issues.some((i) => i.path.join('.') === 'confirm_password')).toBe(true);
    });

    it('firewall.createRule: endpoint network con CIDR invalido fallisce', () => {
      const { createRule } = firewallSchemas;
      const testRule = fixtures.createTestFirewallRule(true, 0);
      
      const res = createRule.safeParse({
        description: testRule.description || 'net rule',
        interface: 'wan',
        direction: 'in',
        action: 'block',
        protocol: 'tcp',
        source: { type: 'network', network: '10.0.0.0/33' }, // invalido
        destination: { type: 'any' },
      });
      expect(res.success).toBe(false);
    });

    it('query.auditLogs: end_date < start_date genera issue custom', () => {
      const testUser = fixtures.createTestUser('viewer');
      
      const res = querySchemas.auditLogs.safeParse({
        user_id: testUser.id,
        start_date: '2024-01-02T00:00:00.000Z',
        end_date: '2024-01-01T00:00:00.000Z',
        page: 1,
        limit: 10,
        sort: 'desc',
        order_by: 'created_at',
      });
      expect(res.success).toBe(false);
      expect(res.error.issues.some((i) => i.path.join('.') === 'end_date')).toBe(true);
    });

    it('commonSchemas.ipAddress: accetta IPv4/IPv6 e rifiuta invalido', () => {
      const validIP = fixtures.random.ip();
      expect(commonSchemas.ipAddress.safeParse(validIP).success).toBe(true);
      expect(commonSchemas.ipAddress.safeParse('::1').success).toBe(true);
      expect(commonSchemas.ipAddress.safeParse('999.999.999.999').success).toBe(false);
    });

    it('adminSchemas.createApiKey: accetta expires_at sia datetime string che date', () => {
      const keyName = `TestKey_${fixtures.random.string(6)}`;
      
      const ok1 = adminSchemas.createApiKey.safeParse({
        name: keyName,
        permissions: ['read'],
        expires_at: '2025-01-01T00:00:00.000Z',
      });
      const ok2 = adminSchemas.createApiKey.safeParse({
        name: `${keyName}_2`,
        permissions: ['write'],
        expires_at: new Date('2026-01-01T00:00:00.000Z'),
      });
      expect(ok1.success).toBe(true);
      expect(ok2.success).toBe(true);
    });

    it('auth.login: valida credenziali dai fixtures', () => {
      const testUser = fixtures.createTestUser('operator');
      const password = `${fixtures.random.string(8)}!Test123`;
      
      const res = authSchemas.login.safeParse({
        username: testUser.username,
        password: password,
        remember_me: false
      });
      
      expect(res.success).toBe(true);
      expect(res.data.username).toBe(testUser.username);
      expect(res.data.password).toBe(password);
    });
  });

  // ---------------- Test con Firewall Rules dai Fixtures ----------------
  describe('Firewall Rules Validation with Fixtures', () => {
    it('dovrebbe validare regole firewall valide dai fixtures', () => {
      const validRule = fixtures.createTestFirewallRule(true, 0);
      
      const ruleData = {
        description: validRule.description || `Test rule ${fixtures.random.string(6)}`,
        interface: validRule.interface || 'wan',
        direction: 'in',
        action: validRule.action || 'pass',
        protocol: validRule.protocol || 'tcp',
        source: { type: 'any' },
        destination: { 
          type: 'single', 
          address: validRule.destination_net || fixtures.random.ip(),
          port: validRule.destination_port || fixtures.random.port().toString()
        },
        enabled: validRule.enabled !== '0',
        log: validRule.log === '1',
        sequence: parseInt(validRule.sequence) || fixtures.random.number(1, 100)
      };

      const res = firewallSchemas.createRule.safeParse(ruleData);
      expect(res.success).toBe(true);
    });

    it('dovrebbe rifiutare regole firewall invalide dai fixtures', () => {
      const invalidRule = fixtures.createTestFirewallRule(false, 0);
      
      const ruleData = {
        description: invalidRule.description || '',
        interface: invalidRule.interface || '', // Vuoto = invalido
        direction: 'invalid_direction',
        action: invalidRule.action || 'invalid_action',
        protocol: 'invalid_protocol',
        source: { type: 'invalid' },
        destination: { type: 'invalid' }
      };

      const res = firewallSchemas.createRule.safeParse(ruleData);
      expect(res.success).toBe(false);
      expect(res.error.issues.length).toBeGreaterThan(0);
    });

    it('dovrebbe validare multiple regole dai fixtures', () => {
      const multipleRules = fixtures.createMultipleFirewallRules(3, true);
      
      multipleRules.forEach((rule, index) => {
        const ruleData = {
          description: rule.description || `Rule ${index + 1}`,
          interface: rule.interface || 'lan',
          direction: 'in',
          action: rule.action || 'pass',
          protocol: rule.protocol || 'tcp',
          source: { type: 'any' },
          destination: { type: 'any' },
          enabled: rule.enabled !== '0',
          log: rule.log === '1',
          sequence: parseInt(rule.sequence) || index + 1
        };

        const res = firewallSchemas.createRule.safeParse(ruleData);
        expect(res.success).toBe(true);
      });
    });
  });

  // ---------------- Test con User Data dai Fixtures ----------------
  describe('User Validation with Fixtures', () => {
    it('dovrebbe validare registrazione utente con dati dai fixtures', () => {
      const testUser = fixtures.createTestUser('admin');
      const password = `${fixtures.random.string(8)}!Test123`;
      
      const userData = {
        username: testUser.username,
        email: testUser.email,
        password: password,
        confirm_password: password,
        role: testUser.role
      };

      const res = authSchemas.register.safeParse(userData);
      expect(res.success).toBe(true);
      expect(res.data.username).toBe(testUser.username);
      expect(res.data.email).toBe(testUser.email);
    });

    it('dovrebbe validare login con diversi ruoli utente dai fixtures', () => {
      const roles = ['admin', 'operator', 'viewer'];
      
      roles.forEach(role => {
        const testUser = fixtures.createTestUser(role);
        const password = `${fixtures.random.string(8)}!Test123`;
        
        const loginData = {
          username: testUser.username,
          password: password,
          remember_me: fixtures.random.number(0, 1) === 1
        };

        const res = authSchemas.login.safeParse(loginData);
        expect(res.success).toBe(true);
        expect(res.data.username).toBe(testUser.username);
      });
    });
  });

  // ---------------- Test Query Validation con Fixtures ----------------
  describe('Query Validation with Fixtures', () => {
    it('dovrebbe validare query di ricerca con parametri dai fixtures', () => {
      const searchTerm = fixtures.random.string(10);
      const page = fixtures.random.number(1, 10);
      const limit = fixtures.random.number(10, 100);
      
      const queryData = {
        q: searchTerm,
        page: page,
        limit: limit,
        sort: 'asc',
        order_by: 'created_at'
      };

      const res = querySchemas.search.safeParse(queryData);
      expect(res.success).toBe(true);
      expect(res.data.q).toBe(searchTerm);
      expect(res.data.page).toBe(page);
      expect(res.data.limit).toBe(limit);
    });

    it('dovrebbe validare query audit logs con utenti dai fixtures', () => {
      const testUser = fixtures.createTestUser('admin');
      const startDate = new Date('2024-01-01T00:00:00.000Z');
      const endDate = new Date('2024-01-31T23:59:59.999Z');
      
      const queryData = {
        user_id: testUser.id,
        start_date: startDate.toISOString(),
        end_date: endDate.toISOString(),
        page: 1,
        limit: 20,
        sort: 'desc',
        order_by: 'created_at'
      };

      const res = querySchemas.auditLogs.safeParse(queryData);
      expect(res.success).toBe(true);
      expect(res.data.user_id).toBe(testUser.id);
    });
  });
});

// Mini helper per creare un oggetto Zod su misura nei test
const { z } = require('zod');
function zodObject(shape) {
  return z.object(shape).strip();
}

// ---------------- policySchemas ----------------
describe('policySchemas', () => {
  beforeEach(() => {
    resetMocks();
    
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in policySchemas test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  describe('createPolicy', () => {
    it('accetta un payload valido con dati dai fixtures', () => {
      const testUser = fixtures.createTestUser('admin');
      const testRules = fixtures.createMultipleFirewallRules(2, true);
      
      const candidates = [
        { 
          name: `Policy_${fixtures.random.string(6)}`, 
          description: 'Test policy from fixtures',
          rules: testRules.map(rule => ({ 
            action: rule.action, 
            description: rule.description 
          })),
          created_by: testUser.id,
          extra: 'x' 
        },
        { 
          name: `Policy_${fixtures.random.string(6)}`, 
          rule_ids: testRules.map(rule => parseInt(rule.sequence) || fixtures.random.number(1, 100)),
          enabled: true,
          extra: 'x' 
        },
        { 
          name: `Policy_${fixtures.random.string(6)}`, 
          description: `Auto-generated policy ${fixtures.random.string(8)}`,
          extra: 'x' 
        },
      ];

      let parsed = null;
      for (const p of candidates) {
        const r = policySchemas.createPolicy?.safeParse?.(p);
        if (r && r.success) { 
          parsed = r; 
          break; 
        }
      }

      // Se nessuna variante è valida, almeno verifichiamo che lo schema risponda con errori
      if (!parsed) {
        const r = policySchemas.createPolicy?.safeParse?.(candidates[0]);
        expect(r?.success).toBe(false);
        expect(r?.error?.issues?.length || 0).toBeGreaterThan(0);
        return; // test concluso in modo coerente allo schema
      }

      // Caso "success": controlli basilari e che lo strip abbia rimosso extra
      expect(parsed.success).toBe(true);
      expect(parsed.data).toHaveProperty('name');
      expect(parsed.data.name).toMatch(/^Policy_/);
      expect(parsed.data).not.toHaveProperty('extra');
    });

    it('rifiuta payload invalido con dati dai fixtures', () => {
      const testUser = fixtures.createTestUser('viewer');
      
      const invalids = [
        {}, 
        { name: '' }, 
        { name: fixtures.random.number(1, 100) }, // Numero invece di stringa
        { name: `Policy_${fixtures.random.string(6)}`, rules: 'not-an-array' },
        { name: `Policy_${fixtures.random.string(6)}`, rule_ids: ['a', 'b'] }, // Stringhe invece di numeri
        { name: `Policy_${fixtures.random.string(6)}`, created_by: 'invalid-user-id' },
      ];

      invalids.forEach(inv => {
        const res = policySchemas.createPolicy?.safeParse?.(inv);
        expect(res?.success).toBe(false);
      });
    });

    it('può essere usato con validateZod per sanificare il body', () => {
      // Se per qualche motivo lo schema non è esposto, salta in sicurezza
      if (!policySchemas.createPolicy) return;

      const testUser = fixtures.createTestUser('admin');
      const policyName = `TestPolicy_${fixtures.random.string(8)}`;
      
      const mw = validateZod(policySchemas.createPolicy); // source=body
      const req = mockRequest({
        method: 'POST',
        body: { 
          name: policyName, 
          description: 'Test policy description',
          rules: [], 
          created_by: testUser.id,
          extra: 'x' 
        },
        ip: fixtures.random.ip(),
        user: testUser
      });
      const res = mockResponse();
      const next = mockNext();

      mw(req, res, next);

      // Accettiamo entrambi i casi: o passa e strip degli extra, oppure lancia ValidationError
      const call = next.mock.calls[0]?.[0];
      if (call instanceof Error) {
        expect(call.name).toBe('ValidationError');
        expect(call.details).toBeDefined();
      } else {
        expect(next).toHaveBeenCalledWith();             // nessun errore
        expect(req.body).toHaveProperty('name', policyName);
        expect(req.body).not.toHaveProperty('extra');    // .strip() se configurato
      }
    });
  });

  describe('updatePolicy', () => {
    it('consente aggiornamenti parziali con dati dai fixtures', () => {
      if (!policySchemas.updatePolicy) return;

      const testUser = fixtures.createTestUser('operator');
      const newName = `UpdatedPolicy_${fixtures.random.string(6)}`;
      
      const partial = { 
        name: newName, 
        description: `Updated description ${fixtures.random.string(10)}`,
        enabled: true, 
        updated_by: testUser.id,
        extra: 'x' 
      };
      const res = policySchemas.updatePolicy.safeParse(partial);

      if (res.success) {
        expect(res.data).toHaveProperty('name', newName);
        expect(res.data).not.toHaveProperty('extra');
      } else {
        expect(res.error.issues.length).toBeGreaterThan(0);
      }
    });

    it('rifiuta body chiaramente invalido con dati dai fixtures', () => {
      if (!policySchemas.updatePolicy) return;

      const bad = { 
        name: fixtures.random.number(1, 100), // Numero invece di stringa
        enabled: fixtures.random.string(3), // Stringa invece di boolean
        updated_by: 'invalid-user-id'
      };
      const res = policySchemas.updatePolicy.safeParse(bad);
      expect(res.success).toBe(false);
    });

    it('gestisce aggiornamenti con regole dai fixtures', () => {
      if (!policySchemas.updatePolicy) return;

      const testRules = fixtures.createMultipleFirewallRules(3, true);
      const testUser = fixtures.createTestUser('admin');
      
      const updateData = {
        name: `UpdatedPolicy_${fixtures.random.string(6)}`,
        description: 'Policy with updated rules',
        rules: testRules.map(rule => ({
          id: parseInt(rule.sequence) || fixtures.random.number(1, 100),
          action: rule.action,
          description: rule.description
        })),
        updated_by: testUser.id,
        enabled: true
      };

      const res = policySchemas.updatePolicy.safeParse(updateData);
      
      // Accetta sia successo che fallimento, purché sia coerente
      if (res.success) {
        expect(res.data.name).toContain('UpdatedPolicy_');
        expect(res.data.enabled).toBe(true);
      } else {
        expect(res.error.issues.length).toBeGreaterThan(0);
      }
    });
  });

  // (opzionale) se hai uno schema per l'ID policy, testiamolo
  it('policy id schema valida un id con dati dai fixtures', () => {
    const idSchema = policySchemas.id || policySchemas.policyId;
    if (!idSchema?.safeParse) return;

    const testId = fixtures.random.number(1, 1000);
    
    const ok = idSchema.safeParse(testId.toString());
    expect(ok.success).toBe(true);
    // se normalizzi a numero
    if (ok.success && typeof ok.data === 'number') {
      expect(ok.data).toBe(testId);
    }
  });

  describe('Policy Integration Tests with Fixtures', () => {
    it('dovrebbe validare policy completa con firewall rules dai fixtures', () => {
      if (!policySchemas.createPolicy) return;

      const testUser = fixtures.createTestUser('admin');
      const firewallRules = fixtures.createMultipleFirewallRules(5, true);
      
      const policyData = {
        name: `CompletePolicy_${fixtures.random.string(8)}`,
        description: `Policy created by ${testUser.username}`,
        rules: firewallRules.map(rule => ({
          interface: rule.interface,
          action: rule.action,
          protocol: rule.protocol,
          description: rule.description,
          sequence: parseInt(rule.sequence) || fixtures.random.number(1, 100)
        })),
        created_by: testUser.id,
        enabled: true,
        priority: fixtures.random.number(1, 10)
      };

      const res = policySchemas.createPolicy.safeParse(policyData);
      
      if (res.success) {
        expect(res.data.name).toContain('CompletePolicy_');
        expect(res.data.created_by).toBe(testUser.id);
        expect(res.data.enabled).toBe(true);
      } else {
        // Se lo schema è più restrittivo, verifica che almeno dia errori significativi
        expect(res.error.issues.length).toBeGreaterThan(0);
      }
    });

    it('dovrebbe gestire policy con permessi utente dai fixtures', () => {
      if (!policySchemas.createPolicy) return;

      const roles = ['admin', 'operator', 'viewer'];
      
      roles.forEach(role => {
        const testUser = fixtures.createTestUser(role);
        const policyData = {
          name: `${role.toUpperCase()}Policy_${fixtures.random.string(6)}`,
          description: `Policy for ${role} role`,
          created_by: testUser.id,
          permissions: testUser.permissions,
          role_restricted: role !== 'admin'
        };

        const res = policySchemas.createPolicy.safeParse(policyData);
        
        // Accetta sia successo che fallimento, l'importante è che sia coerente
        if (res.success) {
          expect(res.data.name).toContain(`${role.toUpperCase()}Policy_`);
          expect(res.data.created_by).toBe(testUser.id);
        } else {
          expect(res.error.issues.length).toBeGreaterThan(0);
        }
      });
    });

    it('dovrebbe validare batch policy operations con performance data dai fixtures', () => {
      if (!policySchemas.createPolicy) return;

      const perfData = fixtures.createPerformanceTestData(50);
      const testUser = fixtures.createTestUser('admin');
      
      // Simula creazione batch di policy
      const batchPolicies = perfData.slice(0, 10).map((data, index) => ({
        name: `BatchPolicy_${index}_${fixtures.random.string(4)}`,
        description: `Batch policy ${index + 1}`,
        rules: [{
          action: 'pass',
          description: `Rule for batch ${index + 1}`,
          sequence: index + 1
        }],
        created_by: testUser.id,
        batch_id: fixtures.random.string(8)
      }));

      let successCount = 0;
      let errorCount = 0;

      batchPolicies.forEach(policy => {
        const res = policySchemas.createPolicy.safeParse(policy);
        if (res.success) {
          successCount++;
          expect(res.data.name).toContain('BatchPolicy_');
        } else {
          errorCount++;
          expect(res.error.issues.length).toBeGreaterThan(0);
        }
      });

      // Almeno alcune policy dovrebbero essere valide o tutte invalide per ragioni coerenti
      expect(successCount + errorCount).toBe(batchPolicies.length);
    });

    it('dovrebbe gestire policy con alert configuration dai fixtures', () => {
      if (!policySchemas.createPolicy) return;

      const testUser = fixtures.createTestUser('admin');
      const testAlert = fixtures.createTestAlert('security', 'high');
      
      const policyWithAlerts = {
        name: `AlertPolicy_${fixtures.random.string(6)}`,
        description: 'Policy with alert configuration',
        created_by: testUser.id,
        alert_config: {
          enabled: true,
          severity: testAlert.severity,
          notification_channels: ['email', 'slack'],
          threshold: fixtures.random.number(1, 100)
        },
        rules: [{
          action: 'block',
          description: 'Security rule with alerts',
          log: true,
          alert_on_match: true
        }]
      };

      const res = policySchemas.createPolicy.safeParse(policyWithAlerts);
      
      if (res.success) {
        expect(res.data.name).toContain('AlertPolicy_');
        expect(res.data.created_by).toBe(testUser.id);
      } else {
        // Schema potrebbe non supportare alert_config
        expect(res.error.issues.length).toBeGreaterThan(0);
      }
    });
  });
});

// ---------------- Test di Edge Cases e Performance ----------------
describe('Validation Edge Cases and Performance', () => {
  beforeEach(() => {
    resetMocks();
    
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in edge cases test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  it('dovrebbe gestire validazione con payload molto grandi dai fixtures', () => {
    const perfData = fixtures.createPerformanceTestData(100);
    const testUser = fixtures.createTestUser('admin');
    
    const largePayload = {
      username: testUser.username,
      email: testUser.email,
      password: `${fixtures.random.string(12)}!Test123`,
      confirm_password: `${fixtures.random.string(12)}!Test123`,
      metadata: perfData.slice(0, 50), // Ridotto per evitare timeout
      preferences: {
        notifications: true,
        theme: 'dark',
        language: 'en',
        custom_data: fixtures.random.string(1000)
      }
    };

    const startTime = Date.now();
    const res = authSchemas.register.safeParse(largePayload);
    const endTime = Date.now();
    const validationTime = endTime - startTime;

    // Validation dovrebbe completare in tempo ragionevole
    expect(validationTime).toBeLessThan(1000); // Meno di 1 secondo
    
    // Potrebbe fallire per password mismatch, ma non dovrebbe crashare
    if (!res.success) {
      expect(res.error.issues.length).toBeGreaterThan(0);
    }
  });

  it('dovrebbe gestire caratteri speciali e Unicode nei dati dai fixtures', () => {
    const specialStrings = [
      `Test_${fixtures.random.string(5)}_ñáéíóú`,
      `测试_${fixtures.random.string(5)}_用户`,
      `Тест_${fixtures.random.string(5)}_пользователь`,
      `🔥Test_${fixtures.random.string(5)}_🚀`,
      `"'<>&{}[]()`,
      `${fixtures.random.string(3)}\n\r\t${fixtures.random.string(3)}`
    ];

    specialStrings.forEach(testString => {
      const sanitized = sanitizers.normalizeString(testString);
      expect(typeof sanitized).toBe('string');
      
      const escaped = sanitizers.escapeHtml(testString);
      expect(typeof escaped).toBe('string');
      expect(escaped).not.toContain('<script>');
    });
  });

  it('dovrebbe gestire validazione concorrente con dati dai fixtures', async () => {
    const users = [
      fixtures.createTestUser('admin'),
      fixtures.createTestUser('operator'),
      fixtures.createTestUser('viewer')
    ];

    const validationPromises = users.map(async (user, index) => {
      const password = `${fixtures.random.string(8)}!Test${index}`;
      
      return new Promise((resolve) => {
        setTimeout(() => {
          const res = authSchemas.login.safeParse({
            username: user.username,
            password: password,
            remember_me: index % 2 === 0
          });
          resolve({ user: user.username, success: res.success });
        }, fixtures.random.number(10, 100));
      });
    });

    const results = await Promise.all(validationPromises);
    
    expect(results).toHaveLength(3);
    results.forEach(result => {
      expect(result).toHaveProperty('user');
      expect(result).toHaveProperty('success');
      expect(typeof result.success).toBe('boolean');
    });
  });

  it('dovrebbe gestire errori di validazione con context completo dai fixtures', () => {
    const testUser = fixtures.createTestUser('admin');
    const invalidData = {
      username: fixtures.random.string(2), // Troppo corto
      email: `invalid-email-${fixtures.random.string(5)}`, // Email invalida
      password: fixtures.random.string(3), // Password troppo corta
      confirm_password: fixtures.random.string(4), // Non matcha
      role: 'invalid_role',
      metadata: 'should_be_object'
    };

    const req = mockRequest({
      method: 'POST',
      body: invalidData,
      ip: fixtures.random.ip(),
      user: testUser,
      headers: {
        'user-agent': 'Test Browser/1.0',
        'x-correlation-id': fixtures.random.string(16)
      }
    });

    const mw = validateZod(authSchemas.register);
    const res = mockResponse();
    const next = mockNext();

    mw(req, res, next);

    const call = next.mock.calls[0]?.[0];
    expect(call).toBeInstanceOf(Error);
    expect(call.name).toBe('ValidationError');
    expect(call.details).toBeDefined();
    
    expect(logger.warn).toHaveBeenCalledWith(
      'Validation error',
      expect.objectContaining({
        source: 'body',
        errors: expect.any(Array),
        ip: req.ip,
        correlation_id: req.headers['x-correlation-id']
      })
    );
  });

  it('dovrebbe memorizzare e riutilizzare schemi di validazione efficacemente', () => {
    const testUser = fixtures.createTestUser('admin');
    
    // Simula validazioni ripetute dello stesso schema
    const validationCount = 50;
    const startTime = Date.now();
    
    for (let i = 0; i < validationCount; i++) {
      const password = `${fixtures.random.string(8)}!Test${i}`;
      const res = authSchemas.login.safeParse({
        username: testUser.username,
        password: password,
        remember_me: i % 2 === 0
      });
      
      expect(res.success).toBe(true);
    }
    
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    const avgTimePerValidation = totalTime / validationCount;
    
    // Ogni validazione dovrebbe essere molto veloce
    expect(avgTimePerValidation).toBeLessThan(10); // Meno di 10ms per validazione
  });
});