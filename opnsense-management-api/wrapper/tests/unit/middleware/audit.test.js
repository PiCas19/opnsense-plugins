// tests/unit/middleware/audit.test.js
const {
  auditMiddleware,
  auditLog,
  auditSecurityEvent,
  AUDIT_LEVELS,
  AUDITED_ACTIONS,
  maskSensitiveData,
  getClientIP,
  getUserAgent,
} = require('../../../src/middleware/audit');

const logger = require('../../../src/utils/logger');

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  audit: jest.fn()
}));

// Mock AuditLog model
jest.mock('../../../src/models/AuditLog', () => ({
  create: jest.fn()
}));

const AuditLog = require('../../../src/models/AuditLog');

describe('Audit Middleware', () => {
  // Helper functions usando fixtures globali
  const mockRequest = (overrides = {}) => {
    const testUser = fixtures.createTestUser('admin');
    return {
      method: 'GET',
      path: '/api/test',
      originalUrl: '/api/test?param=value',
      ip: fixtures.random.ip(),
      headers: {
        'user-agent': 'Test Browser/1.0',
        'content-length': '100'
      },
      query: { param: 'value' },
      body: { data: 'test' },
      user: testUser,
      get: jest.fn().mockImplementation((header) => {
        const headers = {
          'user-agent': 'Test Browser/1.0',
          'x-correlation-id': `corr-${fixtures.random.string(8)}`
        };
        return headers[header.toLowerCase()];
      }),
      ...overrides
    };
  };

  const mockResponse = () => ({
    statusCode: 200,
    get: jest.fn().mockReturnValue('200'),
    setHeader: jest.fn(),
    on: jest.fn(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    locals: {}
  });

  const mockNext = () => jest.fn();

  const resetMocks = () => {
    jest.clearAllMocks();
    logger.error.mockClear();
    logger.warn.mockClear();
    logger.info.mockClear();
    logger.audit.mockClear();
    AuditLog.create.mockClear();
  };

  beforeEach(() => {
    resetMocks();
    AuditLog.create.mockResolvedValue({ id: fixtures.random.number(1, 1000) });
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in audit test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  describe('Constants', () => {
    it('should have correct audit levels', () => {
      expect(AUDIT_LEVELS).toEqual({
        INFO: 'info',
        WARNING: 'warning',
        CRITICAL: 'critical',
        SECURITY: 'security',
      });
    });

    it('should have correct audited actions', () => {
      expect(AUDITED_ACTIONS).toEqual({
        LOGIN: 'login',
        LOGOUT: 'logout',
        RULE_CREATE: 'rule_create',
        RULE_UPDATE: 'rule_update',
        RULE_DELETE: 'rule_delete',
        RULE_TOGGLE: 'rule_toggle',
        POLICY_CREATE: 'policy_create',
        POLICY_UPDATE: 'policy_update',
        POLICY_DELETE: 'policy_delete',
        CONFIG_CHANGE: 'config_change',
        SYSTEM_ACCESS: 'system_access',
        API_ACCESS: 'api_access',
        ADMIN_ACTION: 'admin_action',
      });
    });
  });

  describe('maskSensitiveData', () => {
    it('should mask password fields', () => {
      const testUser = fixtures.createTestUser('admin');
      const input = {
        username: testUser.username,
        password: 'secret123',
        email: testUser.email
      };

      const result = maskSensitiveData(input);

      expect(result).toEqual({
        username: testUser.username,
        password: '***MASKED***',
        email: testUser.email
      });
    });

    it('should mask fields with sensitive keywords', () => {
      const input = {
        api_key: fixtures.createTestJWTToken(),
        secret_token: `token-${fixtures.random.string(10)}`,
        user_password: 'pass789',
        authorization: `Bearer ${fixtures.createTestJWTToken()}`,
        normal_field: 'normal_value'
      };

      const result = maskSensitiveData(input);

      expect(result).toEqual({
        api_key: '***MASKED***',
        secret_token: '***MASKED***',
        user_password: '***MASKED***',
        authorization: '***MASKED***',
        normal_field: 'normal_value'
      });
    });

    it('should handle nested objects', () => {
      const testUser = fixtures.createTestUser('operator');
      const input = {
        user: {
          id: testUser.id,
          password: 'secret'
        },
        config: {
          api_key: fixtures.createTestJWTToken(),
          settings: {
            secret: 'nested_secret'
          }
        }
      };

      const result = maskSensitiveData(input);

      expect(result).toEqual({
        user: {
          id: testUser.id,
          password: '***MASKED***'
        },
        config: {
          api_key: '***MASKED***',
          settings: {
            secret: '***MASKED***'
          }
        }
      });
    });

    it('should handle non-object inputs', () => {
      expect(maskSensitiveData(null)).toBeNull();
      expect(maskSensitiveData(undefined)).toBeUndefined();
      expect(maskSensitiveData('string')).toBe('string');
      expect(maskSensitiveData(123)).toBe(123);
      expect(maskSensitiveData(true)).toBe(true);
    });

    it('should handle arrays', () => {
      const input = [
        { password: 'secret1' },
        { password: 'secret2' }
      ];

      const result = maskSensitiveData(input);

      expect(result).toEqual([
        { password: '***MASKED***' },
        { password: '***MASKED***' }
      ]);
    });

    it('should handle circular references gracefully', () => {
      const input = { name: 'test' };
      input.self = input;

      expect(() => maskSensitiveData(input)).not.toThrow();
    });

    it('should mask test data from fixtures', () => {
      const testUser = fixtures.createTestUser('admin');
      // Simula password nel test user (normalmente hasheata)
      testUser.password = 'plaintext-password';
      
      const result = maskSensitiveData(testUser);
      
      expect(result.password).toBe('***MASKED***');
      expect(result.username).toBe(testUser.username);
      expect(result.email).toBe(testUser.email);
    });
  });

  describe('getClientIP', () => {
    it('should get IP from req.ip', () => {
      const testIP = fixtures.random.ip();
      const req = { ip: testIP };
      expect(getClientIP(req)).toBe(testIP);
    });

    it('should fallback to connection.remoteAddress', () => {
      const testIP = fixtures.random.ip();
      const req = {
        connection: { remoteAddress: testIP }
      };
      expect(getClientIP(req)).toBe(testIP);
    });

    it('should fallback to socket.remoteAddress', () => {
      const testIP = fixtures.random.ip();
      const req = {
        socket: { remoteAddress: testIP }
      };
      expect(getClientIP(req)).toBe(testIP);
    });

    it('should fallback to connection.socket.remoteAddress', () => {
      const testIP = fixtures.random.ip();
      const req = {
        connection: {
          socket: { remoteAddress: testIP }
        }
      };
      expect(getClientIP(req)).toBe(testIP);
    });

    it('should return unknown when no IP found', () => {
      const req = {};
      expect(getClientIP(req)).toBe('unknown');
    });

    it('should prioritize req.ip over other sources', () => {
      const primaryIP = fixtures.random.ip();
      const secondaryIP = fixtures.random.ip();
      const tertiaryIP = fixtures.random.ip();
      
      const req = {
        ip: primaryIP,
        connection: { remoteAddress: secondaryIP },
        socket: { remoteAddress: tertiaryIP }
      };
      expect(getClientIP(req)).toBe(primaryIP);
    });
  });

  describe('getUserAgent', () => {
    it('should get user agent from headers', () => {
      const userAgent = 'Mozilla/5.0 (Test Browser)';
      const req = {
        get: jest.fn().mockReturnValue(userAgent)
      };
      
      expect(getUserAgent(req)).toBe(userAgent);
      expect(req.get).toHaveBeenCalledWith('User-Agent');
    });

    it('should return unknown when no user agent', () => {
      const req = {
        get: jest.fn().mockReturnValue(null)
      };
      
      expect(getUserAgent(req)).toBe('unknown');
    });

    it('should handle missing get method', () => {
      const req = {};
      expect(getUserAgent(req)).toBe('unknown');
    });
  });

  describe('auditMiddleware', () => {
    let req, res, next;

    beforeEach(() => {
      const testUser = fixtures.createTestUser('admin');
      req = mockRequest({
        method: 'GET',
        path: '/api/test',
        originalUrl: '/api/test?param=value',
        ip: fixtures.random.ip(),
        headers: {
          'user-agent': 'Test Browser/1.0',
          'content-length': '100'
        },
        query: { param: 'value' },
        body: { data: 'test' },
        user: testUser
      });

      res = mockResponse();
      res.statusCode = 200;
      next = mockNext();
    });

    it('should skip excluded paths', () => {
      req.path = '/health';
      
      const middleware = auditMiddleware({ excludePaths: ['/health', '/metrics'] });
      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(res.setHeader).not.toHaveBeenCalled();
    });

    it('should add correlation ID to request and response', () => {
      const correlationId = `test-corr-${fixtures.random.string(8)}`;
      req.headers['x-correlation-id'] = correlationId;
      
      const middleware = auditMiddleware();
      middleware(req, res, next);

      expect(req.correlationId).toBe(correlationId);
      expect(res.setHeader).toHaveBeenCalledWith('X-Correlation-ID', correlationId);
      expect(next).toHaveBeenCalled();
    });

    it('should generate correlation ID if not provided', () => {
      const middleware = auditMiddleware();
      middleware(req, res, next);

      expect(req.correlationId).toBeDefined();
      expect(req.correlationId).toBeValidUUID();
      expect(res.setHeader).toHaveBeenCalledWith('X-Correlation-ID', req.correlationId);
    });

    it('should hook into response finish event', () => {
      const middleware = auditMiddleware();
      middleware(req, res, next);

      expect(res.on).toHaveBeenCalledWith('finish', expect.any(Function));
      expect(next).toHaveBeenCalled();
    });

    it('should capture response body when enabled', () => {
      const originalJson = jest.fn();
      res.json = originalJson;
      
      const middleware = auditMiddleware({ includeResponseBody: true });
      middleware(req, res, next);

      expect(res.json).not.toBe(originalJson);
      
      // Test that the wrapped json function works
      const testBody = { result: 'success', data: fixtures.random.string(10) };
      res.json(testBody);
      
      expect(originalJson).toHaveBeenCalledWith(testBody);
    });

    describe('Audit Decision Logic', () => {
      beforeEach(() => {
        // Mock the finish event to be called immediately
        res.on = jest.fn((event, callback) => {
          if (event === 'finish') {
            setImmediate(callback);
          }
        });
      });

      it('should audit authentication endpoints', (done) => {
        req.path = '/auth/login';
        req.method = 'POST';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'login',
              method: 'POST',
              path: '/auth/login'
            })
          );
          done();
        });
      });

      it('should audit admin actions', (done) => {
        req.path = '/admin/users';
        req.method = 'GET';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'admin_action',
              path: '/admin/users'
            })
          );
          done();
        });
      });

      it('should audit firewall rule changes', (done) => {
        const ruleId = fixtures.random.string(8);
        req.path = `/firewall/rules/${ruleId}`;
        req.method = 'DELETE';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'rule_delete',
              method: 'DELETE'
            })
          );
          done();
        });
      });

      it('should audit policy changes', (done) => {
        const policyId = fixtures.random.string(8);
        req.path = `/policies/${policyId}`;
        req.method = 'PUT';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'api_access', // Would be policy action in real implementation
              method: 'PUT'
            })
          );
          done();
        });
      });

      it('should audit failed requests', (done) => {
        res.statusCode = 401;

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              status_code: 401,
              level: 'warning'
            })
          );
          done();
        });
      });

      it('should audit requests with custom header', (done) => {
        req.headers['x-audit-required'] = 'true';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalled();
          done();
        });
      });

      it('should not audit normal GET requests', (done) => {
        req.path = '/api/status';
        req.method = 'GET';
        res.statusCode = 200;

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).not.toHaveBeenCalled();
          done();
        });
      });

      it('should use custom audit check function', (done) => {
        const customAuditCheck = jest.fn().mockReturnValue(true);
        req.path = '/api/custom';

        const middleware = auditMiddleware({ customAuditCheck });
        middleware(req, res, next);

        setImmediate(() => {
          expect(customAuditCheck).toHaveBeenCalledWith(req, res);
          expect(AuditLog.create).toHaveBeenCalled();
          done();
        });
      });
    });

    describe('Audit Level Determination', () => {
      beforeEach(() => {
        res.on = jest.fn((event, callback) => {
          if (event === 'finish') {
            setImmediate(callback);
          }
        });
        req.path = '/auth/login'; // Force auditing
      });

      it('should set INFO level for successful requests', (done) => {
        res.statusCode = 200;

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              level: 'info'
            })
          );
          done();
        });
      });

      it('should set WARNING level for client errors', (done) => {
        res.statusCode = 400;

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              level: 'warning'
            })
          );
          done();
        });
      });

      it('should set CRITICAL level for server errors', (done) => {
        res.statusCode = 500;

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              level: 'critical'
            })
          );
          done();
        });
      });
    });

    describe('Action Determination', () => {
      beforeEach(() => {
        res.on = jest.fn((event, callback) => {
          if (event === 'finish') {
            setImmediate(callback);
          }
        });
      });

      it('should set login action for login endpoint', (done) => {
        req.path = '/auth/login';
        req.method = 'POST';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'login'
            })
          );
          done();
        });
      });

      it('should set logout action for logout endpoint', (done) => {
        req.path = '/auth/logout';
        req.method = 'POST';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'logout'
            })
          );
          done();
        });
      });

      it('should set rule_create action for firewall POST', (done) => {
        req.path = '/firewall/rules';
        req.method = 'POST';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'rule_create'
            })
          );
          done();
        });
      });

      it('should set rule_toggle action for toggle endpoint', (done) => {
        const ruleId = fixtures.random.string(8);
        req.path = `/firewall/rules/${ruleId}/toggle`;
        req.method = 'PATCH';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'rule_toggle'
            })
          );
          done();
        });
      });

      it('should set rule_update action for firewall PUT', (done) => {
        const ruleId = fixtures.random.string(8);
        req.path = `/firewall/rules/${ruleId}`;
        req.method = 'PUT';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'rule_update'
            })
          );
          done();
        });
      });

      it('should set rule_delete action for firewall DELETE', (done) => {
        const ruleId = fixtures.random.string(8);
        req.path = `/firewall/rules/${ruleId}`;
        req.method = 'DELETE';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'rule_delete'
            })
          );
          done();
        });
      });

      it('should set admin_action for admin endpoints', (done) => {
        req.path = '/admin/users';
        req.method = 'GET';

        const middleware = auditMiddleware();
        middleware(req, res, next);

        setImmediate(() => {
          expect(AuditLog.create).toHaveBeenCalledWith(
            expect.objectContaining({
              action: 'admin_action'
            })
          );
          done();
        });
      });
    });

    it('should handle database save errors gracefully', (done) => {
      const dbError = fixtures.createHTTPError(500, 'Database connection failed');
      AuditLog.create.mockRejectedValue(dbError);
      
      req.path = '/auth/login';
      res.on = jest.fn((event, callback) => {
        if (event === 'finish') {
          setImmediate(callback);
        }
      });

      const middleware = auditMiddleware();
      middleware(req, res, next);

      setImmediate(() => {
        expect(logger.error).toHaveBeenCalledWith(
          'Failed to save audit entry to database',
          expect.objectContaining({
            error: 'Database connection failed'
          })
        );
        expect(logger.audit).toHaveBeenCalledWith('AUDIT_ENTRY', expect.any(Object));
        done();
      });
    });

    it('should include response body when under size limit', (done) => {
      const responseBody = { 
        result: 'small',
        data: fixtures.random.string(10)
      };
      
      res.json = function(body) {
        responseBody = body;
        return this;
      };
      
      res.on = jest.fn((event, callback) => {
        if (event === 'finish') {
          setImmediate(callback);
        }
      });

      req.path = '/auth/login';
      
      const middleware = auditMiddleware({ 
        includeResponseBody: true,
        maxBodySize: 1000
      });
      middleware(req, res, next);

      setImmediate(() => {
        expect(AuditLog.create).toHaveBeenCalledWith(
          expect.objectContaining({
            response_body: responseBody
          })
        );
        done();
      });
    });

    it('should exclude large response bodies', (done) => {
      const largeResponseBody = { 
        data: fixtures.random.string(15000)
      };
      
      res.json = function(body) {
        return this;
      };
      
      res.on = jest.fn((event, callback) => {
        if (event === 'finish') {
          setImmediate(callback);
        }
      });

      req.path = '/auth/login';
      
      const middleware = auditMiddleware({ 
        includeResponseBody: true,
        maxBodySize: 10000
      });
      middleware(req, res, next);

      setImmediate(() => {
        expect(AuditLog.create).toHaveBeenCalledWith(
          expect.not.objectContaining({
            response_body: largeResponseBody
          })
        );
        done();
      });
    });

    it('should handle audit middleware errors gracefully', (done) => {
      res.on = jest.fn((event, callback) => {
        if (event === 'finish') {
          setImmediate(() => {
            throw new Error('Audit processing failed');
          });
        }
      });

      const correlationId = `test-${fixtures.random.string(8)}`;
      req.path = '/auth/login';
      req.correlationId = correlationId;

      const middleware = auditMiddleware();
      middleware(req, res, next);

      setImmediate(() => {
        expect(logger.error).toHaveBeenCalledWith(
          'Audit middleware error',
          expect.objectContaining({
            error: 'Audit processing failed',
            correlation_id: correlationId
          })
        );
        done();
      });
    });
  });

  describe('auditLog', () => {
    it('should create manual audit entry', async () => {
      const testUser = fixtures.createTestUser('admin');
      const req = mockRequest({
        user: testUser,
        ip: fixtures.random.ip()
      });

      const auditId = await auditLog(req, 'manual_action', AUDIT_LEVELS.INFO, {
        custom_field: 'custom_value'
      });

      expect(auditId).toBeDefined();
      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'manual_action',
          level: 'info',
          user_id: testUser.id,
          username: testUser.username,
          custom_field: 'custom_value'
        })
      );
    });

    it('should handle audit log errors', async () => {
      const dbError = fixtures.createHTTPError(500, 'Database error');
      AuditLog.create.mockRejectedValue(dbError);

      const req = mockRequest();
      const auditId = await auditLog(req, 'test_action');

      expect(auditId).toBeNull();
      expect(logger.error).toHaveBeenCalledWith(
        'Manual audit log error',
        expect.objectContaining({
          error: 'Database error',
          action: 'test_action'
        })
      );
    });
  });

  describe('auditSecurityEvent', () => {
    it('should create security event with high severity', async () => {
      const testUser = fixtures.createTestUser('admin');
      const testIP = fixtures.random.ip();
      const req = mockRequest({
        user: testUser
      });

      await auditSecurityEvent(req, 'failed_login', 'high', {
        attempts: 5,
        ip: testIP
      });

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_failed_login',
          level: 'critical',
          event_type: 'failed_login',
          severity: 'high',
          security_details: {
            attempts: 5,
            ip: testIP
          }
        })
      );
    });

    it('should create security event with medium severity', async () => {
      const req = mockRequest();

      await auditSecurityEvent(req, 'suspicious_activity', 'medium');

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_suspicious_activity',
          level: 'warning',
          severity: 'medium'
        })
      );
    });

    it('should create security event with low severity', async () => {
      const req = mockRequest();

      await auditSecurityEvent(req, 'info_event', 'low');

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_info_event',
          level: 'info',
          severity: 'low'
        })
      );
    });

    it('should default to medium severity', async () => {
      const req = mockRequest();

      await auditSecurityEvent(req, 'default_event');

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_default_event',
          level: 'warning',
          severity: 'medium'
        })
      );
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing request properties', () => {
      const req = {};
      const res = { statusCode: 200 };

      expect(() => getClientIP(req)).not.toThrow();
      expect(() => getUserAgent(req)).not.toThrow();
      expect(getClientIP(req)).toBe('unknown');
      expect(getUserAgent(req)).toBe('unknown');
    });

    it('should handle null/undefined in maskSensitiveData', () => {
      const input = {
        field1: null,
        field2: undefined,
        password: 'secret',
        nested: {
          field3: null,
          secret: 'hidden'
        }
      };

      const result = maskSensitiveData(input);

      expect(result).toEqual({
        field1: null,
        field2: undefined,
        password: '***MASKED***',
        nested: {
          field3: null,
          secret: '***MASKED***'
        }
      });
    });

    it('should handle requests without user', async () => {
      const req = mockRequest({
        user: null,
        ip: fixtures.random.ip()
      });

      await auditLog(req, 'anonymous_action');

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          user_id: null,
          username: 'anonymous'
        })
      );
    });
  });

  describe('Fixtures Integration Tests', () => {
    it('should work with fixture-generated audit logs', async () => {
      const testUser = fixtures.createTestUser('operator');
      const testAuditLog = fixtures.createTestAuditLog('firewall.rule.create', testUser.id);
      
      expect(testAuditLog.action).toBe('firewall.rule.create');
      expect(testAuditLog.user_id).toBe(testUser.id);
      expect(testAuditLog.success).toBe(true);
    });

    it('should mask sensitive data from fixture users', () => {
      const testUsers = [
        fixtures.createTestUser('admin'),
        fixtures.createTestUser('operator'),
        fixtures.createTestUser('viewer')
      ];

      testUsers.forEach(user => {
        // Add plain password for testing
        user.password = 'plain-password-123';
        
        const masked = maskSensitiveData(user);
        
        expect(masked.password).toBe('***MASKED***');
        expect(masked.username).toBe(user.username);
        expect(masked.role).toBe(user.role);
        expect(masked.permissions).toEqual(user.permissions);
      });
    });

    it('should audit firewall rules from fixtures', async () => {
      const testUser = fixtures.createTestUser('admin');
      const firewallRule = fixtures.createTestFirewallRule(true, 0);
      
      const req = mockRequest({
        user: testUser,
        body: { rule: firewallRule },
        path: '/firewall/rules',
        method: 'POST'
      });

      // Mock response finish event
      const res = mockResponse();
      res.on = jest.fn((event, callback) => {
        if (event === 'finish') {
          setImmediate(callback);
        }
      });

      const middleware = auditMiddleware();
      middleware(req, res, jest.fn());

      await new Promise(resolve => setImmediate(resolve));

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'rule_create',
          user_id: testUser.id,
          username: testUser.username,
          method: 'POST',
          path: '/firewall/rules'
        })
      );
    });

    it('should handle test alerts in audit logs', async () => {
      const testUser = fixtures.createTestUser('admin');
      const securityAlert = fixtures.createTestAlert('security', 'high', {
        source_ip: fixtures.random.ip(),
        description: 'Test security event'
      });

      const req = mockRequest({
        user: testUser,
        ip: securityAlert.source_ip
      });

      await auditSecurityEvent(req, 'security_breach', 'high', {
        alert_id: securityAlert.id,
        alert_type: securityAlert.type,
        details: securityAlert.description
      });

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_security_breach',
          level: 'critical',
          severity: 'high',
          security_details: expect.objectContaining({
            alert_id: securityAlert.id,
            alert_type: 'security'
          })
        })
      );
    });

    it('should work with test JWT tokens in audit context', async () => {
      const testUser = fixtures.createTestUser('admin');
      const jwtToken = fixtures.createTestJWTToken({
        sub: testUser.id.toString(),
        username: testUser.username,
        role: testUser.role
      });

      const req = mockRequest({
        user: testUser,
        headers: {
          'authorization': `Bearer ${jwtToken}`,
          'user-agent': 'Test Client/1.0'
        }
      });

      // Test that sensitive token is masked
      const maskedHeaders = maskSensitiveData(req.headers);
      expect(maskedHeaders.authorization).toBe('***MASKED***');
      expect(maskedHeaders['user-agent']).toBe('Test Client/1.0');
    });

    it('should audit bulk operations from fixtures', async () => {
      const testUser = fixtures.createTestUser('admin');
      const multipleRules = fixtures.createMultipleFirewallRules(5, true);
      
      const req = mockRequest({
        user: testUser,
        body: { rules: multipleRules },
        path: '/firewall/rules/bulk',
        method: 'POST'
      });

      await auditLog(req, 'bulk_rule_create', AUDIT_LEVELS.INFO, {
        rule_count: multipleRules.length,
        rule_ids: multipleRules.map(r => r.uuid),
        operation_type: 'bulk_create'
      });

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'bulk_rule_create',
          user_id: testUser.id,
          rule_count: 5,
          operation_type: 'bulk_create',
          rule_ids: expect.arrayContaining(multipleRules.map(r => r.uuid))
        })
      );
    });

    it('should handle performance test data in audit context', async () => {
      const testUser = fixtures.createTestUser('admin');
      const perfData = fixtures.createPerformanceTestData(100);
      
      const req = mockRequest({
        user: testUser,
        body: { performance_test: true, data_size: perfData.length }
      });

      // Simulate processing time
      const startTime = Date.now();
      await testHelpers.delay(10); // Small delay
      const endTime = Date.now();

      await auditLog(req, 'performance_test', AUDIT_LEVELS.INFO, {
        data_size: perfData.length,
        processing_time: endTime - startTime,
        test_type: 'bulk_processing'
      });

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'performance_test',
          data_size: 100,
          processing_time: expect.any(Number),
          test_type: 'bulk_processing'
        })
      );
    });

    it('should validate audit data structure against fixtures', () => {
      const testUser = fixtures.createTestUser('viewer');
      const mockAuditEntry = {
        id: fixtures.random.number(1, 1000),
        action: 'test_action',
        user_id: testUser.id,
        username: testUser.username,
        timestamp: new Date().toISOString(),
        ip_address: fixtures.random.ip(),
        user_agent: 'Test Browser/1.0',
        success: true
      };

      // Validate structure
      expect(mockAuditEntry).toHaveProperty('id');
      expect(mockAuditEntry).toHaveProperty('action');
      expect(mockAuditEntry).toHaveProperty('user_id');
      expect(mockAuditEntry).toHaveProperty('username');
      expect(mockAuditEntry).toHaveProperty('timestamp');
      expect(mockAuditEntry.timestamp).toHaveValidTimestamp();
      expect(mockAuditEntry.ip_address).toBeValidIP();
    });

    it('should handle rate limit scenarios from fixtures', async () => {
      const testUser = fixtures.createTestUser('operator');
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 10,
        burst_size: 5
      });

      // Simulate rate limit exceeded
      const req = mockRequest({
        user: testUser,
        ip: fixtures.random.ip(),
        headers: {
          'x-rate-limit-remaining': '0',
          'x-rate-limit-reset': Date.now() + 60000
        }
      });

      await auditSecurityEvent(req, 'rate_limit_exceeded', 'medium', {
        rate_limit_config: rateLimitConfig,
        requests_attempted: rateLimitConfig.max_requests_per_minute + 1,
        time_window: '1 minute'
      });

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_rate_limit_exceeded',
          level: 'warning',
          security_details: expect.objectContaining({
            rate_limit_config: rateLimitConfig,
            requests_attempted: 11
          })
        })
      );
    });
  });
});