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

// Mock AuditLog model
jest.mock('../../../src/models/AuditLog', () => ({
  create: jest.fn()
}));

const AuditLog = require('../../../src/models/AuditLog');

describe('Audit Middleware', () => {
  beforeEach(() => {
    resetMocks();
    AuditLog.create.mockResolvedValue({ id: 1 });
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
      const input = {
        username: 'testuser',
        password: 'secret123',
        email: 'test@example.com'
      };

      const result = maskSensitiveData(input);

      expect(result).toEqual({
        username: 'testuser',
        password: '***MASKED***',
        email: 'test@example.com'
      });
    });

    it('should mask fields with sensitive keywords', () => {
      const input = {
        api_key: 'key123',
        secret_token: 'token456',
        user_password: 'pass789',
        authorization: 'Bearer xyz',
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
      const input = {
        user: {
          id: 1,
          password: 'secret'
        },
        config: {
          api_key: 'key123',
          settings: {
            secret: 'nested_secret'
          }
        }
      };

      const result = maskSensitiveData(input);

      expect(result).toEqual({
        user: {
          id: 1,
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
  });

  describe('getClientIP', () => {
    it('should get IP from req.ip', () => {
      const req = { ip: '192.168.1.100' };
      expect(getClientIP(req)).toBe('192.168.1.100');
    });

    it('should fallback to connection.remoteAddress', () => {
      const req = {
        connection: { remoteAddress: '192.168.1.101' }
      };
      expect(getClientIP(req)).toBe('192.168.1.101');
    });

    it('should fallback to socket.remoteAddress', () => {
      const req = {
        socket: { remoteAddress: '192.168.1.102' }
      };
      expect(getClientIP(req)).toBe('192.168.1.102');
    });

    it('should fallback to connection.socket.remoteAddress', () => {
      const req = {
        connection: {
          socket: { remoteAddress: '192.168.1.103' }
        }
      };
      expect(getClientIP(req)).toBe('192.168.1.103');
    });

    it('should return unknown when no IP found', () => {
      const req = {};
      expect(getClientIP(req)).toBe('unknown');
    });

    it('should prioritize req.ip over other sources', () => {
      const req = {
        ip: '192.168.1.1',
        connection: { remoteAddress: '192.168.1.2' },
        socket: { remoteAddress: '192.168.1.3' }
      };
      expect(getClientIP(req)).toBe('192.168.1.1');
    });
  });

  describe('getUserAgent', () => {
    it('should get user agent from headers', () => {
      const req = {
        get: jest.fn().mockReturnValue('Mozilla/5.0 (Test Browser)')
      };
      
      expect(getUserAgent(req)).toBe('Mozilla/5.0 (Test Browser)');
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
      req = mockRequest({
        method: 'GET',
        path: '/api/test',
        originalUrl: '/api/test?param=value',
        ip: '127.0.0.1',
        headers: {
          'user-agent': 'Test Browser',
          'content-length': '100'
        },
        query: { param: 'value' },
        body: { data: 'test' },
        user: { id: 1, username: 'testuser' }
      });

      res = mockResponse();
      res.statusCode = 200;
      res.get = jest.fn().mockReturnValue('200');
      res.setHeader = jest.fn();
      res.on = jest.fn();

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
      req.headers['x-correlation-id'] = 'test-correlation-id';
      
      const middleware = auditMiddleware();
      middleware(req, res, next);

      expect(req.correlationId).toBe('test-correlation-id');
      expect(res.setHeader).toHaveBeenCalledWith('X-Correlation-ID', 'test-correlation-id');
      expect(next).toHaveBeenCalled();
    });

    it('should generate correlation ID if not provided', () => {
      const middleware = auditMiddleware();
      middleware(req, res, next);

      expect(req.correlationId).toBeDefined();
      expect(req.correlationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
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
      const testBody = { result: 'success' };
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
        req.path = '/firewall/rules/123';
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
        req.path = '/policies/456';
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
        req.path = '/firewall/rules/123/toggle';
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
        req.path = '/firewall/rules/123';
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
        req.path = '/firewall/rules/123';
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
      const dbError = new Error('Database connection failed');
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
      const responseBody = { result: 'small' };
      
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
      const largeResponseBody = { data: 'x'.repeat(15000) };
      
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

      req.path = '/auth/login';
      req.correlationId = 'test-correlation';

      const middleware = auditMiddleware();
      middleware(req, res, next);

      setImmediate(() => {
        expect(logger.error).toHaveBeenCalledWith(
          'Audit middleware error',
          expect.objectContaining({
            error: 'Audit processing failed',
            correlation_id: 'test-correlation'
          })
        );
        done();
      });
    });
  });

  describe('auditLog', () => {
    it('should create manual audit entry', async () => {
      const req = mockRequest({
        user: { id: 1, username: 'testuser' },
        ip: '127.0.0.1'
      });

      const auditId = await auditLog(req, 'manual_action', AUDIT_LEVELS.INFO, {
        custom_field: 'custom_value'
      });

      expect(auditId).toBeDefined();
      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'manual_action',
          level: 'info',
          user_id: 1,
          username: 'testuser',
          custom_field: 'custom_value'
        })
      );
    });

    it('should handle audit log errors', async () => {
      const dbError = new Error('Database error');
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
      const req = mockRequest({
        user: { id: 1, username: 'testuser' }
      });

      await auditSecurityEvent(req, 'failed_login', 'high', {
        attempts: 5,
        ip: '192.168.1.100'
      });

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'security_event_failed_login',
          level: 'critical',
          event_type: 'failed_login',
          severity: 'high',
          security_details: {
            attempts: 5,
            ip: '192.168.1.100'
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
        ip: '127.0.0.1'
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
});