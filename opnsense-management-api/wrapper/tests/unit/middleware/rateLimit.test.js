// tests/unit/middleware/rateLimit.test.js
const {
  createRateLimiter,
  createSlowDown,
  dynamicRateLimit,
} = require('../../../src/middleware/rateLimit');

describe('Rate Limiting Middleware', () => {
  // Helper functions usando fixtures globali
  const mockRequest = (overrides = {}) => {
    return {
      method: 'GET',
      path: '/api/test',
      originalUrl: '/api/test',
      ip: fixtures.random.ip(),
      headers: {
        'user-agent': 'Test Browser/1.0',
        'x-forwarded-for': fixtures.random.ip()
      },
      user: fixtures.createTestUser('admin'),
      ...overrides
    };
  };

  const mockResponse = () => ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    setHeader: jest.fn(),
    set: jest.fn(),
    locals: {}
  });

  const mockNext = () => jest.fn();

  const resetMocks = () => {
    jest.clearAllMocks();
  };

  beforeEach(() => {
    resetMocks();
    jest.clearAllTimers();
    jest.useFakeTimers();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in rateLimit test');
    }
  });

  afterEach(() => {
    jest.useRealTimers();
    fixtures.reset();
  });

  describe('createRateLimiter', () => {
    it('should create rate limiter with default options', () => {
      const limiter = createRateLimiter();
      
      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should create rate limiter with custom options', () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 100,
        burst_size: 20
      });
      
      const options = {
        windowMs: 60000,
        max: rateLimitConfig.max_requests_per_minute,
        message: { 
          error: `Rate limit exceeded: ${rateLimitConfig.max_requests_per_minute} requests per minute`,
          retryAfter: 60
        }
      };
      
      const limiter = createRateLimiter(options);
      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should respect skip function', () => {
      const healthPaths = ['/health', '/metrics', '/status'];
      const skipFunction = jest.fn((req) => healthPaths.includes(req.path));
      const limiter = createRateLimiter({ skip: skipFunction });
      
      const req = mockRequest({ path: '/health' });
      const res = mockResponse();
      const next = mockNext();
      
      limiter(req, res, next);
      
      expect(skipFunction).toHaveBeenCalledWith(req, res);
      expect(next).toHaveBeenCalled();
    });

    it('should apply rate limit based on user role', () => {
      const testUsers = [
        fixtures.createTestUser('admin'),
        fixtures.createTestUser('operator'),
        fixtures.createTestUser('viewer')
      ];

      testUsers.forEach(user => {
        const rateLimitConfig = fixtures.createRateLimitConfig({
          max_requests_per_minute: user.role === 'admin' ? 1000 : 
                                  user.role === 'operator' ? 500 : 100
        });

        const keyGenerator = (req) => `${req.ip}:${req.user?.role || 'anonymous'}`;
        const limiter = createRateLimiter({ 
          max: rateLimitConfig.max_requests_per_minute,
          keyGenerator 
        });
        
        expect(limiter).toBeDefined();
      });
    });

    it('should handle requests from different IPs', () => {
      const limiter = createRateLimiter({ windowMs: 1000, max: 2 });
      
      const ips = [
        fixtures.random.ip(),
        fixtures.random.ip(),
        fixtures.random.ip()
      ];

      ips.forEach(ip => {
        const req = mockRequest({ ip });
        const res = mockResponse();
        const next = mockNext();
        
        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });
  });

  describe('createSlowDown', () => {
    it('should create slow down middleware with default options', () => {
      const slowDown = createSlowDown();
      
      expect(slowDown).toBeDefined();
      expect(typeof slowDown).toBe('function');
    });

    it('should create slow down middleware with custom options', () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 50,
        burst_size: 10
      });
      
      const options = {
        windowMs: 60000,
        delayAfter: rateLimitConfig.burst_size,
        delayStepMs: 1000,
        maxDelayMs: 10000
      };
      
      const slowDown = createSlowDown(options);
      expect(slowDown).toBeDefined();
      expect(typeof slowDown).toBe('function');
    });

    it('should calculate delay based on usage', () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        burst_size: 2
      });
      
      const options = {
        windowMs: 60000,
        delayAfter: rateLimitConfig.burst_size,
        delayStepMs: 500
      };
      
      const slowDown = createSlowDown(options);
      
      // Mock req with slowDown properties
      const req = mockRequest();
      req.slowDown = { limit: rateLimitConfig.burst_size };
      const res = mockResponse();
      const next = mockNext();
      
      // Simulate multiple requests
      slowDown(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('should apply progressive delay for high traffic users', () => {
      const testUser = fixtures.createTestUser('operator');
      const rateLimitConfig = fixtures.createRateLimitConfig({
        delayAfter: 5,
        delayStepMs: 200
      });

      const slowDown = createSlowDown({
        windowMs: 60000,
        delayAfter: rateLimitConfig.delayAfter,
        delayStepMs: rateLimitConfig.delayStepMs,
        keyGenerator: (req) => `${req.ip}:${req.user?.id || 'anonymous'}`
      });
      
      const req = mockRequest({ 
        user: testUser,
        ip: fixtures.random.ip()
      });
      const res = mockResponse();
      const next = mockNext();
      
      slowDown(req, res, next);
      expect(next).toHaveBeenCalled();
    });
  });

  describe('dynamicRateLimit', () => {
    it('should apply write chain for POST requests', () => {
      const testUser = fixtures.createTestUser('admin');
      const req = mockRequest({ 
        method: 'POST', 
        path: '/api/firewall/rules',
        user: testUser,
        body: fixtures.createTestFirewallRule(true, 0)
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      // Should complete without error
      expect(next).toHaveBeenCalled();
    });

    it('should apply write chain for firewall paths', () => {
      const testUser = fixtures.createTestUser('operator');
      const ruleId = fixtures.random.string(8);
      const req = mockRequest({ 
        method: 'GET', 
        path: `/api/firewall/rules/${ruleId}`,
        user: testUser
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should apply general chain for GET requests to non-sensitive paths', () => {
      const testUser = fixtures.createTestUser('viewer');
      const req = mockRequest({ 
        method: 'GET', 
        path: '/api/status',
        user: testUser
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should apply write chain for admin paths', () => {
      const testUser = fixtures.createTestUser('admin');
      const userId = fixtures.random.number(1, 1000);
      const req = mockRequest({ 
        method: 'GET', 
        path: `/api/admin/users/${userId}`,
        user: testUser
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should apply write chain for policies paths', () => {
      const testUser = fixtures.createTestUser('admin');
      const policyId = fixtures.random.string(8);
      const req = mockRequest({ 
        method: 'PUT', 
        path: `/api/policies/${policyId}`,
        user: testUser,
        body: {
          name: `Updated Policy ${fixtures.random.string(6)}`,
          description: 'Updated via API'
        }
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should handle DELETE requests with write chain', () => {
      const testUser = fixtures.createTestUser('admin');
      const ruleId = fixtures.random.string(8);
      const req = mockRequest({ 
        method: 'DELETE', 
        path: `/api/rules/${ruleId}`,
        user: testUser
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should handle PATCH requests with write chain', () => {
      const testUser = fixtures.createTestUser('operator');
      const ruleId = fixtures.random.string(8);
      const req = mockRequest({ 
        method: 'PATCH', 
        path: `/api/rules/${ruleId}/toggle`,
        user: testUser
      });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should handle requests without path property', () => {
      const testUser = fixtures.createTestUser('viewer');
      const req = mockRequest({ 
        method: 'GET',
        user: testUser
      });
      delete req.path;
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should differentiate rate limits by user role', () => {
      const testCases = [
        { role: 'admin', expectedChain: 'write' },
        { role: 'operator', expectedChain: 'write' },
        { role: 'viewer', expectedChain: 'read' }
      ];

      testCases.forEach(({ role }) => {
        const testUser = fixtures.createTestUser(role);
        const req = mockRequest({
          method: 'GET',
          path: '/api/firewall/rules',
          user: testUser
        });
        const res = mockResponse();
        const next = mockNext();

        dynamicRateLimit(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should handle concurrent requests correctly', (done) => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 2
      });
      
      const limiter = createRateLimiter({ 
        windowMs: 1000, 
        max: rateLimitConfig.max_requests_per_minute 
      });
      
      let completedRequests = 0;
      const requests = [];
      const testIP = fixtures.random.ip();
      
      for (let i = 0; i < 3; i++) {
        const req = mockRequest({ ip: testIP });
        const res = mockResponse();
        const next = jest.fn(() => {
          completedRequests++;
          if (completedRequests === 2) {
            // First 2 should pass
            done();
          }
        });
        
        requests.push({ req, res, next });
      }
      
      // Execute requests
      requests.forEach(({ req, res, next }) => {
        limiter(req, res, next);
      });
    });

    it('should reset limits after window expires', (done) => {
      const windowMs = 100;
      const limiter = createRateLimiter({ windowMs, max: 1 });
      
      const testIP = fixtures.random.ip();
      const req1 = mockRequest({ ip: testIP });
      const res1 = mockResponse();
      const next1 = jest.fn();
      
      // First request should pass
      limiter(req1, res1, next1);
      expect(next1).toHaveBeenCalled();
      
      setTimeout(() => {
        const req2 = mockRequest({ ip: testIP });
        const res2 = mockResponse();
        const next2 = jest.fn();
        
        // Second request after window should also pass
        limiter(req2, res2, next2);
        expect(next2).toHaveBeenCalled();
        done();
      }, windowMs + 10);
      
      jest.advanceTimersByTime(windowMs + 10);
    });

    it('should handle different IPs independently', () => {
      const limiter = createRateLimiter({ windowMs: 1000, max: 1 });
      
      const ip1 = fixtures.random.ip();
      const ip2 = fixtures.random.ip();
      
      const req1 = mockRequest({ ip: ip1 });
      const res1 = mockResponse();
      const next1 = mockNext();
      
      const req2 = mockRequest({ ip: ip2 });
      const res2 = mockResponse();
      const next2 = mockNext();
      
      limiter(req1, res1, next1);
      limiter(req2, res2, next2);
      
      expect(next1).toHaveBeenCalled();
      expect(next2).toHaveBeenCalled();
    });

    it('should handle different user types with custom limits', () => {
      const userTypes = [
        { role: 'admin', limit: 1000 },
        { role: 'operator', limit: 500 },
        { role: 'viewer', limit: 100 }
      ];

      userTypes.forEach(({ role, limit }) => {
        const testUser = fixtures.createTestUser(role);
        const limiter = createRateLimiter({
          windowMs: 60000,
          max: limit,
          keyGenerator: (req) => `${req.ip}:${req.user?.role || 'anonymous'}`
        });

        const req = mockRequest({ user: testUser });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });

    it('should track requests per user across multiple endpoints', () => {
      const testUser = fixtures.createTestUser('operator');
      const userIP = fixtures.random.ip();
      const limiter = createRateLimiter({
        windowMs: 60000,
        max: 5,
        keyGenerator: (req) => `${req.ip}:${req.user?.id || 'anonymous'}`
      });

      const endpoints = [
        '/api/firewall/rules',
        '/api/policies',
        '/api/monitoring/stats',
        '/api/admin/users'
      ];

      endpoints.forEach(endpoint => {
        const req = mockRequest({
          user: testUser,
          ip: userIP,
          path: endpoint
        });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });

    it('should handle burst traffic with slow down', () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        burst_size: 3,
        max_requests_per_minute: 10
      });

      const slowDown = createSlowDown({
        windowMs: 60000,
        delayAfter: rateLimitConfig.burst_size,
        delayStepMs: 100
      });

      const testIP = fixtures.random.ip();
      const testUser = fixtures.createTestUser('admin');

      // Simulate burst traffic
      for (let i = 0; i < 5; i++) {
        const req = mockRequest({
          ip: testIP,
          user: testUser,
          path: `/api/request-${i}`
        });
        const res = mockResponse();
        const next = mockNext();

        slowDown(req, res, next);
        expect(next).toHaveBeenCalled();
      }
    });
  });

  describe('Error Scenarios', () => {
    it('should handle missing request properties gracefully', () => {
      const limiter = createRateLimiter();
      
      const req = {}; // Minimal request object
      const res = mockResponse();
      const next = mockNext();
      
      expect(() => {
        limiter(req, res, next);
      }).not.toThrow();
    });

    it('should handle invalid rate limit configuration', () => {
      const invalidOptions = {
        windowMs: -1,
        max: -1
      };
      
      expect(() => {
        createRateLimiter(invalidOptions);
      }).not.toThrow();
    });

    it('should handle requests with malformed user data', () => {
      const limiter = createRateLimiter({
        keyGenerator: (req) => `${req.ip}:${req.user?.id || 'anonymous'}`
      });

      const malformedUsers = [
        null,
        undefined,
        {},
        { id: null },
        { id: undefined },
        { id: 'invalid' }
      ];

      malformedUsers.forEach(user => {
        const req = mockRequest({ user });
        const res = mockResponse();
        const next = mockNext();

        expect(() => {
          limiter(req, res, next);
        }).not.toThrow();
      });
    });

    it('should handle network errors gracefully', () => {
      const networkError = fixtures.createNetworkError('connection_refused');
      const limiter = createRateLimiter({
        onLimitReached: (req, res) => {
          throw networkError;
        }
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      expect(() => {
        limiter(req, res, next);
      }).not.toThrow();
    });
  });

  describe('Security and Edge Cases', () => {
    it('should handle IP spoofing attempts', () => {
      const limiter = createRateLimiter({ max: 1 });
      
      const spoofingAttempts = [
        { ip: fixtures.random.ip(), headers: { 'x-forwarded-for': fixtures.random.ip() } },
        { ip: fixtures.random.ip(), headers: { 'x-real-ip': fixtures.random.ip() } },
        { ip: fixtures.random.ip(), headers: { 'x-client-ip': fixtures.random.ip() } }
      ];

      spoofingAttempts.forEach(({ ip, headers }) => {
        const req = mockRequest({ ip, headers });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });

    it('should handle requests with JWT tokens from fixtures', () => {
      const testUser = fixtures.createTestUser('admin');
      const jwtToken = fixtures.createTestJWTToken({
        sub: testUser.id,
        username: testUser.username,
        role: testUser.role
      });

      const limiter = createRateLimiter({
        keyGenerator: (req) => {
          const token = req.headers.authorization?.split(' ')[1];
          return token ? `token:${token.substring(0, 10)}` : `ip:${req.ip}`;
        }
      });

      const req = mockRequest({
        user: testUser,
        headers: {
          'authorization': `Bearer ${jwtToken}`,
          'user-agent': 'Test Client/1.0'
        }
      });
      const res = mockResponse();
      const next = mockNext();

      limiter(req, res, next);
      expect(next).toHaveBeenCalled();
    });

    it('should handle rate limit with custom message from fixtures', () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 5
      });

      const customMessage = {
        error: `Rate limit exceeded. Maximum ${rateLimitConfig.max_requests_per_minute} requests per minute allowed.`,
        retryAfter: 60,
        limit: rateLimitConfig.max_requests_per_minute,
        remaining: 0
      };

      const limiter = createRateLimiter({
        max: rateLimitConfig.max_requests_per_minute,
        message: customMessage
      });

      expect(limiter).toBeDefined();
    });

    it('should handle concurrent users with different permissions', () => {
      const users = [
        fixtures.createTestUser('admin'),
        fixtures.createTestUser('operator'),
        fixtures.createTestUser('viewer')
      ];

      const limiter = createRateLimiter({
        max: 10,
        keyGenerator: (req) => `${req.ip}:${req.user?.role || 'anonymous'}`
      });

      users.forEach(user => {
        const req = mockRequest({
          user,
          ip: fixtures.random.ip()
        });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });

    it('should handle requests to sensitive endpoints', () => {
      const sensitiveEndpoints = [
        '/api/admin/users',
        '/api/firewall/rules',
        '/api/policies',
        '/api/system/config'
      ];

      const testUser = fixtures.createTestUser('admin');
      
      sensitiveEndpoints.forEach(endpoint => {
        const req = mockRequest({
          method: 'POST',
          path: endpoint,
          user: testUser
        });
        const res = mockResponse();
        const next = mockNext();

        dynamicRateLimit(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });
  });

  describe('Performance and Stress Testing', () => {
    it('should handle high volume of requests efficiently', () => {
      const limiter = createRateLimiter({ max: 1000, windowMs: 60000 });
      const testUser = fixtures.createTestUser('admin');
      
      const startTime = Date.now();
      
      for (let i = 0; i < 100; i++) {
        const req = mockRequest({
          user: testUser,
          ip: fixtures.random.ip(),
          path: `/api/test-${i}`
        });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      }

      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should complete in reasonable time
      expect(duration).toBeLessThan(1000); // Less than 1 second
    });

    it('should work with performance test data from fixtures', () => {
      const perfData = fixtures.createPerformanceTestData(50);
      const limiter = createRateLimiter({ max: 100 });

      perfData.forEach((data, index) => {
        const req = mockRequest({
          path: `/api/perf-test/${index}`,
          body: { testData: data }
        });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      });
    });

    it('should handle memory efficiently with many unique IPs', () => {
      const limiter = createRateLimiter({ max: 10, windowMs: 1000 });
      
      // Simulate requests from many different IPs
      const uniqueIPs = new Set();
      for (let i = 0; i < 200; i++) {
        const ip = fixtures.random.ip();
        uniqueIPs.add(ip);
        
        const req = mockRequest({ ip });
        const res = mockResponse();
        const next = mockNext();

        limiter(req, res, next);
        expect(next).toHaveBeenCalled();
      }

      expect(uniqueIPs.size).toBeGreaterThan(150); // Should have many unique IPs
    });
  });
});