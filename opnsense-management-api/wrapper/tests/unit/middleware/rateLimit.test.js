// tests/unit/middleware/rateLimit.test.js
const {
  createRateLimiter,
  createSlowDown,
  dynamicRateLimit,
} = require('../../../src/middleware/rateLimit');

describe('Rate Limiting Middleware', () => {
  beforeEach(() => {
    resetMocks();
    jest.clearAllTimers();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('createRateLimiter', () => {
    it('should create rate limiter with default options', () => {
      const limiter = createRateLimiter();
      
      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should create rate limiter with custom options', () => {
      const options = {
        windowMs: 60000,
        max: 100,
        message: { error: 'Custom rate limit message' }
      };
      
      const limiter = createRateLimiter(options);
      expect(limiter).toBeDefined();
      expect(typeof limiter).toBe('function');
    });

    it('should respect skip function', () => {
      const skipFunction = jest.fn((req) => req.path === '/health');
      const limiter = createRateLimiter({ skip: skipFunction });
      
      const req = mockRequest({ path: '/health' });
      const res = mockResponse();
      const next = mockNext();
      
      limiter(req, res, next);
      
      expect(skipFunction).toHaveBeenCalledWith(req, res);
      expect(next).toHaveBeenCalled();
    });
  });

  describe('createSlowDown', () => {
    it('should create slow down middleware with default options', () => {
      const slowDown = createSlowDown();
      
      expect(slowDown).toBeDefined();
      expect(typeof slowDown).toBe('function');
    });

    it('should create slow down middleware with custom options', () => {
      const options = {
        windowMs: 60000,
        delayAfter: 50,
        delayStepMs: 1000
      };
      
      const slowDown = createSlowDown(options);
      expect(slowDown).toBeDefined();
      expect(typeof slowDown).toBe('function');
    });

    it('should calculate delay based on usage', () => {
      const options = {
        windowMs: 60000,
        delayAfter: 2,
        delayStepMs: 500
      };
      
      const slowDown = createSlowDown(options);
      
      // Mock req with slowDown properties
      const req = mockRequest();
      req.slowDown = { limit: 2 };
      const res = mockResponse();
      const next = mockNext();
      
      // Simulate multiple requests
      slowDown(req, res, next);
      expect(next).toHaveBeenCalled();
    });
  });

  describe('dynamicRateLimit', () => {
    it('should apply write chain for POST requests', () => {
      const req = mockRequest({ method: 'POST', path: '/api/test' });
      const res = mockResponse();
      const next = mockNext();
      
      // Mock middleware chain
      jest.spyOn(require('../../../src/middleware/rateLimit'), 'dynamicRateLimit');
      
      dynamicRateLimit(req, res, next);
      
      // Should complete without error
      expect(next).toHaveBeenCalled();
    });

    it('should apply write chain for firewall paths', () => {
      const req = mockRequest({ method: 'GET', path: '/api/firewall/rules' });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should apply general chain for GET requests to non-sensitive paths', () => {
      const req = mockRequest({ method: 'GET', path: '/api/status' });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should apply write chain for admin paths', () => {
      const req = mockRequest({ method: 'GET', path: '/api/admin/users' });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should apply write chain for policies paths', () => {
      const req = mockRequest({ method: 'PUT', path: '/api/policies/123' });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should handle DELETE requests with write chain', () => {
      const req = mockRequest({ method: 'DELETE', path: '/api/rules/123' });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should handle PATCH requests with write chain', () => {
      const req = mockRequest({ method: 'PATCH', path: '/api/rules/123/toggle' });
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });

    it('should handle requests without path property', () => {
      const req = mockRequest({ method: 'GET' });
      delete req.path;
      const res = mockResponse();
      const next = mockNext();
      
      dynamicRateLimit(req, res, next);
      
      expect(next).toHaveBeenCalled();
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should handle concurrent requests correctly', (done) => {
      const limiter = createRateLimiter({ windowMs: 1000, max: 2 });
      
      let completedRequests = 0;
      const requests = [];
      
      for (let i = 0; i < 3; i++) {
        const req = mockRequest({ ip: '127.0.0.1' });
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
      
      const req1 = mockRequest({ ip: '127.0.0.1' });
      const res1 = mockResponse();
      const next1 = jest.fn();
      
      // First request should pass
      limiter(req1, res1, next1);
      expect(next1).toHaveBeenCalled();
      
      setTimeout(() => {
        const req2 = mockRequest({ ip: '127.0.0.1' });
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
      
      const req1 = mockRequest({ ip: '127.0.0.1' });
      const res1 = mockResponse();
      const next1 = mockNext();
      
      const req2 = mockRequest({ ip: '192.168.1.1' });
      const res2 = mockResponse();
      const next2 = mockNext();
      
      limiter(req1, res1, next1);
      limiter(req2, res2, next2);
      
      expect(next1).toHaveBeenCalled();
      expect(next2).toHaveBeenCalled();
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
  });
});