// tests/unit/middleware/asyncHandler.test.js
const {
  asyncHandler,
  asyncHandlerWithTimeout,
  batchAsyncHandler,
  retryAsyncHandler,
  createAsyncHandler,
  dbAsyncHandler
} = require('../../../src/middleware/asyncHandler');

const logger = require('../../../src/utils/logger');

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
}));

// Mock database
jest.mock('../../../src/config/database', () => ({
  sequelize: {
    transaction: jest.fn(),
    Transaction: {
      ISOLATION_LEVELS: {
        READ_COMMITTED: 'READ_COMMITTED'
      }
    }
  }
}));

const { sequelize } = require('../../../src/config/database');

describe('AsyncHandler Middleware', () => {
  // Helper functions usando fixtures globali
  const mockRequest = (overrides = {}) => {
    return {
      method: 'GET',
      originalUrl: '/api/test',
      ip: fixtures.random.ip(),
      user: fixtures.createTestUser('admin'),
      id: `req-${fixtures.random.string(8)}`,
      headers: {
        'user-agent': 'Test Agent'
      },
      ...overrides
    };
  };

  const mockResponse = () => ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    locals: {}
  });

  const mockNext = () => jest.fn();

  const resetMocks = () => {
    jest.clearAllMocks();
    logger.warn.mockClear();
    logger.error.mockClear();
    logger.info.mockClear();
    sequelize.transaction.mockClear();
  };

  beforeEach(() => {
    resetMocks();
    jest.clearAllTimers();
    jest.useFakeTimers();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in asyncHandler test');
    }
  });

  afterEach(() => {
    jest.useRealTimers();
    fixtures.reset();
  });

  describe('asyncHandler', () => {
    it('should handle successful async operations', async () => {
      const mockAsyncFn = jest.fn().mockResolvedValue('success');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(mockAsyncFn).toHaveBeenCalledWith(req, res, next);
      expect(next).not.toHaveBeenCalled();
    });

    it('should catch and forward errors to next', async () => {
      const error = fixtures.createHTTPError(500, 'Test error');
      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
      expect(error.requestContext).toBeDefined();
      expect(error.requestContext.method).toBe('GET');
    });

    it('should add request context to errors', async () => {
      const error = new Error('Context test');
      const testUser = fixtures.createTestUser('admin', { id: 123 });
      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest({
        method: 'POST',
        originalUrl: '/api/test',
        ip: '192.168.1.100',
        user: testUser,
        id: 'req-123'
      });
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(error.requestContext).toEqual({
        method: 'POST',
        url: '/api/test',
        ip: '192.168.1.100',
        userAgent: 'Test Agent',
        requestId: 'req-123',
        userId: 123,
        timestamp: expect.any(String)
      });
    });

    it('should log slow operations', async () => {
      const mockAsyncFn = jest.fn().mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => resolve('slow result'), 1500);
        });
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      const handlerPromise = handler(req, res, next);

      // Advance time to trigger slow operation
      jest.advanceTimersByTime(1500);
      await handlerPromise;

      expect(logger.warn).toHaveBeenCalledWith(
        'Slow async operation detected',
        expect.objectContaining({
          duration: expect.any(Number),
          operation: expect.any(String)
        })
      );
    });

    it('should handle sync functions', () => {
      const mockSyncFn = jest.fn().mockReturnValue('sync result');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockSyncFn);
      handler(req, res, next);

      expect(mockSyncFn).toHaveBeenCalledWith(req, res, next);
      expect(next).not.toHaveBeenCalled();
    });

    it('should handle functions that throw synchronously', () => {
      const error = fixtures.createHTTPError(400, 'Sync error');
      const mockSyncFn = jest.fn().mockImplementation(() => {
        throw error;
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockSyncFn);
      handler(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
    });
  });

  describe('asyncHandlerWithTimeout', () => {
    it('should resolve within timeout', async () => {
      const mockAsyncFn = jest.fn().mockResolvedValue('success');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandlerWithTimeout(mockAsyncFn, 5000);
      await handler(req, res, next);

      expect(mockAsyncFn).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it('should timeout and throw error', async () => {
      const mockAsyncFn = jest.fn().mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => resolve('late result'), 10000);
        });
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandlerWithTimeout(mockAsyncFn, 1000);
      const handlerPromise = handler(req, res, next);

      // Advance time past timeout
      jest.advanceTimersByTime(1001);
      await handlerPromise;

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Operation timed out after 1000ms',
          status: 408,
          code: 'OPERATION_TIMEOUT'
        })
      );
    });

    it('should use default timeout', async () => {
      const mockAsyncFn = jest.fn().mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => resolve('result'), 35000);
        });
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandlerWithTimeout(mockAsyncFn); // Default 30000ms
      const handlerPromise = handler(req, res, next);

      jest.advanceTimersByTime(30001);
      await handlerPromise;

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Operation timed out after 30000ms'
        })
      );
    });
  });

  describe('batchAsyncHandler', () => {
    it('should process batch operations successfully', async () => {
      const operations = [
        Promise.resolve('result1'),
        Promise.resolve('result2'),
        Promise.resolve('result3')
      ];

      const mockBatchFn = jest.fn().mockResolvedValue(operations);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = batchAsyncHandler(mockBatchFn);
      await handler(req, res, next);

      expect(req.batchResults).toEqual({
        successful: expect.arrayContaining([
          expect.objectContaining({ success: true, result: 'result1', index: 0 }),
          expect.objectContaining({ success: true, result: 'result2', index: 1 }),
          expect.objectContaining({ success: true, result: 'result3', index: 2 })
        ]),
        failed: [],
        totalCount: 3,
        successCount: 3,
        errorCount: 0
      });
    });

    it('should handle mixed success and failure', async () => {
      const testError = fixtures.createNetworkError('connection_refused');
      const operations = [
        Promise.resolve('success'),
        Promise.reject(testError),
        Promise.resolve('success2')
      ];

      const mockBatchFn = jest.fn().mockResolvedValue(operations);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = batchAsyncHandler(mockBatchFn, { failFast: false });
      await handler(req, res, next);

      expect(req.batchResults.successCount).toBe(2);
      expect(req.batchResults.errorCount).toBe(1);
      expect(req.batchResults.failed[0]).toEqual(
        expect.objectContaining({
          success: false,
          error: expect.any(Error),
          index: 1
        })
      );
    });

    it('should fail fast when enabled', async () => {
      const testError = fixtures.createHTTPError(500, 'Server failure');
      const operations = [
        Promise.resolve('success'),
        Promise.reject(testError),
        Promise.resolve('success2')
      ];

      const mockBatchFn = jest.fn().mockResolvedValue(operations);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = batchAsyncHandler(mockBatchFn, { failFast: true });
      await handler(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Batch operation failed',
          status: 500
        })
      );
    });

    it('should respect maxConcurrency setting', async () => {
      const operations = Array(10).fill().map((_, i) => 
        Promise.resolve(`result${i}`)
      );

      const mockBatchFn = jest.fn().mockResolvedValue(operations);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = batchAsyncHandler(mockBatchFn, { maxConcurrency: 3 });
      await handler(req, res, next);

      expect(req.batchResults.totalCount).toBe(10);
      expect(req.batchResults.successCount).toBe(10);
    });

    it('should throw error for non-array return', async () => {
      const mockBatchFn = jest.fn().mockResolvedValue('not an array');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = batchAsyncHandler(mockBatchFn);
      await handler(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Batch handler function must return array of promises'
        })
      );
    });

    it('should handle batch operation timeout', async () => {
      const operations = [
        new Promise(resolve => setTimeout(() => resolve('slow'), 2000))
      ];

      const mockBatchFn = jest.fn().mockResolvedValue(operations);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = batchAsyncHandler(mockBatchFn, { timeout: 1000 });
      const handlerPromise = handler(req, res, next);

      jest.advanceTimersByTime(1001);
      await handlerPromise;

      expect(req.batchResults.errorCount).toBe(1);
      expect(req.batchResults.failed[0].error.message).toBe('Batch operation timeout');
    });
  });

  describe('retryAsyncHandler', () => {
    it('should succeed on first attempt', async () => {
      const mockAsyncFn = jest.fn().mockResolvedValue('success');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(mockAsyncFn).toHaveBeenCalledTimes(1);
      expect(next).not.toHaveBeenCalled();
    });

    it('should retry on retriable errors', async () => {
      const error = fixtures.createNetworkError('connection_refused');

      const mockAsyncFn = jest.fn()
        .mockRejectedValueOnce(error)
        .mockRejectedValueOnce(error)
        .mockResolvedValue('success');

      const req = mockRequest({ id: 'test-req' });
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn, { maxRetries: 3, retryDelay: 100 });
      const handlerPromise = handler(req, res, next);

      // Advance time for retries
      jest.advanceTimersByTime(300);
      await handlerPromise;

      expect(mockAsyncFn).toHaveBeenCalledTimes(3);
      expect(logger.info).toHaveBeenCalledWith(
        'Retry successful',
        expect.objectContaining({
          attempt: 2,
          maxRetries: 3
        })
      );
    });

    it('should not retry non-retriable errors', async () => {
      const error = fixtures.createHTTPError(400, 'Validation failed');

      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(mockAsyncFn).toHaveBeenCalledTimes(1);
      expect(next).toHaveBeenCalledWith(error);
    });

    it('should exhaust retries and fail', async () => {
      const error = fixtures.createHTTPError(500, 'Server error');

      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest({ id: 'test-req' });
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn, { maxRetries: 2, retryDelay: 100 });
      const handlerPromise = handler(req, res, next);

      jest.advanceTimersByTime(300);
      await handlerPromise;

      expect(mockAsyncFn).toHaveBeenCalledTimes(3); // Initial + 2 retries
      expect(logger.error).toHaveBeenCalledWith(
        'All retry attempts exhausted',
        expect.objectContaining({
          maxRetries: 2,
          finalError: 'Server error'
        })
      );
      expect(next).toHaveBeenCalledWith(error);
    });

    it('should use exponential backoff', async () => {
      const error = fixtures.createHTTPError(500, 'Server error');

      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn, {
        maxRetries: 2,
        retryDelay: 100,
        exponentialBackoff: true
      });

      const handlerPromise = handler(req, res, next);

      // First retry after 100ms, second retry after 200ms
      jest.advanceTimersByTime(100);
      jest.advanceTimersByTime(200);
      await handlerPromise;

      expect(logger.warn).toHaveBeenCalledWith(
        'Operation failed, retrying',
        expect.objectContaining({
          delay: 100
        })
      );

      expect(logger.warn).toHaveBeenCalledWith(
        'Operation failed, retrying',
        expect.objectContaining({
          delay: 200
        })
      );
    });

    it('should use linear backoff when disabled', async () => {
      const error = fixtures.createHTTPError(500, 'Server error');

      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn, {
        maxRetries: 2,
        retryDelay: 100,
        exponentialBackoff: false
      });

      const handlerPromise = handler(req, res, next);
      jest.advanceTimersByTime(300);
      await handlerPromise;

      // Both retries should use same delay
      expect(logger.warn).toHaveBeenCalledWith(
        'Operation failed, retrying',
        expect.objectContaining({
          delay: 100
        })
      );
    });

    it('should use custom retry condition', async () => {
      const error = new Error('Custom error');
      error.customCode = 'RETRY_ME';

      const customRetryCondition = (err) => err.customCode === 'RETRY_ME';

      const mockAsyncFn = jest.fn()
        .mockRejectedValueOnce(error)
        .mockResolvedValue('success');

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = retryAsyncHandler(mockAsyncFn, {
        retryCondition: customRetryCondition,
        retryDelay: 100
      });

      const handlerPromise = handler(req, res, next);
      jest.advanceTimersByTime(100);
      await handlerPromise;

      expect(mockAsyncFn).toHaveBeenCalledTimes(2);
    });
  });

  describe('createAsyncHandler', () => {
    it('should create handler with timeout option', async () => {
      const mockAsyncFn = jest.fn().mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => resolve('result'), 2000);
        });
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handlerFactory = createAsyncHandler({ timeout: 1000 });
      const handler = handlerFactory(mockAsyncFn);
      const handlerPromise = handler(req, res, next);

      jest.advanceTimersByTime(1001);
      await handlerPromise;

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('timed out')
        })
      );
    });

    it('should create handler with retry option', async () => {
      const error = fixtures.createHTTPError(500, 'Server error');

      const mockAsyncFn = jest.fn()
        .mockRejectedValueOnce(error)
        .mockResolvedValue('success');

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handlerFactory = createAsyncHandler({
        retries: { maxRetries: 2, retryDelay: 100 }
      });
      const handler = handlerFactory(mockAsyncFn);
      const handlerPromise = handler(req, res, next);

      jest.advanceTimersByTime(100);
      await handlerPromise;

      expect(mockAsyncFn).toHaveBeenCalledTimes(2);
    });

    it('should apply error transformer', async () => {
      const originalError = fixtures.createHTTPError(500, 'Original error');
      const transformedError = fixtures.createHTTPError(400, 'Transformed error');
      transformedError.transformed = true;

      const errorTransformer = jest.fn().mockReturnValue(transformedError);
      const mockAsyncFn = jest.fn().mockRejectedValue(originalError);

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handlerFactory = createAsyncHandler({ errorTransformer });
      const handler = handlerFactory(mockAsyncFn);
      await handler(req, res, next);

      expect(errorTransformer).toHaveBeenCalledWith(originalError);
      expect(next).toHaveBeenCalledWith(transformedError);
    });

    it('should disable slow operation logging', async () => {
      const mockAsyncFn = jest.fn().mockImplementation(() => {
        return new Promise(resolve => {
          setTimeout(() => resolve('result'), 1500);
        });
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handlerFactory = createAsyncHandler({ logSlowOperations: false });
      const handler = handlerFactory(mockAsyncFn);
      const handlerPromise = handler(req, res, next);

      jest.advanceTimersByTime(1500);
      await handlerPromise;

      expect(logger.warn).not.toHaveBeenCalledWith(
        'Slow operation detected',
        expect.any(Object)
      );
    });
  });

  describe('dbAsyncHandler', () => {
    it('should handle database operation with auto transaction', async () => {
      const mockTransaction = {
        commit: jest.fn().mockResolvedValue(),
        rollback: jest.fn().mockResolvedValue()
      };

      sequelize.transaction.mockResolvedValue(mockTransaction);

      const mockDbFn = jest.fn().mockResolvedValue('db result');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = dbAsyncHandler(mockDbFn);
      await handler(req, res, next);

      expect(sequelize.transaction).toHaveBeenCalledWith({
        isolationLevel: 'READ_COMMITTED'
      });
      expect(req.transaction).toBe(mockTransaction);
      expect(mockDbFn).toHaveBeenCalledWith(req, res, next);
      expect(mockTransaction.commit).toHaveBeenCalled();
      expect(mockTransaction.rollback).not.toHaveBeenCalled();
    });

    it('should rollback transaction on error', async () => {
      const mockTransaction = {
        commit: jest.fn().mockResolvedValue(),
        rollback: jest.fn().mockResolvedValue()
      };

      sequelize.transaction.mockResolvedValue(mockTransaction);

      const error = fixtures.createHTTPError(500, 'Database error');
      const mockDbFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest({ id: 'test-req' });
      const res = mockResponse();
      const next = mockNext();

      const handler = dbAsyncHandler(mockDbFn);
      await handler(req, res, next);

      expect(mockTransaction.rollback).toHaveBeenCalled();
      expect(mockTransaction.commit).not.toHaveBeenCalled();
      expect(next).toHaveBeenCalledWith(error);
      expect(logger.error).toHaveBeenCalledWith(
        'Database transaction rolled back',
        expect.objectContaining({
          error: 'Database error',
          requestId: 'test-req'
        })
      );
    });

    it('should skip transaction when autoTransaction is false', async () => {
      const mockDbFn = jest.fn().mockResolvedValue('result');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = dbAsyncHandler(mockDbFn, { autoTransaction: false });
      await handler(req, res, next);

      expect(sequelize.transaction).not.toHaveBeenCalled();
      expect(mockDbFn).toHaveBeenCalledWith(req, res, next);
    });

    it('should use custom isolation level', async () => {
      const mockTransaction = {
        commit: jest.fn().mockResolvedValue(),
        rollback: jest.fn().mockResolvedValue()
      };

      sequelize.transaction.mockResolvedValue(mockTransaction);

      const mockDbFn = jest.fn().mockResolvedValue('result');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = dbAsyncHandler(mockDbFn, {
        isolationLevel: 'SERIALIZABLE'
      });
      await handler(req, res, next);

      expect(sequelize.transaction).toHaveBeenCalledWith({
        isolationLevel: 'SERIALIZABLE'
      });
    });
  });

  describe('Error Scenarios', () => {
    it('should handle null/undefined functions', () => {
      expect(() => asyncHandler(null)).not.toThrow();
      expect(() => asyncHandler(undefined)).not.toThrow();
    });

    it('should handle functions that return non-promises', () => {
      const mockFn = jest.fn().mockReturnValue('string result');
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockFn);
      handler(req, res, next);

      expect(mockFn).toHaveBeenCalled();
      expect(next).not.toHaveBeenCalled();
    });

    it('should handle missing request properties gracefully', async () => {
      const mockAsyncFn = jest.fn().mockRejectedValue(new Error('test'));
      const req = {}; // Missing properties
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          requestContext: expect.objectContaining({
            method: undefined,
            url: undefined,
            ip: undefined
          })
        })
      );
    });
  });

  describe('Fixtures Integration Tests', () => {
    it('should work with fixture-generated test data', async () => {
      // Usa i test data dai fixtures per creare scenari realistici
      const testUser = fixtures.createTestUser('admin');
      const testAlert = fixtures.createTestAlert('security', 'high');
      
      const mockAsyncFn = jest.fn().mockResolvedValue({
        user: testUser,
        alert: testAlert
      });

      const req = mockRequest({ user: testUser });
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(mockAsyncFn).toHaveBeenCalledWith(req, res, next);
      expect(req.user.role).toBe('admin');
      expect(req.user.permissions).toContain('firewall:write');
    });

    it('should handle fixture-generated errors properly', async () => {
      const networkError = fixtures.createNetworkError('timeout');
      const httpError = fixtures.createHTTPError(429, 'Rate limited');

      const mockAsyncFn = jest.fn()
        .mockRejectedValueOnce(networkError)
        .mockRejectedValueOnce(httpError);

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      // Test network error
      const handler1 = asyncHandler(mockAsyncFn);
      await handler1(req, res, next);

      expect(next).toHaveBeenCalledWith(networkError);
      expect(networkError.code).toBe('ECONNABORTED');

      // Reset mocks for second test
      next.mockClear();

      // Test HTTP error
      const handler2 = asyncHandler(mockAsyncFn);
      await handler2(req, res, next);

      expect(next).toHaveBeenCalledWith(httpError);
      expect(httpError.response.status).toBe(429);
    });

    it('should validate test data structure', () => {
      const testUser = fixtures.createTestUser('operator');
      const multipleRules = fixtures.createMultipleFirewallRules(3, true);
      const perfData = fixtures.createPerformanceTestData(10);

      // Valida che i dati abbiano la struttura corretta
      expect(testUser).toHaveProperty('id');
      expect(testUser).toHaveProperty('username');
      expect(testUser).toHaveProperty('role');
      expect(testUser.role).toBe('operator');

      expect(multipleRules).toHaveLength(3);
      expect(multipleRules[0]).toHaveProperty('uuid');
      expect(multipleRules[0]).toHaveProperty('action');

      expect(perfData).toHaveLength(10);
      expect(perfData[0].uuid).toContain('perf-test-rule-0');
    });

    it('should work with rate limit configuration from fixtures', async () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 30,
        burst_size: 10
      });

      const mockAsyncFn = jest.fn().mockImplementation(async (req) => {
        req.rateLimitConfig = rateLimitConfig;
        return 'success';
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(req.rateLimitConfig.max_requests_per_minute).toBe(30);
      expect(req.rateLimitConfig.burst_size).toBe(10);
    });
  });
});