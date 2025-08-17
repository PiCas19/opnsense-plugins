// tests/unit/middleware/errorHandler.test.js
const {
  errorHandler,
  asyncHandler,
  notFoundHandler,
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ExternalApiError,
  DatabaseError,
  determineErrorType,
  extractErrorDetails,
  shouldExposeError,
  sanitizeErrorMessage,
  initializeErrorHandling,
  ERROR_TYPES,
  STATUS_CODES,
} = require('../../../src/middleware/errorHandler');

const logger = require('../../../src/utils/logger');

// Mock logger
jest.mock('../../../src/utils/logger', () => ({
  error: jest.fn(),
  warn: jest.fn(),
  info: jest.fn(),
  metricsRecorder: jest.fn()
}));

describe('Error Handler Middleware', () => {
  // Helper functions usando fixtures globali
  const mockRequest = (overrides = {}) => {
    return {
      method: 'GET',
      originalUrl: '/api/test',
      ip: fixtures.random.ip(),
      user: null,
      correlationId: `corr-${fixtures.random.string(8)}`,
      headers: {
        'user-agent': 'Test Browser/1.0'
      },
      get: jest.fn().mockImplementation((header) => {
        const headers = {
          'user-agent': 'Test Browser/1.0'
        };
        return headers[header.toLowerCase()];
      }),
      ...overrides
    };
  };

  const mockResponse = () => ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    setHeader: jest.fn(),
    locals: {}
  });

  const mockNext = () => jest.fn();

  const resetMocks = () => {
    jest.clearAllMocks();
    logger.error.mockClear();
    logger.warn.mockClear();
    logger.info.mockClear();
    logger.metricsRecorder.mockClear();
  };

  beforeEach(() => {
    resetMocks();
    
    // Verifica che i fixtures siano pronti
    if (!fixtures.isReady()) {
      console.warn('Fixtures not ready in errorHandler test');
    }
  });

  afterEach(() => {
    fixtures.reset();
  });

  describe('Constants', () => {
    it('should have correct error types', () => {
      expect(ERROR_TYPES).toEqual({
        VALIDATION_ERROR: 'VALIDATION_ERROR',
        AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
        AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
        NOT_FOUND_ERROR: 'NOT_FOUND_ERROR',
        CONFLICT_ERROR: 'CONFLICT_ERROR',
        RATE_LIMIT_ERROR: 'RATE_LIMIT_ERROR',
        EXTERNAL_API_ERROR: 'EXTERNAL_API_ERROR',
        DATABASE_ERROR: 'DATABASE_ERROR',
        INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
      });
    });

    it('should have correct status codes mapping', () => {
      expect(STATUS_CODES).toEqual({
        VALIDATION_ERROR: 400,
        AUTHENTICATION_ERROR: 401,
        AUTHORIZATION_ERROR: 403,
        NOT_FOUND_ERROR: 404,
        CONFLICT_ERROR: 409,
        RATE_LIMIT_ERROR: 429,
        EXTERNAL_API_ERROR: 502,
        DATABASE_ERROR: 503,
        INTERNAL_SERVER_ERROR: 500,
      });
    });
  });

  describe('Error Classes', () => {
    describe('AppError', () => {
      it('should create error with default values', () => {
        const errorMessage = `Test error ${fixtures.random.string(6)}`;
        const error = new AppError(errorMessage);

        expect(error.message).toBe(errorMessage);
        expect(error.name).toBe('AppError');
        expect(error.type).toBe(ERROR_TYPES.INTERNAL_SERVER_ERROR);
        expect(error.statusCode).toBe(500);
        expect(error.isOperational).toBe(true);
        expect(error.timestamp).toHaveValidTimestamp();
        expect(error.details).toBeNull();
      });

      it('should create error with custom parameters', () => {
        const testUser = fixtures.createTestUser('admin');
        const details = { 
          field: 'username', 
          userId: testUser.id,
          correlationId: fixtures.random.string(10)
        };
        const errorMessage = `Custom error for ${testUser.username}`;
        
        const error = new AppError(
          errorMessage,
          ERROR_TYPES.VALIDATION_ERROR,
          400,
          details
        );

        expect(error.message).toBe(errorMessage);
        expect(error.type).toBe(ERROR_TYPES.VALIDATION_ERROR);
        expect(error.statusCode).toBe(400);
        expect(error.details).toBe(details);
      });

      it('should use default status code for error type', () => {
        const error = new AppError(
          'Auth error',
          ERROR_TYPES.AUTHENTICATION_ERROR
        );

        expect(error.statusCode).toBe(401);
      });

      it('should capture stack trace', () => {
        const error = new AppError('Test error');
        expect(error.stack).toBeDefined();
        expect(error.stack).toContain('AppError');
      });
    });

    describe('ValidationError', () => {
      it('should create validation error', () => {
        const testUser = fixtures.createTestUser('viewer');
        const details = { 
          field: 'email', 
          value: `invalid-${fixtures.random.string(5)}@`,
          userId: testUser.id 
        };
        const error = new ValidationError('Invalid email format', details);

        expect(error.message).toBe('Invalid email format');
        expect(error.type).toBe(ERROR_TYPES.VALIDATION_ERROR);
        expect(error.statusCode).toBe(400);
        expect(error.details).toBe(details);
        expect(error.isOperational).toBe(true);
      });
    });

    describe('AuthenticationError', () => {
      it('should create authentication error', () => {
        const error = new AuthenticationError('Invalid credentials');

        expect(error.message).toBe('Invalid credentials');
        expect(error.type).toBe(ERROR_TYPES.AUTHENTICATION_ERROR);
        expect(error.statusCode).toBe(401);
      });

      it('should work with fixture-generated errors', () => {
        const authError = fixtures.createHTTPError(401, 'Token expired');
        const error = new AuthenticationError(authError.message);

        expect(error.statusCode).toBe(401);
        expect(error.message).toBe('Token expired');
      });
    });

    describe('AuthorizationError', () => {
      it('should create authorization error', () => {
        const testUser = fixtures.createTestUser('viewer');
        const error = new AuthorizationError(`Access denied for user ${testUser.username}`);

        expect(error.message).toContain(testUser.username);
        expect(error.type).toBe(ERROR_TYPES.AUTHORIZATION_ERROR);
        expect(error.statusCode).toBe(403);
      });
    });

    describe('NotFoundError', () => {
      it('should create not found error', () => {
        const resourceId = fixtures.random.string(8);
        const error = new NotFoundError(`Resource ${resourceId} not found`);

        expect(error.message).toContain(resourceId);
        expect(error.type).toBe(ERROR_TYPES.NOT_FOUND_ERROR);
        expect(error.statusCode).toBe(404);
      });
    });

    describe('ConflictError', () => {
      it('should create conflict error', () => {
        const testUser = fixtures.createTestUser('admin');
        const error = new ConflictError(`User ${testUser.username} already exists`);

        expect(error.message).toContain(testUser.username);
        expect(error.type).toBe(ERROR_TYPES.CONFLICT_ERROR);
        expect(error.statusCode).toBe(409);
      });
    });

    describe('RateLimitError', () => {
      it('should create rate limit error', () => {
        const rateLimitConfig = fixtures.createRateLimitConfig();
        const error = new RateLimitError(`Rate limit exceeded: ${rateLimitConfig.max_requests_per_minute} requests/minute`);

        expect(error.message).toContain(rateLimitConfig.max_requests_per_minute.toString());
        expect(error.type).toBe(ERROR_TYPES.RATE_LIMIT_ERROR);
        expect(error.statusCode).toBe(429);
      });
    });

    describe('ExternalApiError', () => {
      it('should create external API error', () => {
        const networkError = fixtures.createNetworkError('connection_refused');
        const error = new ExternalApiError(`OPNsense API unavailable: ${networkError.message}`);

        expect(error.message).toContain('OPNsense API unavailable');
        expect(error.type).toBe(ERROR_TYPES.EXTERNAL_API_ERROR);
        expect(error.statusCode).toBe(502);
      });
    });

    describe('DatabaseError', () => {
      it('should create database error', () => {
        const dbError = fixtures.createHTTPError(503, 'Connection pool exhausted');
        const error = new DatabaseError(dbError.message);

        expect(error.message).toBe('Connection pool exhausted');
        expect(error.type).toBe(ERROR_TYPES.DATABASE_ERROR);
        expect(error.statusCode).toBe(503);
      });
    });
  });

  describe('determineErrorType', () => {
    it('should detect Sequelize validation errors', () => {
      const error = { name: 'SequelizeValidationError' };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.VALIDATION_ERROR);
    });

    it('should detect Sequelize unique constraint errors', () => {
      const error = { name: 'SequelizeUniqueConstraintError' };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.CONFLICT_ERROR);
    });

    it('should detect Sequelize foreign key constraint errors', () => {
      const error = { name: 'SequelizeForeignKeyConstraintError' };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.VALIDATION_ERROR);
    });

    it('should detect Sequelize connection errors', () => {
      const error = { name: 'SequelizeConnectionError' };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.DATABASE_ERROR);
    });

    it('should detect JWT errors', () => {
      const jwtError = { name: 'JsonWebTokenError' };
      const expiredError = { name: 'TokenExpiredError' };
      
      expect(determineErrorType(jwtError)).toBe(ERROR_TYPES.AUTHENTICATION_ERROR);
      expect(determineErrorType(expiredError)).toBe(ERROR_TYPES.AUTHENTICATION_ERROR);
    });

    it('should detect Joi validation errors', () => {
      const error = { name: 'ValidationError', isJoi: true };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.VALIDATION_ERROR);
    });

    it('should detect entity parse errors', () => {
      const error = { type: 'entity.parse.failed' };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.VALIDATION_ERROR);
    });

    it('should detect Axios errors', () => {
      const error = { isAxiosError: true };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.EXTERNAL_API_ERROR);
    });

    it('should detect AppError instances', () => {
      const error = new ValidationError('Test');
      expect(determineErrorType(error)).toBe(ERROR_TYPES.VALIDATION_ERROR);
    });

    it('should default to internal server error', () => {
      const error = { name: 'UnknownError' };
      expect(determineErrorType(error)).toBe(ERROR_TYPES.INTERNAL_SERVER_ERROR);
    });

    it('should handle fixture-generated network errors', () => {
      const networkError = fixtures.createNetworkError('timeout');
      const axiosError = {
        isAxiosError: true,
        code: networkError.code,
        message: networkError.message
      };
      
      expect(determineErrorType(axiosError)).toBe(ERROR_TYPES.EXTERNAL_API_ERROR);
    });
  });

  describe('extractErrorDetails', () => {
    it('should extract Sequelize validation error details', () => {
      const testUser = fixtures.createTestUser('admin');
      const error = {
        name: 'SequelizeValidationError',
        errors: [
          { path: 'email', message: 'Invalid email', value: `invalid-${fixtures.random.string(5)}@test` },
          { path: 'username', message: 'Too short', value: testUser.username.substring(0, 2) }
        ]
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        validation_errors: [
          { field: 'email', message: 'Invalid email', value: error.errors[0].value },
          { field: 'username', message: 'Too short', value: error.errors[1].value }
        ]
      });
    });

    it('should extract Joi validation error details', () => {
      const testEmail = fixtures.random.email();
      const error = {
        isJoi: true,
        details: [
          {
            path: ['user', 'email'],
            message: 'Email is required',
            context: { value: testEmail }
          }
        ]
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        validation_errors: [
          { field: 'user.email', message: 'Email is required', value: testEmail }
        ]
      });
    });

    it('should extract express-validator error details', () => {
      const testUser = fixtures.createTestUser('operator');
      const error = {
        array: jest.fn().mockReturnValue([
          { path: 'username', msg: 'Username is required', value: testUser.username },
          { param: 'age', msg: 'Must be a number', value: 'abc' }
        ])
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        validation_errors: [
          { field: 'username', message: 'Username is required', value: testUser.username },
          { field: 'age', message: 'Must be a number', value: 'abc' }
        ]
      });
    });

    it('should extract Axios error details', () => {
      const testUrl = `/api/firewall/rules/${fixtures.random.string(8)}`;
      const error = {
        isAxiosError: true,
        response: {
          status: 404,
          statusText: 'Not Found'
        },
        config: {
          url: testUrl,
          method: 'get'
        }
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        external_service: 'OPNsense API',
        status_code: 404,
        status_text: 'Not Found',
        url: testUrl,
        method: 'GET'
      });
    });

    it('should extract custom error details', () => {
      const testUser = fixtures.createTestUser('viewer');
      const correlationId = fixtures.random.string(10);
      const error = {
        details: {
          user_id: testUser.id,
          correlation_id: correlationId,
          reason: 'Insufficient permissions'
        }
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        user_id: testUser.id,
        correlation_id: correlationId,
        reason: 'Insufficient permissions'
      });
    });

    it('should return null for errors without details', () => {
      const error = { message: `Simple error ${fixtures.random.string(6)}` };
      const details = extractErrorDetails(error);
      expect(details).toBeNull();
    });

    it('should handle missing properties gracefully', () => {
      const axiosError = {
        isAxiosError: true,
        response: null,
        config: { method: 'post' }
      };

      const details = extractErrorDetails(axiosError);

      expect(details).toEqual({
        external_service: 'OPNsense API',
        status_code: undefined,
        status_text: undefined,
        url: undefined,
        method: 'POST'
      });
    });

    it('should extract details from fixture-generated errors', () => {
      const httpError = fixtures.createHTTPError(422, 'Validation failed');
      const error = {
        details: {
          status: httpError.response.status,
          message: httpError.message,
          timestamp: new Date().toISOString()
        }
      };

      const details = extractErrorDetails(error);

      expect(details.status).toBe(422);
      expect(details.message).toBe('Validation failed');
      expect(details.timestamp).toHaveValidTimestamp();
    });
  });

  describe('shouldExposeError', () => {
    it('should expose operational errors', () => {
      const testUser = fixtures.createTestUser('admin');
      const error = new ValidationError(`Invalid data for user ${testUser.username}`);
      expect(shouldExposeError(error)).toBe(true);
    });

    it('should expose errors in development', () => {
      const error = new Error(`Development error ${fixtures.random.string(8)}`);
      expect(shouldExposeError(error, 'development')).toBe(true);
    });

    it('should expose safe error types in production', () => {
      const safeErrors = [
        ERROR_TYPES.VALIDATION_ERROR,
        ERROR_TYPES.AUTHENTICATION_ERROR,
        ERROR_TYPES.AUTHORIZATION_ERROR,
        ERROR_TYPES.NOT_FOUND_ERROR,
        ERROR_TYPES.CONFLICT_ERROR,
        ERROR_TYPES.RATE_LIMIT_ERROR,
      ];

      safeErrors.forEach(type => {
        const error = { type };
        expect(shouldExposeError(error, 'production')).toBe(true);
      });
    });

    it('should not expose unsafe errors in production', () => {
      const unsafeErrors = [
        ERROR_TYPES.DATABASE_ERROR,
        ERROR_TYPES.EXTERNAL_API_ERROR,
        ERROR_TYPES.INTERNAL_SERVER_ERROR,
      ];

      unsafeErrors.forEach(type => {
        const error = { type };
        expect(shouldExposeError(error, 'production')).toBe(false);
      });
    });

    it('should use NODE_ENV by default', () => {
      const originalEnv = process.env.NODE_ENV;
      
      process.env.NODE_ENV = 'development';
      const error = new Error(`Test ${fixtures.random.string(6)}`);
      expect(shouldExposeError(error)).toBe(true);
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('sanitizeErrorMessage', () => {
    it('should return generic message when not exposing', () => {
      const error = new Error(`Internal error ${fixtures.random.string(8)}`);
      const result = sanitizeErrorMessage(error, false);
      expect(result).toBe('An internal server error occurred');
    });

    it('should return original message for operational errors', () => {
      const testUser = fixtures.createTestUser('operator');
      const message = `Validation failed for user ${testUser.username}`;
      const error = new ValidationError(message);
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe(message);
    });

    it('should return sanitized message for database errors', () => {
      const error = { type: ERROR_TYPES.DATABASE_ERROR };
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('Database service temporarily unavailable');
    });

    it('should return sanitized message for external API errors', () => {
      const error = { type: ERROR_TYPES.EXTERNAL_API_ERROR };
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('External service temporarily unavailable');
    });

    it('should return original or default message for other types', () => {
      const message = `Custom error ${fixtures.random.string(10)}`;
      const error = { message };
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe(message);
    });

    it('should return default message when no message available', () => {
      const error = {};
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('An error occurred');
    });
  });

  describe('errorHandler middleware', () => {
    let req, res, next;

    beforeEach(() => {
      const testUser = fixtures.createTestUser('admin');
      req = mockRequest({
        method: 'POST',
        originalUrl: '/api/test',
        ip: fixtures.random.ip(),
        user: testUser,
        correlationId: `test-${fixtures.random.string(8)}`
      });

      res = mockResponse();
      next = mockNext();
    });

    it('should handle validation errors correctly', () => {
      const testUser = fixtures.createTestUser('viewer');
      const error = new ValidationError('Invalid input', {
        field: 'email',
        value: `invalid-${fixtures.random.string(5)}@test`,
        userId: testUser.id
      });

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Invalid input',
        code: 'VALIDATION_ERROR',
        error_id: expect.any(String),
        timestamp: expect.any(String),
        details: expect.objectContaining({
          field: 'email',
          userId: testUser.id
        })
      });
    });

    it('should handle authentication errors', () => {
      const error = new AuthenticationError('Invalid token');

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Invalid token',
        code: 'AUTHENTICATION_ERROR',
        error_id: expect.any(String),
        timestamp: expect.any(String)
      });
    });

    it('should handle internal server errors with sanitized message', () => {
      const sensitiveError = new Error(`Database connection string: ${fixtures.random.string(20)}`);

      errorHandler(sensitiveError, req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'An internal server error occurred',
        code: 'INTERNAL_SERVER_ERROR',
        error_id: expect.any(String),
        timestamp: expect.any(String)
      });
    });

    it('should include stack trace in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const error = new Error(`Development error ${fixtures.random.string(8)}`);
      error.stack = 'Error stack trace';

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          stack: 'Error stack trace'
        })
      );

      process.env.NODE_ENV = originalEnv;
    });

    it('should not include stack trace in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const error = new Error(`Production error ${fixtures.random.string(8)}`);
      error.stack = 'Error stack trace';

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.not.objectContaining({
          stack: expect.any(String)
        })
      );

      process.env.NODE_ENV = originalEnv;
    });

    it('should log server errors as errors', () => {
      const error = new Error(`Server error ${fixtures.random.string(8)}`);

      errorHandler(error, req, res, next);

      expect(logger.error).toHaveBeenCalledWith(
        'Internal server error',
        expect.objectContaining({
          error_id: expect.any(String),
          type: 'INTERNAL_SERVER_ERROR',
          status_code: 500,
          url: '/api/test',
          method: 'POST',
          user_id: req.user.id,
          ip_address: req.ip,
          correlation_id: req.correlationId
        })
      );
    });

    it('should log client errors as warnings', () => {
      const error = new ValidationError(`Client error ${fixtures.random.string(8)}`);

      errorHandler(error, req, res, next);

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Client error'),
        expect.objectContaining({
          status_code: 400,
          type: 'VALIDATION_ERROR'
        })
      );
    });

    it('should handle missing request properties', () => {
      const req = {}; // Minimal request
      const error = new Error(`Test error ${fixtures.random.string(8)}`);

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
      expect(logger.error).toHaveBeenCalledWith(
        'Internal server error',
        expect.objectContaining({
          url: undefined,
          method: undefined,
          user_id: null,
          ip_address: undefined
        })
      );
    });

    it('should handle custom status codes', () => {
      const error = new AppError(
        `Custom error ${fixtures.random.string(8)}`, 
        ERROR_TYPES.VALIDATION_ERROR, 
        422
      );

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(422);
    });

    it('should handle metrics recording safely', () => {
      logger.metricsRecorder = jest.fn().mockImplementation(() => {
        throw new Error('Metrics error');
      });

      const error = new Error(`Test error ${fixtures.random.string(8)}`);

      expect(() => {
        errorHandler(error, req, res, next);
      }).not.toThrow();

      expect(logger.metricsRecorder).toHaveBeenCalled();
    });

    it('should not include details when error should not be exposed', () => {
      const error = new Error(`Internal error ${fixtures.random.string(8)}`);
      error.details = { 
        sensitive: 'data',
        apiKey: fixtures.createTestJWTToken()
      };

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.not.objectContaining({
          details: expect.any(Object)
        })
      );
    });

    it('should handle fixture-generated HTTP errors', () => {
      const httpError = fixtures.createHTTPError(429, 'Too Many Requests');
      const error = new RateLimitError(httpError.message);

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: 'Too Many Requests',
          code: 'RATE_LIMIT_ERROR'
        })
      );
    });
  });

  describe('asyncHandler', () => {
    it('should handle successful async operations', async () => {
      const testUser = fixtures.createTestUser('operator');
      const mockAsyncFn = jest.fn().mockResolvedValue({
        user: testUser,
        success: true
      });
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(mockAsyncFn).toHaveBeenCalledWith(req, res, next);
      expect(next).not.toHaveBeenCalled();
    });

    it('should catch and forward async errors', async () => {
      const error = fixtures.createHTTPError(500, 'Async operation failed');
      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
    });

    it('should handle sync functions', () => {
      const testData = {
        rules: fixtures.createMultipleFirewallRules(3, true),
        timestamp: new Date().toISOString()
      };
      const mockSyncFn = jest.fn().mockReturnValue(testData);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockSyncFn);
      handler(req, res, next);

      expect(mockSyncFn).toHaveBeenCalledWith(req, res, next);
      expect(next).not.toHaveBeenCalled();
    });

    it('should handle sync errors', () => {
      const error = fixtures.createNetworkError('connection_refused');
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

  describe('notFoundHandler', () => {
    it('should create NotFoundError with route information', () => {
      const req = mockRequest({
        method: 'GET',
        originalUrl: `/api/nonexistent/${fixtures.random.string(8)}`,
        app: {
          _router: {
            stack: [
              {
                route: {
                  path: '/api/users',
                  methods: { get: true }
                }
              },
              {
                route: {
                  path: '/api/firewall/rules',
                  methods: { post: true }
                }
              }
            ]
          }
        }
      });
      const res = mockResponse();
      const next = mockNext();

      notFoundHandler(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('Route GET /api/nonexistent/'),
          type: 'NOT_FOUND_ERROR',
          details: {
            method: 'GET',
            url: expect.stringContaining('/api/nonexistent/'),
            available_routes: [
              { method: 'GET', path: '/api/users' },
              { method: 'POST', path: '/api/firewall/rules' }
            ]
          }
        })
      );
    });

    it('should handle missing router information', () => {
      const resourceId = fixtures.random.string(8);
      const req = mockRequest({
        method: 'POST',
        originalUrl: `/api/missing/${resourceId}`
      });
      const res = mockResponse();
      const next = mockNext();

      notFoundHandler(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: `Route POST /api/missing/${resourceId} not found`,
          details: {
            method: 'POST',
            url: `/api/missing/${resourceId}`,
            available_routes: []
          }
        })
      );
    });
  });

  describe('initializeErrorHandling', () => {
    let originalListeners;

    beforeEach(() => {
      // Store original listeners
      originalListeners = {
        unhandledRejection: process.listeners('unhandledRejection'),
        uncaughtException: process.listeners('uncaughtException')
      };
      
      // Remove existing listeners
      process.removeAllListeners('unhandledRejection');
      process.removeAllListeners('uncaughtException');
    });

    afterEach(() => {
      // Restore original listeners
      process.removeAllListeners('unhandledRejection');
      process.removeAllListeners('uncaughtException');
      
      originalListeners.unhandledRejection.forEach(listener => {
        process.on('unhandledRejection', listener);
      });
      originalListeners.uncaughtException.forEach(listener => {
        process.on('uncaughtException', listener);
      });
    });

    it('should set up error handlers', () => {
      initializeErrorHandling();

      expect(process.listenerCount('unhandledRejection')).toBe(1);
      expect(process.listenerCount('uncaughtException')).toBe(1);
      expect(logger.info).toHaveBeenCalledWith('Error handling initialized');
    });

    it('should handle unhandled rejections', (done) => {
      const originalExit = process.exit;
      process.exit = jest.fn();

      initializeErrorHandling();

      // Simulate unhandled rejection with fixture error
      const errorMessage = `Unhandled rejection ${fixtures.random.string(8)}`;
      const promise = Promise.reject(new Error(errorMessage));
      
      setTimeout(() => {
        expect(logger.error).toHaveBeenCalledWith(
          'Unhandled Promise Rejection',
          expect.objectContaining({
            reason: errorMessage
          })
        );
        
        process.exit = originalExit;
        done();
      }, 10);
    });

    it('should handle uncaught exceptions', (done) => {
      const originalExit = process.exit;
      process.exit = jest.fn();

      initializeErrorHandling();

      // Mock the uncaught exception handler
      const handler = process.listeners('uncaughtException')[0];
      const errorMessage = `Uncaught exception ${fixtures.random.string(8)}`;
      const error = new Error(errorMessage);
      
      handler(error);

      expect(logger.error).toHaveBeenCalledWith(
        'Uncaught Exception',
        {
          message: errorMessage,
          stack: expect.any(String)
        }
      );
      expect(process.exit).toHaveBeenCalledWith(1);

      process.exit = originalExit;
      done();
    });

    it('should exit in production for unhandled rejections', (done) => {
      const originalEnv = process.env.NODE_ENV;
      const originalExit = process.exit;
      
      process.env.NODE_ENV = 'production';
      process.exit = jest.fn();

      initializeErrorHandling();

      // Simulate unhandled rejection
      const errorMessage = `Production error ${fixtures.random.string(8)}`;
      const promise = Promise.reject(new Error(errorMessage));
      
      setTimeout(() => {
        expect(process.exit).toHaveBeenCalledWith(1);
        
        process.env.NODE_ENV = originalEnv;
        process.exit = originalExit;
        done();
      }, 1100); // Wait longer than the timeout in the handler
    });
  });

  describe('Edge Cases and Error Scenarios', () => {
    it('should handle circular references in error objects', () => {
      const error = new Error(`Circular error ${fixtures.random.string(8)}`);
      error.circular = error;

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      expect(() => {
        errorHandler(error, req, res, next);
      }).not.toThrow();
    });

    it('should handle errors without message', () => {
      const error = new Error();
      delete error.message;

      const sanitized = sanitizeErrorMessage(error, true);
      expect(sanitized).toBe('An error occurred');
    });

    it('should handle malformed Sequelize errors', () => {
      const error = {
        name: 'SequelizeValidationError',
        errors: null
      };

      const details = extractErrorDetails(error);
      expect(details).toBeNull();
    });

    it('should handle malformed Joi errors', () => {
      const testValue = fixtures.random.string(10);
      const error = {
        isJoi: true,
        details: [
          {
            path: null,
            message: 'Invalid',
            context: { value: testValue }
          }
        ]
      };

      const details = extractErrorDetails(error);
      expect(details.validation_errors[0]).toEqual({
        field: '',
        message: 'Invalid',
        value: testValue
      });
    });

    it('should handle extremely large error objects', () => {
      const largeData = fixtures.createPerformanceTestData(1000);
      const error = new Error('Large error');
      error.largeData = largeData;

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      expect(() => {
        errorHandler(error, req, res, next);
      }).not.toThrow();
    });

    it('should handle errors with invalid timestamps', () => {
      const error = new AppError('Test error');
      error.timestamp = 'invalid-timestamp';

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          timestamp: expect.any(String)
        })
      );
    });
  });

  describe('Integration Tests with Fixtures', () => {
    it('should handle firewall rule validation errors', () => {
      const invalidRule = fixtures.createTestFirewallRule(false, 0);
      const testUser = fixtures.createTestUser('operator');
      
      const error = new ValidationError('Invalid firewall rule', {
        rule: invalidRule,
        user_id: testUser.id,
        validation_errors: [
          { field: 'interface', message: 'Interface is required' },
          { field: 'action', message: 'Invalid action' }
        ]
      });

      const req = mockRequest({ user: testUser });
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'VALIDATION_ERROR',
          details: expect.objectContaining({
            user_id: testUser.id,
            validation_errors: expect.arrayContaining([
              expect.objectContaining({ field: 'interface' }),
              expect.objectContaining({ field: 'action' })
            ])
          })
        })
      );
    });

    it('should handle user authentication errors with test data', () => {
      const testUser = fixtures.createTestUser('viewer');
      const jwtToken = fixtures.createTestJWTToken({ 
        sub: testUser.id,
        exp: Math.floor(Date.now() / 1000) - 3600 // Expired
      });

      const error = new AuthenticationError('Token expired', {
        user_id: testUser.id,
        token_type: 'JWT',
        expiry: new Date(Date.now() - 3600000).toISOString()
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'AUTHENTICATION_ERROR',
          details: expect.objectContaining({
            user_id: testUser.id,
            token_type: 'JWT'
          })
        })
      );
    });

    it('should handle rate limiting errors with fixture config', () => {
      const rateLimitConfig = fixtures.createRateLimitConfig({
        max_requests_per_minute: 30,
        burst_size: 10
      });
      const testUser = fixtures.createTestUser('admin');

      const error = new RateLimitError('Rate limit exceeded', {
        user_id: testUser.id,
        current_requests: rateLimitConfig.max_requests_per_minute + 5,
        limit: rateLimitConfig.max_requests_per_minute,
        reset_time: Date.now() + 60000
      });

      const req = mockRequest({ user: testUser });
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'RATE_LIMIT_ERROR',
          details: expect.objectContaining({
            limit: 30,
            current_requests: 35
          })
        })
      );
    });

    it('should handle external API errors with network issues', () => {
      const networkError = fixtures.createNetworkError('timeout');
      const error = new ExternalApiError('OPNsense API timeout', {
        service: 'OPNsense',
        endpoint: '/api/firewall/filter/getRule',
        timeout: 30000,
        error_code: networkError.code
      });

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(502);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'EXTERNAL_API_ERROR',
          details: expect.objectContaining({
            service: 'OPNsense',
            error_code: 'ECONNABORTED'
          })
        })
      );
    });

    it('should handle bulk operation errors', () => {
      const multipleRules = fixtures.createMultipleFirewallRules(5, false);
      const testUser = fixtures.createTestUser('admin');

      const error = new ValidationError('Bulk operation failed', {
        operation: 'bulk_create_rules',
        user_id: testUser.id,
        total_rules: multipleRules.length,
        failed_rules: multipleRules.filter((_, i) => i % 2 === 0),
        validation_errors: multipleRules.map((rule, index) => ({
          rule_index: index,
          rule_uuid: rule.uuid,
          errors: ['Invalid interface', 'Missing action']
        }))
      });

      const req = mockRequest({ user: testUser });
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          details: expect.objectContaining({
            operation: 'bulk_create_rules',
            total_rules: 5,
            validation_errors: expect.arrayContaining([
              expect.objectContaining({
                rule_index: expect.any(Number),
                rule_uuid: expect.any(String)
              })
            ])
          })
        })
      );
    });

    it('should sanitize sensitive data in error details', () => {
      const testUser = fixtures.createTestUser('operator');
      const jwtToken = fixtures.createTestJWTToken();
      
      const error = new Error('Sensitive data exposed');
      error.details = {
        user: testUser,
        api_key: jwtToken,
        password: 'secret123',
        database_url: 'postgres://user:pass@host:5432/db'
      };

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      // In production, sensitive details should not be exposed
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.not.objectContaining({
          details: expect.objectContaining({
            api_key: jwtToken,
            password: 'secret123'
          })
        })
      );

      process.env.NODE_ENV = originalEnv;
    });

    it('should generate consistent error IDs', () => {
      const error1 = new ValidationError(`Error 1 ${fixtures.random.string(6)}`);
      const error2 = new ValidationError(`Error 2 ${fixtures.random.string(6)}`);

      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error1, req, res, next);
      const call1 = res.json.mock.calls[0][0];

      res.json.mockClear();
      errorHandler(error2, req, res, next);
      const call2 = res.json.mock.calls[0][0];

      expect(call1.error_id).toBeValidUUID();
      expect(call2.error_id).toBeValidUUID();
      expect(call1.error_id).not.toBe(call2.error_id);
    });

    it('should handle performance test errors', () => {
      const perfData = fixtures.createPerformanceTestData(100);
      const testUser = fixtures.createTestUser('admin');

      const error = new Error('Performance test timeout');
      error.details = {
        test_type: 'bulk_processing',
        data_size: perfData.length,
        processing_time: 30000,
        timeout_limit: 25000,
        user_id: testUser.id
      };

      const req = mockRequest({ user: testUser });
      const res = mockResponse();
      const next = mockNext();

      errorHandler(error, req, res, next);

      expect(logger.error).toHaveBeenCalledWith(
        'Internal server error',
        expect.objectContaining({
          user_id: testUser.id,
          url: req.originalUrl,
          method: req.method
        })
      );
    });
  });
});