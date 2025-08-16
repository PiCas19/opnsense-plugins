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

describe('Error Handler Middleware', () => {
  beforeEach(() => {
    resetMocks();
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
        const error = new AppError('Test error');

        expect(error.message).toBe('Test error');
        expect(error.name).toBe('AppError');
        expect(error.type).toBe(ERROR_TYPES.INTERNAL_SERVER_ERROR);
        expect(error.statusCode).toBe(500);
        expect(error.isOperational).toBe(true);
        expect(error.timestamp).toBeDefined();
        expect(error.details).toBeNull();
      });

      it('should create error with custom parameters', () => {
        const details = { field: 'username' };
        const error = new AppError(
          'Custom error',
          ERROR_TYPES.VALIDATION_ERROR,
          400,
          details
        );

        expect(error.message).toBe('Custom error');
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
        const details = { field: 'email', value: 'invalid' };
        const error = new ValidationError('Invalid email', details);

        expect(error.message).toBe('Invalid email');
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
    });

    describe('AuthorizationError', () => {
      it('should create authorization error', () => {
        const error = new AuthorizationError('Access denied');

        expect(error.message).toBe('Access denied');
        expect(error.type).toBe(ERROR_TYPES.AUTHORIZATION_ERROR);
        expect(error.statusCode).toBe(403);
      });
    });

    describe('NotFoundError', () => {
      it('should create not found error', () => {
        const error = new NotFoundError('Resource not found');

        expect(error.message).toBe('Resource not found');
        expect(error.type).toBe(ERROR_TYPES.NOT_FOUND_ERROR);
        expect(error.statusCode).toBe(404);
      });
    });

    describe('ConflictError', () => {
      it('should create conflict error', () => {
        const error = new ConflictError('Resource already exists');

        expect(error.message).toBe('Resource already exists');
        expect(error.type).toBe(ERROR_TYPES.CONFLICT_ERROR);
        expect(error.statusCode).toBe(409);
      });
    });

    describe('RateLimitError', () => {
      it('should create rate limit error', () => {
        const error = new RateLimitError('Rate limit exceeded');

        expect(error.message).toBe('Rate limit exceeded');
        expect(error.type).toBe(ERROR_TYPES.RATE_LIMIT_ERROR);
        expect(error.statusCode).toBe(429);
      });
    });

    describe('ExternalApiError', () => {
      it('should create external API error', () => {
        const error = new ExternalApiError('API unavailable');

        expect(error.message).toBe('API unavailable');
        expect(error.type).toBe(ERROR_TYPES.EXTERNAL_API_ERROR);
        expect(error.statusCode).toBe(502);
      });
    });

    describe('DatabaseError', () => {
      it('should create database error', () => {
        const error = new DatabaseError('Connection failed');

        expect(error.message).toBe('Connection failed');
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
  });

  describe('extractErrorDetails', () => {
    it('should extract Sequelize validation error details', () => {
      const error = {
        name: 'SequelizeValidationError',
        errors: [
          { path: 'email', message: 'Invalid email', value: 'invalid' },
          { path: 'password', message: 'Too short', value: '123' }
        ]
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        validation_errors: [
          { field: 'email', message: 'Invalid email', value: 'invalid' },
          { field: 'password', message: 'Too short', value: '123' }
        ]
      });
    });

    it('should extract Joi validation error details', () => {
      const error = {
        isJoi: true,
        details: [
          {
            path: ['user', 'email'],
            message: 'Email is required',
            context: { value: undefined }
          }
        ]
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        validation_errors: [
          { field: 'user.email', message: 'Email is required', value: undefined }
        ]
      });
    });

    it('should extract express-validator error details', () => {
      const error = {
        array: jest.fn().mockReturnValue([
          { path: 'username', msg: 'Username is required', value: '' },
          { param: 'age', msg: 'Must be a number', value: 'abc' }
        ])
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        validation_errors: [
          { field: 'username', message: 'Username is required', value: '' },
          { field: 'age', message: 'Must be a number', value: 'abc' }
        ]
      });
    });

    it('should extract Axios error details', () => {
      const error = {
        isAxiosError: true,
        response: {
          status: 404,
          statusText: 'Not Found'
        },
        config: {
          url: '/api/test',
          method: 'get'
        }
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        external_service: 'OPNsense API',
        status_code: 404,
        status_text: 'Not Found',
        url: '/api/test',
        method: 'GET'
      });
    });

    it('should extract custom error details', () => {
      const error = {
        details: {
          custom_field: 'custom_value',
          reason: 'custom reason'
        }
      };

      const details = extractErrorDetails(error);

      expect(details).toEqual({
        custom_field: 'custom_value',
        reason: 'custom reason'
      });
    });

    it('should return null for errors without details', () => {
      const error = { message: 'Simple error' };
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
  });

  describe('shouldExposeError', () => {
    it('should expose operational errors', () => {
      const error = new ValidationError('Test error');
      expect(shouldExposeError(error)).toBe(true);
    });

    it('should expose errors in development', () => {
      const error = new Error('Any error');
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
        jest.spyOn(module.exports, 'determineErrorType').mockReturnValue(type);
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
        jest.spyOn(module.exports, 'determineErrorType').mockReturnValue(type);
        expect(shouldExposeError(error, 'production')).toBe(false);
      });
    });

    it('should use NODE_ENV by default', () => {
      const originalEnv = process.env.NODE_ENV;
      
      process.env.NODE_ENV = 'development';
      const error = new Error('Test');
      expect(shouldExposeError(error)).toBe(true);
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('sanitizeErrorMessage', () => {
    it('should return generic message when not exposing', () => {
      const error = new Error('Internal error');
      const result = sanitizeErrorMessage(error, false);
      expect(result).toBe('An internal server error occurred');
    });

    it('should return original message for operational errors', () => {
      const error = new ValidationError('Validation failed');
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('Validation failed');
    });

    it('should return sanitized message for database errors', () => {
      const error = { type: ERROR_TYPES.DATABASE_ERROR };
      jest.spyOn(module.exports, 'determineErrorType').mockReturnValue(ERROR_TYPES.DATABASE_ERROR);
      
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('Database service temporarily unavailable');
    });

    it('should return sanitized message for external API errors', () => {
      const error = { type: ERROR_TYPES.EXTERNAL_API_ERROR };
      jest.spyOn(module.exports, 'determineErrorType').mockReturnValue(ERROR_TYPES.EXTERNAL_API_ERROR);
      
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('External service temporarily unavailable');
    });

    it('should return original or default message for other types', () => {
      const error = { message: 'Custom error' };
      const result = sanitizeErrorMessage(error, true);
      expect(result).toBe('Custom error');
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
      req = mockRequest({
        method: 'POST',
        originalUrl: '/api/test',
        ip: '127.0.0.1',
        user: { id: 123 },
        correlationId: 'test-correlation-id'
      });
      req.get = jest.fn().mockReturnValue('Test Browser');

      res = mockResponse();
      next = mockNext();
    });

    it('should handle validation errors correctly', () => {
      const error = new ValidationError('Invalid input', {
        field: 'email',
        value: 'invalid'
      });

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: 'Invalid input',
        code: 'VALIDATION_ERROR',
        error_id: expect.any(String),
        timestamp: expect.any(String),
        details: { field: 'email', value: 'invalid' }
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
      const error = new Error('Database connection string exposed');

      errorHandler(error, req, res, next);

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

      const error = new Error('Development error');
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

      const error = new Error('Production error');
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
      const error = new Error('Server error');

      errorHandler(error, req, res, next);

      expect(logger.error).toHaveBeenCalledWith(
        'Internal server error',
        expect.objectContaining({
          error_id: expect.any(String),
          type: 'INTERNAL_SERVER_ERROR',
          status_code: 500,
          url: '/api/test',
          method: 'POST',
          user_id: 123,
          ip_address: '127.0.0.1',
          correlation_id: 'test-correlation-id'
        })
      );
    });

    it('should log client errors as warnings', () => {
      const error = new ValidationError('Client error');

      errorHandler(error, req, res, next);

      expect(logger.warn).toHaveBeenCalledWith(
        'Client error',
        expect.objectContaining({
          status_code: 400,
          type: 'VALIDATION_ERROR'
        })
      );
    });

    it('should handle missing request properties', () => {
      const req = {}; // Minimal request
      const error = new Error('Test error');

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
      const error = new AppError('Custom error', ERROR_TYPES.VALIDATION_ERROR, 422);

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(422);
    });

    it('should handle metrics recording safely', () => {
      logger.metricsRecorder = jest.fn().mockImplementation(() => {
        throw new Error('Metrics error');
      });

      const error = new Error('Test error');

      expect(() => {
        errorHandler(error, req, res, next);
      }).not.toThrow();

      expect(logger.metricsRecorder).toHaveBeenCalled();
    });

    it('should not include details when error should not be exposed', () => {
      const error = new Error('Internal error');
      error.details = { sensitive: 'data' };

      errorHandler(error, req, res, next);

      expect(res.json).toHaveBeenCalledWith(
        expect.not.objectContaining({
          details: expect.any(Object)
        })
      );
    });
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

    it('should catch and forward async errors', async () => {
      const error = new Error('Async error');
      const mockAsyncFn = jest.fn().mockRejectedValue(error);
      const req = mockRequest();
      const res = mockResponse();
      const next = mockNext();

      const handler = asyncHandler(mockAsyncFn);
      await handler(req, res, next);

      expect(next).toHaveBeenCalledWith(error);
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

    it('should handle sync errors', () => {
      const error = new Error('Sync error');
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
        originalUrl: '/api/nonexistent',
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
                  path: '/api/posts',
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
          message: 'Route GET /api/nonexistent not found',
          type: 'NOT_FOUND_ERROR',
          details: {
            method: 'GET',
            url: '/api/nonexistent',
            available_routes: [
              { method: 'GET', path: '/api/users' },
              { method: 'POST', path: '/api/posts' }
            ]
          }
        })
      );
    });

    it('should handle missing router information', () => {
      const req = mockRequest({
        method: 'POST',
        originalUrl: '/api/missing'
      });
      const res = mockResponse();
      const next = mockNext();

      notFoundHandler(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Route POST /api/missing not found',
          details: {
            method: 'POST',
            url: '/api/missing',
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

      // Simulate unhandled rejection
      const promise = Promise.reject(new Error('Unhandled rejection'));
      
      setTimeout(() => {
        expect(logger.error).toHaveBeenCalledWith(
          'Unhandled Promise Rejection',
          expect.objectContaining({
            reason: 'Unhandled rejection'
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
      const error = new Error('Uncaught exception');
      
      handler(error);

      expect(logger.error).toHaveBeenCalledWith(
        'Uncaught Exception',
        {
          message: 'Uncaught exception',
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
      const promise = Promise.reject(new Error('Production error'));
      
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
      const error = new Error('Circular error');
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
      const error = {
        isJoi: true,
        details: [
          {
            path: null,
            message: 'Invalid',
            context: null
          }
        ]
      };

      const details = extractErrorDetails(error);
      expect(details.validation_errors[0]).toEqual({
        field: '',
        message: 'Invalid',
        value: undefined
      });
    });
  });
});