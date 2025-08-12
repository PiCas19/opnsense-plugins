const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

// Error types and codes
const ERROR_TYPES = {
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR: 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR: 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR: 'NOT_FOUND_ERROR',
  CONFLICT_ERROR: 'CONFLICT_ERROR',
  RATE_LIMIT_ERROR: 'RATE_LIMIT_ERROR',
  EXTERNAL_API_ERROR: 'EXTERNAL_API_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
};

// HTTP Status codes mapping
const STATUS_CODES = {
  [ERROR_TYPES.VALIDATION_ERROR]: 400,
  [ERROR_TYPES.AUTHENTICATION_ERROR]: 401,
  [ERROR_TYPES.AUTHORIZATION_ERROR]: 403,
  [ERROR_TYPES.NOT_FOUND_ERROR]: 404,
  [ERROR_TYPES.CONFLICT_ERROR]: 409,
  [ERROR_TYPES.RATE_LIMIT_ERROR]: 429,
  [ERROR_TYPES.EXTERNAL_API_ERROR]: 502,
  [ERROR_TYPES.DATABASE_ERROR]: 503,
  [ERROR_TYPES.INTERNAL_SERVER_ERROR]: 500,
};

/**
 * Custom Error classes
 */
class AppError extends Error {
  constructor(message, type = ERROR_TYPES.INTERNAL_SERVER_ERROR, statusCode = null, details = null) {
    super(message);
    this.name = this.constructor.name;
    this.type = type;
    this.statusCode = statusCode || STATUS_CODES[type] || 500;
    this.details = details;
    this.isOperational = true;
    this.timestamp = new Date().toISOString();
    
    // Capture stack trace
    Error.captureStackTrace(this, this.constructor);
  }
}

class ValidationError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.VALIDATION_ERROR, 400, details);
  }
}

class AuthenticationError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.AUTHENTICATION_ERROR, 401, details);
  }
}

class AuthorizationError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.AUTHORIZATION_ERROR, 403, details);
  }
}

class NotFoundError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.NOT_FOUND_ERROR, 404, details);
  }
}

class ConflictError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.CONFLICT_ERROR, 409, details);
  }
}

class RateLimitError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.RATE_LIMIT_ERROR, 429, details);
  }
}

class ExternalApiError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.EXTERNAL_API_ERROR, 502, details);
  }
}

class DatabaseError extends AppError {
  constructor(message, details = null) {
    super(message, ERROR_TYPES.DATABASE_ERROR, 503, details);
  }
}

/**
 * Determine error type from error object
 */
const determineErrorType = (error) => {
  // Sequelize errors
  if (error.name === 'SequelizeValidationError') {
    return ERROR_TYPES.VALIDATION_ERROR;
  }
  if (error.name === 'SequelizeUniqueConstraintError') {
    return ERROR_TYPES.CONFLICT_ERROR;
  }
  if (error.name === 'SequelizeForeignKeyConstraintError') {
    return ERROR_TYPES.VALIDATION_ERROR;
  }
  if (error.name === 'SequelizeConnectionError') {
    return ERROR_TYPES.DATABASE_ERROR;
  }
  
  // JWT errors
  if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
    return ERROR_TYPES.AUTHENTICATION_ERROR;
  }
  
  // Joi validation errors
  if (error.name === 'ValidationError' && error.isJoi) {
    return ERROR_TYPES.VALIDATION_ERROR;
  }
  
  // Express validation errors
  if (error.type === 'entity.parse.failed') {
    return ERROR_TYPES.VALIDATION_ERROR;
  }
  
  // Axios errors (OPNsense API)
  if (error.isAxiosError) {
    return ERROR_TYPES.EXTERNAL_API_ERROR;
  }
  
  // Custom app errors
  if (error instanceof AppError) {
    return error.type;
  }
  
  return ERROR_TYPES.INTERNAL_SERVER_ERROR;
};

/**
 * Extract error details for response
 */
const extractErrorDetails = (error) => {
  const details = {};
  
  // Sequelize validation errors
  if (error.name === 'SequelizeValidationError') {
    details.validation_errors = error.errors.map(err => ({
      field: err.path,
      message: err.message,
      value: err.value,
    }));
  }
  
  // Joi validation errors
  if (error.isJoi) {
    details.validation_errors = error.details.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message,
      value: detail.context?.value,
    }));
  }
  
  // Express validator errors
  if (error.array && typeof error.array === 'function') {
    details.validation_errors = error.array().map(err => ({
      field: err.path || err.param,
      message: err.msg,
      value: err.value,
    }));
  }
  
  // Axios errors
  if (error.isAxiosError) {
    details.external_service = 'OPNsense API';
    details.status_code = error.response?.status;
    details.status_text = error.response?.statusText;
    details.url = error.config?.url;
    details.method = error.config?.method?.toUpperCase();
  }
  
  // Custom error details
  if (error.details) {
    Object.assign(details, error.details);
  }
  
  return Object.keys(details).length > 0 ? details : null;
};

/**
 * Check if error should be exposed to client
 */
const shouldExposeError = (error, env = process.env.NODE_ENV) => {
  // Always expose operational errors
  if (error.isOperational) return true;
  
  // In development, expose all errors
  if (env === 'development') return true;
  
  // In production, only expose known error types
  const safeErrors = [
    ERROR_TYPES.VALIDATION_ERROR,
    ERROR_TYPES.AUTHENTICATION_ERROR,
    ERROR_TYPES.AUTHORIZATION_ERROR,
    ERROR_TYPES.NOT_FOUND_ERROR,
    ERROR_TYPES.CONFLICT_ERROR,
    ERROR_TYPES.RATE_LIMIT_ERROR,
  ];
  
  return safeErrors.includes(determineErrorType(error));
};

/**
 * Sanitize error message for client
 */
const sanitizeErrorMessage = (error, shouldExpose) => {
  if (!shouldExpose) {
    return 'An internal server error occurred';
  }
  
  // Return original message for operational errors
  if (error.isOperational) {
    return error.message;
  }
  
  // Customize messages for specific error types
  const type = determineErrorType(error);
  
  switch (type) {
    case ERROR_TYPES.DATABASE_ERROR:
      return 'Database service temporarily unavailable';
    case ERROR_TYPES.EXTERNAL_API_ERROR:
      return 'External service temporarily unavailable';
    default:
      return error.message || 'An error occurred';
  }
};

/**
 * Main error handler middleware
 */
const errorHandler = (error, req, res, next) => {
  // Generate error ID for tracking
  const errorId = uuidv4();
  const timestamp = new Date().toISOString();
  
  // Determine error type and status code
  const errorType = determineErrorType(error);
  const statusCode = error.statusCode || STATUS_CODES[errorType] || 500;
  
  // Extract error details
  const errorDetails = extractErrorDetails(error);
  
  // Check if error should be exposed
  const shouldExpose = shouldExposeError(error);
  
  // Create error context for logging
  const errorContext = {
    error_id: errorId,
    timestamp,
    type: errorType,
    message: error.message,
    stack: error.stack,
    status_code: statusCode,
    url: req.originalUrl || req.url,
    method: req.method,
    user_id: req.user?.id || null,
    user_agent: req.get('User-Agent'),
    ip_address: req.ip,
    correlation_id: req.correlationId,
    details: errorDetails,
  };
  
  // Log error with appropriate level
  if (statusCode >= 500) {
    logger.error('Internal server error', errorContext);
  } else if (statusCode >= 400) {
    logger.warn('Client error', errorContext);
  } else {
    logger.info('Error handled', errorContext);
  }
  
  // Record error metrics
  try {
    const { metricsHelpers } = require('../config/monitoring');
    metricsHelpers.recordHttpRequest(
      req.method,
      req.route?.path || req.path,
      statusCode,
      Date.now() - (req.startTime || Date.now())
    );
  } catch (metricsError) {
    // Monitoring not available
  }
  
  // Create response object
  const responseBody = {
    success: false,
    error: sanitizeErrorMessage(error, shouldExpose),
    code: errorType,
    error_id: errorId,
    timestamp,
  };
  
  // Add details in development or for operational errors
  if (shouldExpose && errorDetails) {
    responseBody.details = errorDetails;
  }
  
  // Add stack trace in development
  if (process.env.NODE_ENV === 'development' && error.stack) {
    responseBody.stack = error.stack;
  }
  
  // Send error response
  res.status(statusCode).json(responseBody);
};

/**
 * Async error wrapper for route handlers
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * 404 Not Found handler
 */
const notFoundHandler = (req, res, next) => {
  const error = new NotFoundError(
    `Route ${req.method} ${req.originalUrl} not found`,
    {
      method: req.method,
      url: req.originalUrl,
      available_routes: req.app._router?.stack
        ?.filter(layer => layer.route)
        ?.map(layer => ({
          method: Object.keys(layer.route.methods)[0]?.toUpperCase(),
          path: layer.route.path,
        })) || [],
    }
  );
  
  next(error);
};

/**
 * Unhandled promise rejection handler
 */
const handleUnhandledRejection = () => {
  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Promise Rejection', {
      reason: reason?.message || reason,
      stack: reason?.stack,
      promise: promise.toString(),
    });
    
    // Optionally exit process in production
    if (process.env.NODE_ENV === 'production') {
      setTimeout(() => {
        process.exit(1);
      }, 1000);
    }
  });
};

/**
 * Uncaught exception handler
 */
const handleUncaughtException = () => {
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception', {
      message: error.message,
      stack: error.stack,
    });
    
    // Exit process immediately for uncaught exceptions
    process.exit(1);
  });
};

/**
 * Initialize error handling
 */
const initializeErrorHandling = () => {
  handleUnhandledRejection();
  handleUncaughtException();
  
  logger.info('Error handling initialized');
};

module.exports = {
  // Middleware
  errorHandler,
  asyncHandler,
  notFoundHandler,
  
  // Error classes
  AppError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  ExternalApiError,
  DatabaseError,
  
  // Utilities
  determineErrorType,
  extractErrorDetails,
  shouldExposeError,
  sanitizeErrorMessage,
  initializeErrorHandling,
  
  // Constants
  ERROR_TYPES,
  STATUS_CODES,
};